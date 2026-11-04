package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/oauth"
	"github.com/adamdlear/centrauth/internal/repository"
)

type fakeApps struct {
	apps       []db.Application
	clients    []db.OAuthClient
	nextAppID  int64
	nextClient int64
	failCreate error
}

func (f *fakeApps) Create(_ context.Context, app *db.Application) (db.Application, error) {
	f.nextAppID++
	app.ID = f.nextAppID
	f.apps = append(f.apps, *app)
	return *app, nil
}

func (f *fakeApps) CreateWithClient(_ context.Context, app *db.Application, client *db.OAuthClient) error {
	if f.failCreate != nil {
		return f.failCreate
	}
	f.nextAppID++
	app.ID = f.nextAppID
	client.ApplicationID = app.ID
	f.nextClient++
	client.ID = f.nextClient
	f.apps = append(f.apps, *app)
	f.clients = append(f.clients, *client)
	return nil
}

func (f *fakeApps) GetByID(_ context.Context, id int64) (db.Application, error) {
	for _, app := range f.apps {
		if app.ID == id {
			return app, nil
		}
	}
	return db.Application{}, repository.ErrNotFound
}

func (f *fakeApps) List(_ context.Context) ([]db.Application, error) { return f.apps, nil }

func (f *fakeApps) Update(_ context.Context, app *db.Application) (db.Application, error) {
	for i := range f.apps {
		if f.apps[i].ID == app.ID {
			f.apps[i] = *app
			return *app, nil
		}
	}
	return db.Application{}, repository.ErrNotFound
}

func (f *fakeApps) GetWithClients(_ context.Context, id int64) (db.Application, []db.OAuthClient, error) {
	app, err := f.GetByID(context.Background(), id)
	return app, f.clients, err
}

type fakeClients struct {
	clients []db.OAuthClient
	nextID  int64
}

func (f *fakeClients) GetByID(_ context.Context, id int64) (db.OAuthClient, error) {
	for _, c := range f.clients {
		if c.ID == id {
			return c, nil
		}
	}
	return db.OAuthClient{}, repository.ErrNotFound
}

func (f *fakeClients) GetByClientID(_ context.Context, clientID string) (db.OAuthClient, error) {
	for _, c := range f.clients {
		if c.ClientID == clientID {
			return c, nil
		}
	}
	return db.OAuthClient{}, repository.ErrNotFound
}

func (f *fakeClients) Create(_ context.Context, client *db.OAuthClient) (db.OAuthClient, error) {
	f.nextID++
	client.ID = f.nextID
	f.clients = append(f.clients, *client)
	return *client, nil
}

func (f *fakeClients) Update(_ context.Context, client *db.OAuthClient) (db.OAuthClient, error) {
	for i := range f.clients {
		if f.clients[i].ID == client.ID {
			f.clients[i] = *client
			return *client, nil
		}
	}
	return db.OAuthClient{}, repository.ErrNotFound
}

func (f *fakeClients) List(_ context.Context) ([]db.OAuthClient, error) { return f.clients, nil }

func (f *fakeClients) ListByEnvironment(_ context.Context, env string) ([]db.OAuthClient, error) {
	var out []db.OAuthClient
	for _, c := range f.clients {
		if c.Environment == env {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeClients) ListByApplicationID(_ context.Context, appID int64) ([]db.OAuthClient, error) {
	var out []db.OAuthClient
	for _, c := range f.clients {
		if c.ApplicationID == appID {
			out = append(out, c)
		}
	}
	return out, nil
}

func validInput() RegisterAppInput {
	return RegisterAppInput{
		Name:          "Todo",
		Description:   "A todo app",
		FirstParty:    true,
		AllowedScopes: []string{"openid", "profile"},
		Client: ClientInput{
			ClientType:     "confidential",
			RedirectURIs:   []string{"https://example.com/callback"},
			Environment:    "production",
			AllowedOrigins: []string{"https://example.com"},
		},
	}
}

func TestRegisterApp_ConfidentialClient(t *testing.T) {
	apps := &fakeApps{}
	clients := &fakeClients{}
	svc := NewAppService(apps, clients)

	out, err := svc.RegisterApp(context.Background(), validInput())
	if err != nil {
		t.Fatalf("RegisterApp() error = %v", err)
	}

	if out.App.ID == 0 || out.Client.ApplicationID != out.App.ID {
		t.Errorf("app/client IDs = %d/%d, want client linked to created app", out.App.ID, out.Client.ApplicationID)
	}
	if out.App.Name != "Todo" || !out.App.FirstParty {
		t.Errorf("app = %+v, want metadata preserved", out.App)
	}
	if out.Client.ClientID == "" {
		t.Error("ClientID is empty")
	}
	if out.Client.ClientType != "confidential" || out.Client.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("client type/auth = %q/%q", out.Client.ClientType, out.Client.TokenEndpointAuthMethod)
	}
	if out.ClientSecret == "" {
		t.Fatal("ClientSecret is empty for a confidential client")
	}

	sum := sha256.Sum256([]byte(out.ClientSecret))
	if string(sum[:]) != string(out.Client.ClientSecretHash) {
		t.Error("stored hash does not match sha256(plaintext secret)")
	}
	if !oauth.ValidateClientSecret(out.Client, out.ClientSecret) {
		t.Error("ValidateClientSecret() rejected the correct secret")
	}
	if oauth.ValidateClientSecret(out.Client, "wrong") {
		t.Error("ValidateClientSecret() accepted a wrong secret")
	}
	if strings.Contains(string(out.Client.ClientSecretHash), out.ClientSecret) {
		t.Error("stored hash contains the plaintext secret")
	}
}

func TestRegisterApp_PublicClientHasNoSecret(t *testing.T) {
	apps := &fakeApps{}
	clients := &fakeClients{}
	svc := NewAppService(apps, clients)

	input := validInput()
	input.Client.ClientType = "public"

	out, err := svc.RegisterApp(context.Background(), input)
	if err != nil {
		t.Fatalf("RegisterApp() error = %v", err)
	}
	if out.ClientSecret != "" {
		t.Errorf("ClientSecret = %q, want empty for a public client", out.ClientSecret)
	}
	if len(out.Client.ClientSecretHash) != 0 {
		t.Errorf("ClientSecretHash = %v, want empty for a public client", out.Client.ClientSecretHash)
	}
	if out.Client.TokenEndpointAuthMethod != "none" {
		t.Errorf("TokenEndpointAuthMethod = %q, want none", out.Client.TokenEndpointAuthMethod)
	}
}

func TestRegisterApp_GeneratesUniqueClientIDs(t *testing.T) {
	apps := &fakeApps{}
	clients := &fakeClients{}
	svc := NewAppService(apps, clients)

	seen := map[string]bool{}
	for i := 0; i < 25; i++ {
		out, err := svc.RegisterApp(context.Background(), validInput())
		if err != nil {
			t.Fatalf("RegisterApp() error = %v", err)
		}
		if seen[out.Client.ClientID] {
			t.Fatalf("duplicate client ID %q", out.Client.ClientID)
		}
		seen[out.Client.ClientID] = true
		if len(out.Client.ClientID) != 32 {
			t.Errorf("ClientID %q length = %d, want 32", out.Client.ClientID, len(out.Client.ClientID))
		}
	}
}

func TestRegisterApp_Validation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RegisterAppInput)
		field  string
	}{
		{"missing name", func(in *RegisterAppInput) { in.Name = "   " }, "name"},
		{"unsupported scope", func(in *RegisterAppInput) { in.AllowedScopes = []string{"admin"} }, "allowed_scopes"},
		{"bad client type", func(in *RegisterAppInput) { in.Client.ClientType = "robot" }, "client_client_type"},
		{"no redirect uri", func(in *RegisterAppInput) { in.Client.RedirectURIs = nil }, "client_redirect_uris"},
		{"relative redirect uri", func(in *RegisterAppInput) { in.Client.RedirectURIs = []string{"/callback"} }, "client_redirect_uris"},
		{"insecure redirect uri", func(in *RegisterAppInput) { in.Client.RedirectURIs = []string{"http://example.com/callback"} }, "client_redirect_uris"},
		{"wildcard redirect uri", func(in *RegisterAppInput) { in.Client.RedirectURIs = []string{"https://*.example.com/callback"} }, "client_redirect_uris"},
		{"unknown environment", func(in *RegisterAppInput) { in.Client.Environment = "moon" }, "client_environment"},
		{"bad post logout uri", func(in *RegisterAppInput) { in.Client.PostLogoutRedirectURIs = []string{"nope"} }, "client_post_logout_redirect_uris"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apps := &fakeApps{}
			clients := &fakeClients{}
			svc := NewAppService(apps, clients)

			input := validInput()
			tt.mutate(&input)

			_, err := svc.RegisterApp(context.Background(), input)
			if err == nil {
				t.Fatal("RegisterApp() error = nil, want validation error")
			}
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("RegisterApp() error = %T, want *ValidationError", err)
			}
			if verr.Fields[tt.field] == "" {
				t.Errorf("validation error fields = %v, want %q", verr.Fields, tt.field)
			}
			if len(apps.apps) != 0 || len(clients.clients) != 0 {
				t.Errorf("invalid input persisted %d apps and %d clients", len(apps.apps), len(clients.clients))
			}
		})
	}
}

func TestRegisterApp_PropagatesRepositoryFailure(t *testing.T) {
	apps := &fakeApps{failCreate: errors.New("boom")}
	clients := &fakeClients{}
	svc := NewAppService(apps, clients)

	_, err := svc.RegisterApp(context.Background(), validInput())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("RegisterApp() error = %v, want repository failure", err)
	}
}

func TestCreateClient(t *testing.T) {
	apps := &fakeApps{}
	clients := &fakeClients{}
	svc := NewAppService(apps, clients)

	out, err := svc.CreateClient(context.Background(), 42, ClientInput{
		ClientType:   "public",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Environment:  "local",
	})
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	if out.Client.ApplicationID != 42 {
		t.Errorf("ApplicationID = %d, want 42", out.Client.ApplicationID)
	}
	if out.Client.ClientID == "" {
		t.Error("ClientID is empty")
	}
}

func TestUpdateApp(t *testing.T) {
	apps := &fakeApps{}
	clients := &fakeClients{}
	svc := NewAppService(apps, clients)

	created, err := svc.RegisterApp(context.Background(), validInput())
	if err != nil {
		t.Fatalf("RegisterApp() error = %v", err)
	}

	updated, err := svc.UpdateApp(context.Background(), created.App, AppMetadataInput{
		Name:          "Renamed",
		Description:   "",
		FirstParty:    false,
		AllowedScopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("UpdateApp() error = %v", err)
	}
	if updated.Name != "Renamed" || updated.FirstParty || len(updated.AllowedScopes) != 1 {
		t.Errorf("updated app = %+v, want renamed/third-party/one scope", updated)
	}

	_, err = svc.UpdateApp(context.Background(), updated, AppMetadataInput{Name: "  "})
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("UpdateApp() with blank name error = %v, want *ValidationError", err)
	}
}

func TestRegisterApp_ProducesUsableClientAndScopes(t *testing.T) {
	apps := &fakeApps{}
	clients := &fakeClients{}
	svc := NewAppService(apps, clients)

	out, err := svc.RegisterApp(context.Background(), validInput())
	if err != nil {
		t.Fatalf("RegisterApp() error = %v", err)
	}

	if !oauth.IsRedirectURIAllowed(out.Client, "https://example.com/callback") {
		t.Error("registered redirect URI is not accepted by IsRedirectURIAllowed")
	}
	if oauth.IsRedirectURIAllowed(out.Client, "https://evil.example.com/callback") {
		t.Error("unregistered redirect URI was accepted")
	}
	if !oauth.ValidateRequestedScopes(out.App, "openid profile") {
		t.Error("registered scopes are not accepted by ValidateRequestedScopes")
	}
	if oauth.ValidateRequestedScopes(out.App, "openid admin") {
		t.Error("unregistered scope was accepted")
	}
}
