package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/sha256"
	"github.com/adamdlear/centrauth/internal/admin"
	"github.com/adamdlear/centrauth/internal/admin/templates"
	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/oauth"
	"github.com/adamdlear/centrauth/internal/oidc"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/secrets"
	"github.com/adamdlear/centrauth/internal/service"
	"github.com/adamdlear/centrauth/internal/session"
	"github.com/adamdlear/centrauth/internal/signing"
	"github.com/adamdlear/centrauth/internal/upstream"
	"github.com/go-jose/go-jose/v4"
	pq "github.com/lib/pq"
)

type fakeUserRepo struct {
	byID    map[int64]db.User
	byEmail map[string]db.User
	nextID  int64
}

func (f *fakeUserRepo) GetByEmail(_ context.Context, email string) (db.User, error) {
	if u, ok := f.byEmail[email]; ok {
		return u, nil
	}
	return db.User{}, repository.ErrNotFound
}

func (f *fakeUserRepo) GetByID(_ context.Context, id int64) (db.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return db.User{}, repository.ErrNotFound
}

func (f *fakeUserRepo) Create(_ context.Context, u *db.User) (db.User, error) {
	return *u, nil
}

type fakeClientRepo struct {
	clients []db.OAuthClient
}

func (f *fakeClientRepo) GetByID(_ context.Context, id int64) (db.OAuthClient, error) {
	for _, c := range f.clients {
		if c.ID == id {
			return c, nil
		}
	}
	return db.OAuthClient{}, repository.ErrNotFound
}

func (f *fakeClientRepo) GetByClientID(_ context.Context, clientID string) (db.OAuthClient, error) {
	for _, c := range f.clients {
		if c.ClientID == clientID {
			return c, nil
		}
	}
	return db.OAuthClient{}, repository.ErrNotFound
}

func (f *fakeClientRepo) Create(_ context.Context, c *db.OAuthClient) (db.OAuthClient, error) {
	if c.ID == 0 {
		c.ID = int64(len(f.clients) + 1)
	}
	f.clients = append(f.clients, *c)
	return *c, nil
}

func (f *fakeClientRepo) Update(_ context.Context, c *db.OAuthClient) (db.OAuthClient, error) {
	for i := range f.clients {
		if f.clients[i].ID == c.ID {
			f.clients[i] = *c
			return *c, nil
		}
	}
	return db.OAuthClient{}, repository.ErrNotFound
}

func (f *fakeClientRepo) List(_ context.Context) ([]db.OAuthClient, error) {
	return f.clients, nil
}

func (f *fakeClientRepo) ListByEnvironment(_ context.Context, environment string) ([]db.OAuthClient, error) {
	var clients []db.OAuthClient
	for _, c := range f.clients {
		if c.Environment == environment {
			clients = append(clients, c)
		}
	}
	return clients, nil
}

func (f *fakeClientRepo) ListByApplicationID(_ context.Context, applicationID int64) ([]db.OAuthClient, error) {
	var clients []db.OAuthClient
	for _, c := range f.clients {
		if c.ApplicationID == applicationID {
			clients = append(clients, c)
		}
	}
	return clients, nil
}

type fakeApplicationRepo struct {
	apps       []db.Application
	nextID     int64
	clientRepo *fakeClientRepo
}

func (f *fakeApplicationRepo) Create(_ context.Context, a *db.Application) (db.Application, error) {
	f.nextID++
	a.ID = f.nextID
	f.apps = append(f.apps, *a)
	return *a, nil
}

func (f *fakeApplicationRepo) CreateWithClient(_ context.Context, a *db.Application, c *db.OAuthClient) error {
	f.nextID++
	a.ID = f.nextID
	c.ApplicationID = a.ID
	if c.ID == 0 {
		c.ID = int64(len(f.clientRepo.clients) + 1)
	}
	f.apps = append(f.apps, *a)
	f.clientRepo.clients = append(f.clientRepo.clients, *c)
	return nil
}

func (f *fakeApplicationRepo) GetByID(_ context.Context, id int64) (db.Application, error) {
	for _, a := range f.apps {
		if a.ID == id {
			return a, nil
		}
	}
	return db.Application{}, repository.ErrNotFound
}

func (f *fakeApplicationRepo) List(_ context.Context) ([]db.Application, error) {
	return f.apps, nil
}

func (f *fakeApplicationRepo) Update(_ context.Context, a *db.Application) (db.Application, error) {
	for i := range f.apps {
		if f.apps[i].ID == a.ID {
			f.apps[i] = *a
			return *a, nil
		}
	}
	return db.Application{}, repository.ErrNotFound
}

func (f *fakeApplicationRepo) GetWithClients(_ context.Context, id int64) (db.Application, []db.OAuthClient, error) {
	for _, a := range f.apps {
		if a.ID == id {
			clients, err := f.clientRepo.ListByApplicationID(context.Background(), id)
			return a, clients, err
		}
	}
	return db.Application{}, nil, repository.ErrNotFound
}

type fakeSessionRepo struct {
	sessions []db.Session
	nextID   int64
}

func (f *fakeSessionRepo) Create(_ context.Context, s *db.Session) (db.Session, error) {
	f.nextID++
	s.ID = f.nextID
	f.sessions = append(f.sessions, *s)
	return *s, nil
}

func (f *fakeSessionRepo) GetByTokenHash(_ context.Context, tokenHash []byte) (db.Session, error) {
	for _, s := range f.sessions {
		if bytes.Equal(s.TokenHash, tokenHash) {
			return s, nil
		}
	}
	return db.Session{}, repository.ErrNotFound
}

func (f *fakeSessionRepo) Revoke(_ context.Context, id int64) error {
	for i := range f.sessions {
		if f.sessions[i].ID == id {
			now := time.Now()
			f.sessions[i].RevokedAt = &now
			return nil
		}
	}
	return repository.ErrNotFound
}

func (f *fakeSessionRepo) RevokeAllForUser(_ context.Context, userID int64) error {
	now := time.Now()
	for i := range f.sessions {
		if f.sessions[i].UserID == userID && f.sessions[i].RevokedAt == nil {
			f.sessions[i].RevokedAt = &now
		}
	}
	return nil
}

func (f *fakeSessionRepo) DeleteInactive(_ context.Context) (int, error) {
	kept := make([]db.Session, 0, len(f.sessions))
	deleted := 0
	for _, s := range f.sessions {
		if s.ExpiresAt.Before(time.Now()) || s.RevokedAt != nil {
			deleted++
			continue
		}
		kept = append(kept, s)
	}
	f.sessions = kept
	return deleted, nil
}

type fakeOperatorRepo struct {
	operators []db.Operator
	nextID    int64
}

func (f *fakeOperatorRepo) GetByEmail(_ context.Context, email string) (db.Operator, error) {
	for _, o := range f.operators {
		if strings.EqualFold(o.Email, email) {
			return o, nil
		}
	}
	return db.Operator{}, repository.ErrNotFound
}

func (f *fakeOperatorRepo) GetByID(_ context.Context, id int64) (db.Operator, error) {
	for _, o := range f.operators {
		if o.ID == id {
			return o, nil
		}
	}
	return db.Operator{}, repository.ErrNotFound
}

func (f *fakeOperatorRepo) Count(_ context.Context) (int64, error) {
	return int64(len(f.operators)), nil
}

func (f *fakeOperatorRepo) CreateFirstOperator(_ context.Context, operator *db.Operator) (db.Operator, error) {
	if len(f.operators) > 0 {
		return db.Operator{}, repository.ErrSeatTaken
	}
	f.nextID++
	operator.ID = f.nextID
	f.operators = append(f.operators, *operator)
	return *operator, nil
}

type fakeOperatorSessionRepo struct {
	sessions []db.OperatorSession
	nextID   int64
}

func (f *fakeOperatorSessionRepo) Create(_ context.Context, s *db.OperatorSession) (db.OperatorSession, error) {
	f.nextID++
	s.ID = f.nextID
	f.sessions = append(f.sessions, *s)
	return *s, nil
}

func (f *fakeOperatorSessionRepo) GetByTokenHash(_ context.Context, tokenHash []byte) (db.OperatorSession, error) {
	for _, s := range f.sessions {
		if bytes.Equal(s.TokenHash, tokenHash) {
			return s, nil
		}
	}
	return db.OperatorSession{}, repository.ErrNotFound
}

func (f *fakeOperatorSessionRepo) Revoke(_ context.Context, id int64) error {
	for i := range f.sessions {
		if f.sessions[i].ID == id {
			now := time.Now()
			f.sessions[i].RevokedAt = &now
			return nil
		}
	}
	return repository.ErrNotFound
}

func (f *fakeOperatorSessionRepo) RevokeAllForOperator(_ context.Context, operatorID int64) error {
	now := time.Now()
	for i := range f.sessions {
		if f.sessions[i].OperatorID == operatorID && f.sessions[i].RevokedAt == nil {
			f.sessions[i].RevokedAt = &now
		}
	}
	return nil
}

func (f *fakeOperatorSessionRepo) DeleteInactive(_ context.Context) (int, error) {
	kept := make([]db.OperatorSession, 0, len(f.sessions))
	deleted := 0
	for _, s := range f.sessions {
		if s.ExpiresAt.Before(time.Now()) || s.RevokedAt != nil {
			deleted++
			continue
		}
		kept = append(kept, s)
	}
	f.sessions = kept
	return deleted, nil
}

type fakeIdentityProviderRepo struct {
	providers []db.IdentityProvider
	nextID    int64
}

func (f *fakeIdentityProviderRepo) ListByApplicationID(_ context.Context, applicationID int64) ([]db.IdentityProvider, error) {
	var out []db.IdentityProvider
	for _, p := range f.providers {
		if p.ApplicationID == applicationID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeIdentityProviderRepo) GetByApplicationAndProvider(_ context.Context, applicationID int64, provider string) (db.IdentityProvider, error) {
	for _, p := range f.providers {
		if p.ApplicationID == applicationID && p.Provider == provider {
			return p, nil
		}
	}
	return db.IdentityProvider{}, repository.ErrNotFound
}

func (f *fakeIdentityProviderRepo) Upsert(_ context.Context, provider *db.IdentityProvider) (db.IdentityProvider, error) {
	for i := range f.providers {
		if f.providers[i].ApplicationID == provider.ApplicationID && f.providers[i].Provider == provider.Provider {
			provider.ID = f.providers[i].ID
			f.providers[i] = *provider
			return *provider, nil
		}
	}
	f.nextID++
	provider.ID = f.nextID
	f.providers = append(f.providers, *provider)
	return *provider, nil
}

func (f *fakeIdentityProviderRepo) SetEnabled(_ context.Context, applicationID int64, provider string, enabled bool) error {
	for i := range f.providers {
		if f.providers[i].ApplicationID == applicationID && f.providers[i].Provider == provider {
			f.providers[i].Enabled = enabled
			return nil
		}
	}
	return repository.ErrNotFound
}

func (f *fakeIdentityProviderRepo) Delete(_ context.Context, applicationID int64, provider string) error {
	for i := range f.providers {
		if f.providers[i].ApplicationID == applicationID && f.providers[i].Provider == provider {
			f.providers = append(f.providers[:i], f.providers[i+1:]...)
			return nil
		}
	}
	return repository.ErrNotFound
}

type fakeUserIdentityRepo struct {
	identities []db.UserIdentity
	nextID     int64
}

func (f *fakeUserIdentityRepo) GetByProviderSubject(_ context.Context, provider, subject string) (db.UserIdentity, error) {
	for _, identity := range f.identities {
		if identity.Provider == provider && identity.ProviderSubject == subject {
			return identity, nil
		}
	}
	return db.UserIdentity{}, repository.ErrNotFound
}

func (f *fakeUserIdentityRepo) ListByUserID(_ context.Context, userID int64) ([]db.UserIdentity, error) {
	var out []db.UserIdentity
	for _, identity := range f.identities {
		if identity.UserID == userID {
			out = append(out, identity)
		}
	}
	return out, nil
}

func (f *fakeUserIdentityRepo) Create(_ context.Context, identity *db.UserIdentity) (db.UserIdentity, error) {
	f.nextID++
	identity.ID = f.nextID
	f.identities = append(f.identities, *identity)
	return *identity, nil
}

func (f *fakeUserIdentityRepo) CreateWithUser(_ context.Context, user *db.User, identity *db.UserIdentity) error {
	if user.ID == 0 {
		user.ID = int64(len(f.identities) + 1)
	}
	identity.UserID = user.ID
	_, err := f.Create(context.Background(), identity)
	return err
}

var (
	testKeyOnce sync.Once
	testKey     *signing.KeyManager
)

func testKeyManager() *signing.KeyManager {
	testKeyOnce.Do(func() {
		dir, err := os.MkdirTemp("", "centrauth-test-keys")
		if err != nil {
			panic(err)
		}
		testKey, err = signing.NewKeyManager(filepath.Join(dir, "signing-key.pem"))
		if err != nil {
			panic(err)
		}
	})
	return testKey
}

type fakeCodeRepo struct {
	codes  []db.OAuthAuthorizationCode
	nextID int64
}

func (f *fakeCodeRepo) Create(_ context.Context, code *db.OAuthAuthorizationCode) (db.OAuthAuthorizationCode, error) {
	f.nextID++
	code.ID = f.nextID
	f.codes = append(f.codes, *code)
	return *code, nil
}

func (f *fakeCodeRepo) GetByCodeHash(_ context.Context, hash []byte) (db.OAuthAuthorizationCode, error) {
	for _, c := range f.codes {
		if bytes.Equal(c.CodeHash, hash) {
			return c, nil
		}
	}
	return db.OAuthAuthorizationCode{}, repository.ErrNotFound
}

func (f *fakeCodeRepo) Consume(_ context.Context, id int64) error {
	for i := range f.codes {
		if f.codes[i].ID == id {
			if f.codes[i].ConsumedAt != nil || time.Now().After(f.codes[i].ExpiresAt) {
				return repository.ErrNotFound
			}
			now := time.Now()
			f.codes[i].ConsumedAt = &now
			return nil
		}
	}
	return repository.ErrNotFound
}

func newTestApp() (*App, *fakeUserRepo, *fakeSessionRepo, *fakeApplicationRepo, *fakeClientRepo, *fakeOperatorRepo, *fakeOperatorSessionRepo) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := &fakeUserRepo{byID: map[int64]db.User{}, byEmail: map[string]db.User{}}
	sessions := &fakeSessionRepo{}
	clients := &fakeClientRepo{}
	applications := &fakeApplicationRepo{clientRepo: clients}
	operators := &fakeOperatorRepo{}
	operatorSessions := &fakeOperatorSessionRepo{}
	providerRepo := &fakeIdentityProviderRepo{}
	identityRepo := &fakeUserIdentityRepo{}
	secretBox, _ := secrets.NewBox(make([]byte, 32))
	providerService := service.NewProviderService(providerRepo, users, identityRepo, secretBox)

	tpl := templates.New()
	operatorLogin := service.NewOperatorLoginService(logger, operators)
	operatorManager := session.NewOperatorManager(operatorSessions, session.Config{CookieName: "centrauth_operator", TTL: time.Hour})

	app := &App{
		logger:           logger,
		templates:        tpl,
		operatorLogin:    operatorLogin,
		sessions:         session.NewManager(sessions, session.Config{CookieName: "centrauth_session", TTL: time.Hour}),
		operatorSessions: operatorManager,
		users:            users,
		operators:        operators,
		applications:     applications,
		clients:          clients,
		admin:            admin.NewHandler(logger, tpl, applications, clients, service.NewAppService(applications, clients), providerService, operatorLogin, operatorManager),
		keyManager:       testKeyManager(),
		discovery:        oidc.NewDiscoveryConfig("http://localhost:8080"),
		idTokens:         oidc.NewIDTokenIssuer(testKeyManager(), "http://localhost:8080", 10*time.Minute),
		codes:            &fakeCodeRepo{},
		secrets:          secretBox,
		providers:        providerService,
		providerRepo:     providerRepo,
		providerFactory:  upstream.ConfigFor,
	}

	return app, users, sessions, applications, clients, operators, operatorSessions
}

func TestHealthRoute(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestRoutesRejectCrossSitePost(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRoutesAllowSameOriginPost(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRootRedirectsToAdmin(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin" {
		t.Errorf("Location = %q, want %q", loc, "/admin")
	}
}

func TestAdminRedirectsAnonymousToOperatorLogin(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/login" {
		t.Errorf("Location = %q, want %q", loc, "/admin/login")
	}
}

func TestAdminRendersForAuthenticatedOperator(t *testing.T) {
	app, _, _, applications, clients, operators, _ := newTestApp()

	operator := db.Operator{ID: 7, Email: "dash@example.com", PasswordHash: "hash"}
	operators.operators = append(operators.operators, operator)

	applications.apps = []db.Application{{ID: 1, Name: "Todo App"}}
	clients.clients = []db.OAuthClient{
		{ID: 1, ApplicationID: 1, ClientID: "todo-web", ClientType: "confidential"},
		{ID: 2, ApplicationID: 1, ClientID: "todo-mobile", ClientType: "public"},
	}

	token, err := app.operatorSessions.Create(context.Background(), operator.ID)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "centrauth_operator", Value: token})
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	for _, want := range []string{
		"dash@example.com",
		`action="/admin/auth/logout"`,
		"Todo App",
		`class="count-n">2<`,
		`href="/admin/apps/new"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response body missing %q", want)
		}
	}
}

func TestUserSessionCannotReachAdmin(t *testing.T) {
	app, users, _, _, _, _, _ := newTestApp()

	user := db.User{ID: 7, Subject: "user-admin-subject", Email: "useradmin@example.com"}
	users.byID[7] = user

	token, err := app.sessions.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "centrauth_session", Value: token})
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/login" {
		t.Errorf("Location = %q, want %q", loc, "/admin/login")
	}
}

func operatorSessionCookie(t *testing.T, app *App, operators *fakeOperatorRepo, email string) *http.Cookie {
	t.Helper()
	operator := db.Operator{ID: int64(len(operators.operators) + 1), Email: email, PasswordHash: "hash"}
	operators.operators = append(operators.operators, operator)

	token, err := app.operatorSessions.Create(context.Background(), operator.ID)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	return &http.Cookie{Name: "centrauth_operator", Value: token}
}

func TestRegisterAppCreatesAppAndClient(t *testing.T) {
	app, _, _, applications, clients, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "register@example.com")

	form := url.Values{
		"name":           {"Todo App"},
		"description":    {"A todo app"},
		"first_party":    {"on"},
		"allowed_scopes": {"openid profile"},
		"client_type":    {"confidential"},
		"redirect_uris":  {"https://example.com/callback\nhttps://app.example.com/auth"},
		"environment":    {"production"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/apps", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}

	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "shown once") {
		t.Error("response body missing one-time secret warning")
	}

	if len(applications.apps) != 1 {
		t.Fatalf("stored %d apps, want 1", len(applications.apps))
	}
	createdApp := applications.apps[0]
	if createdApp.Name != "Todo App" || createdApp.Description != "A todo app" || !createdApp.FirstParty {
		t.Errorf("app metadata = %+v, want name/description/first-party set", createdApp)
	}
	if len(createdApp.AllowedScopes) != 2 || createdApp.AllowedScopes[0] != "openid" || createdApp.AllowedScopes[1] != "profile" {
		t.Errorf("AllowedScopes = %v, want [openid profile]", createdApp.AllowedScopes)
	}

	if len(clients.clients) != 1 {
		t.Fatalf("stored %d clients, want 1", len(clients.clients))
	}
	createdClient := clients.clients[0]
	if createdClient.ApplicationID != createdApp.ID {
		t.Errorf("client ApplicationID = %d, want %d", createdClient.ApplicationID, createdApp.ID)
	}
	if createdClient.ClientID == "" || len(createdClient.ClientID) != 32 {
		t.Errorf("ClientID = %q, want 32 hex characters", createdClient.ClientID)
	}
	if len(createdClient.ClientSecretHash) != 32 {
		t.Errorf("ClientSecretHash length = %d, want 32", len(createdClient.ClientSecretHash))
	}
	if createdClient.ClientType != "confidential" || createdClient.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("client type/auth = %q/%q, want confidential/client_secret_basic", createdClient.ClientType, createdClient.TokenEndpointAuthMethod)
	}
	if createdClient.Environment != "production" {
		t.Errorf("Environment = %q, want production", createdClient.Environment)
	}
	if len(createdClient.RedirectURIs) != 2 || createdClient.RedirectURIs[0] != "https://example.com/callback" {
		t.Errorf("RedirectURIs = %v, want two URIs", createdClient.RedirectURIs)
	}
	if strings.Contains(string(body), "client_secret_hash") {
		t.Error("response body contains the secret hash")
	}
}

func TestRegisterAppRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
	}{
		{
			name: "missing app name",
			form: url.Values{"name": {"   "}, "allowed_scopes": {"openid"}, "client_type": {"confidential"}, "redirect_uris": {"https://example.com/callback"}, "environment": {"local"}},
		},
		{
			name: "unsupported scope",
			form: url.Values{"name": {"App"}, "allowed_scopes": {"admin:all"}, "client_type": {"confidential"}, "redirect_uris": {"https://example.com/callback"}, "environment": {"local"}},
		},
		{
			name: "no redirect URIs",
			form: url.Values{"name": {"App"}, "allowed_scopes": {"openid"}, "client_type": {"confidential"}, "redirect_uris": {""}, "environment": {"local"}},
		},
		{
			name: "insecure non-localhost redirect",
			form: url.Values{"name": {"App"}, "allowed_scopes": {"openid"}, "client_type": {"confidential"}, "redirect_uris": {"http://example.com/callback"}, "environment": {"local"}},
		},
		{
			name: "relative redirect",
			form: url.Values{"name": {"App"}, "allowed_scopes": {"openid"}, "client_type": {"confidential"}, "redirect_uris": {"/callback"}, "environment": {"local"}},
		},
		{
			name: "unknown environment",
			form: url.Values{"name": {"App"}, "allowed_scopes": {"openid"}, "client_type": {"confidential"}, "redirect_uris": {"https://example.com/callback"}, "environment": {"moon"}},
		},
		{
			name: "unknown client type",
			form: url.Values{"name": {"App"}, "allowed_scopes": {"openid"}, "client_type": {"robot"}, "redirect_uris": {"https://example.com/callback"}, "environment": {"local"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, _, _, applications, clients, operators, _ := newTestApp()
			cookie := operatorSessionCookie(t, app, operators, "invalid@example.com")

			req := httptest.NewRequest(http.MethodPost, "/admin/apps", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()

			app.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if len(applications.apps) != 0 || len(clients.clients) != 0 {
				t.Errorf("invalid registration created app/client: %d apps, %d clients", len(applications.apps), len(clients.clients))
			}
		})
	}
}

func TestAppNewPageRenders(t *testing.T) {
	app, _, _, _, _, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "newpage@example.com")

	req := httptest.NewRequest(http.MethodGet, "/admin/apps/new", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{`action="/admin/apps"`, `name="name"`, `name="client_type"`, `name="redirect_uris"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response body missing %q", want)
		}
	}
}

func TestCreateAppRedirectsAnonymousToLogin(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	form := url.Values{"name": {"Todo App"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/apps", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/login" {
		t.Errorf("Location = %q, want %q", loc, "/admin/login")
	}
}

func TestSetupPageRendersWhenNoOperators(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/setup", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	for _, want := range []string{
		`action="/setup"`,
		`name="email"`,
		`name="password"`,
		`name="password_confirm"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response body missing %q", want)
		}
	}
}

func TestSetupPageGoneOnceOperatorExists(t *testing.T) {
	app, _, _, _, _, operators, _ := newTestApp()

	operators.operators = []db.Operator{{ID: 1, Email: "ops@example.com", PasswordHash: "hash"}}

	req := httptest.NewRequest(http.MethodGet, "/setup", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusTemporaryRedirect)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/login" {
		t.Errorf("Location = %q, want %q", loc, "/admin/login")
	}
}

func TestSetupCreatesFirstOperator(t *testing.T) {
	app, _, _, _, _, operators, _ := newTestApp()

	form := url.Values{"email": {"ops@example.com"}, "password": {"correct-password"}, "password_confirm": {"correct-password"}}
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}

	if len(operators.operators) != 1 {
		t.Fatalf("stored %d operators, want 1", len(operators.operators))
	}
	created := operators.operators[0]
	if created.Email != "ops@example.com" {
		t.Errorf("Email = %q, want %q", created.Email, "ops@example.com")
	}
	if created.PasswordHash == "" || !strings.HasPrefix(created.PasswordHash, "$argon2id$") {
		t.Errorf("PasswordHash = %q, want an argon2id encoded hash", created.PasswordHash)
	}
}

func TestSetupRejectsMismatchedPasswords(t *testing.T) {
	app, _, _, _, _, operators, _ := newTestApp()

	form := url.Values{"email": {"ops@example.com"}, "password": {"correct-password"}, "password_confirm": {"other-password"}}
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (setup page re-rendered)", rec.Code, http.StatusOK)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !strings.Contains(string(body), "Passwords must match") {
		t.Error("response body missing error message")
	}
	if len(operators.operators) != 0 {
		t.Errorf("created %d operators with mismatched passwords, want 0", len(operators.operators))
	}
}

func TestSetupGoneOnceOperatorExists(t *testing.T) {
	app, _, _, _, _, operators, _ := newTestApp()

	operators.operators = []db.Operator{{ID: 1, Email: "ops@example.com", PasswordHash: "hash"}}

	form := url.Values{"email": {"second@example.com"}, "password": {"correct-password"}, "password_confirm": {"correct-password"}}
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusTemporaryRedirect)
	}
	if len(operators.operators) != 1 {
		t.Errorf("stored %d operators, want 1", len(operators.operators))
	}
}

func TestSetupSeatClaimedExactlyOnce(t *testing.T) {
	app, _, _, _, _, operators, _ := newTestApp()

	post := func() *httptest.ResponseRecorder {
		form := url.Values{"email": {"ops@example.com"}, "password": {"correct-password"}, "password_confirm": {"correct-password"}}
		req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		app.routes().ServeHTTP(rec, req)
		return rec
	}

	first := post()
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first setup: got status %d, want %d", first.Code, http.StatusSeeOther)
	}

	second := post()
	if second.Code != http.StatusTemporaryRedirect {
		t.Fatalf("second setup: got status %d, want %d", second.Code, http.StatusTemporaryRedirect)
	}

	if len(operators.operators) != 1 {
		t.Errorf("stored %d operators, want 1", len(operators.operators))
	}
}

func TestOperatorLoginPageRendersWithoutSignup(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	for _, want := range []string{
		`action="/admin/auth/login"`,
		`name="email"`,
		`name="password"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response body missing %q", want)
		}
	}
	if strings.Contains(string(body), "/auth/register") {
		t.Error("operator login page contains a sign-up affordance")
	}
}

func TestOperatorLoginCreatesSessionAndCookie(t *testing.T) {
	app, _, _, _, _, operators, operatorSessions := newTestApp()

	hash, err := service.HashPassword("correct-password", &service.PasswordHashParams{
		Memory:      64,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   32,
		SaltLength:  16,
	})
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}

	operator := db.Operator{ID: 7, Email: "ops@example.com", PasswordHash: hash}
	operators.operators = append(operators.operators, operator)

	form := url.Values{"email": {operator.Email}, "password": {"correct-password"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin" {
		t.Errorf("Location = %q, want %q", loc, "/admin")
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "centrauth_operator" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("operator login did not set a session cookie")
	}
	if !sessionCookie.HttpOnly {
		t.Error("operator session cookie is not HttpOnly")
	}

	if len(operatorSessions.sessions) != 1 {
		t.Fatalf("stored %d operator sessions, want 1", len(operatorSessions.sessions))
	}
	if operatorSessions.sessions[0].OperatorID != operator.ID {
		t.Errorf("stored session OperatorID = %d, want %d", operatorSessions.sessions[0].OperatorID, operator.ID)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("admin with operator session: got status %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestOperatorLoginRejectsWrongPassword(t *testing.T) {
	app, _, _, _, _, operators, operatorSessions := newTestApp()

	hash, err := service.HashPassword("correct-password", &service.PasswordHashParams{
		Memory:      64,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   32,
		SaltLength:  16,
	})
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}

	operator := db.Operator{ID: 7, Email: "wrongpw-ops@example.com", PasswordHash: hash}
	operators.operators = append(operators.operators, operator)

	form := url.Values{"email": {operator.Email}, "password": {"wrong-password"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (login page re-rendered)", rec.Code, http.StatusOK)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !strings.Contains(string(body), "Invalid email or password") {
		t.Error("response body missing generic error message")
	}
	if len(operatorSessions.sessions) != 0 {
		t.Errorf("created %d operator sessions on failed login, want 0", len(operatorSessions.sessions))
	}
}

func TestOperatorLoginRejectsUnknownEmail(t *testing.T) {
	app, _, _, _, _, _, operatorSessions := newTestApp()

	form := url.Values{"email": {"nobody@example.com"}, "password": {"correct-password"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (login page re-rendered)", rec.Code, http.StatusOK)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !strings.Contains(string(body), "Invalid email or password") {
		t.Error("response body missing generic error message")
	}
	if len(operatorSessions.sessions) != 0 {
		t.Errorf("created %d operator sessions on failed login, want 0", len(operatorSessions.sessions))
	}
}

func TestOperatorLogoutRevokesSessionAndClearsCookie(t *testing.T) {
	app, _, _, _, _, operators, _ := newTestApp()

	operator := db.Operator{ID: 7, Email: "logout-ops@example.com", PasswordHash: "hash"}
	operators.operators = append(operators.operators, operator)

	token, err := app.operatorSessions.Create(context.Background(), operator.ID)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "centrauth_operator", Value: token})
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/login" {
		t.Errorf("Location = %q, want %q", loc, "/admin/login")
	}

	var cleared *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "centrauth_operator" {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatal("operator logout did not clear the session cookie")
	}
	if cleared.MaxAge != -1 {
		t.Errorf("clearing cookie MaxAge = %d, want -1", cleared.MaxAge)
	}

	if _, err := app.operatorSessions.Validate(context.Background(), token); !errors.Is(err, session.ErrSessionRevoked) {
		t.Errorf("Validate() after logout error = %v, want %v", err, session.ErrSessionRevoked)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "centrauth_operator", Value: token})
	rec = httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("admin with revoked operator session: got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
}

func TestSetupCreatesOperatorSession(t *testing.T) {
	app, _, _, _, _, operators, operatorSessions := newTestApp()

	form := url.Values{"email": {"ops@example.com"}, "password": {"correct-password"}, "password_confirm": {"correct-password"}}
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if len(operators.operators) != 1 {
		t.Fatalf("stored %d operators, want 1", len(operators.operators))
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "centrauth_operator" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("setup did not set an operator session cookie")
	}
	if len(operatorSessions.sessions) != 1 {
		t.Fatalf("stored %d operator sessions, want 1", len(operatorSessions.sessions))
	}
	if operatorSessions.sessions[0].OperatorID != operators.operators[0].ID {
		t.Errorf("stored session OperatorID = %d, want %d", operatorSessions.sessions[0].OperatorID, operators.operators[0].ID)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("admin with setup session cookie: got status %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestJWKSRoute(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q", got)
	}

	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), app.keyManager.KeyID()) {
		t.Errorf("JWKS body missing key ID %q", app.keyManager.KeyID())
	}
	if !strings.Contains(string(body), `"kty":"RSA"`) || !strings.Contains(string(body), `"alg":"RS256"`) {
		t.Errorf("JWKS body missing RSA/RS256 metadata: %s", body)
	}
}

func TestDiscoveryRoute(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q", got)
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode discovery document: %v", err)
	}
	if doc["issuer"] != "http://localhost:8080" {
		t.Errorf("issuer = %v", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "http://localhost:8080/authorize" {
		t.Errorf("authorization_endpoint = %v", doc["authorization_endpoint"])
	}
	if doc["token_endpoint"] != "http://localhost:8080/token" {
		t.Errorf("token_endpoint = %v", doc["token_endpoint"])
	}
	if doc["jwks_uri"] != "http://localhost:8080/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v", doc["jwks_uri"])
	}
}

const testPKCEVerifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

func seedOAuthClient(t *testing.T, app *App, applications *fakeApplicationRepo, clients *fakeClientRepo, clientID, clientType, secret string) (db.Application, db.OAuthClient) {
	t.Helper()

	appModel := db.Application{
		ID:            int64(len(applications.apps) + 1),
		Name:          "Test App",
		FirstParty:    true,
		AllowedScopes: pq.StringArray{"openid", "profile", "email"},
		CreatedAt:     time.Now().Add(-time.Hour),
	}
	applications.apps = append(applications.apps, appModel)

	authMethod := "none"
	var hash []byte
	if clientType == "confidential" {
		authMethod = "client_secret_basic"
		sum := sha256.Sum256([]byte(secret))
		hash = sum[:]
	}
	client := db.OAuthClient{
		ID:                      int64(len(clients.clients) + 1),
		ApplicationID:           appModel.ID,
		ClientID:                clientID,
		ClientSecretHash:        hash,
		ClientType:              clientType,
		TokenEndpointAuthMethod: authMethod,
		RedirectURIs:            pq.StringArray{"https://app.example.com/callback"},
		Environment:             "production",
		CreatedAt:               time.Now(),
	}
	clients.clients = append(clients.clients, client)
	return appModel, client
}

func signedInCookie(t *testing.T, app *App, users *fakeUserRepo, userID int64) *http.Cookie {
	t.Helper()
	users.byID[userID] = db.User{ID: userID, Subject: "subject-1", Email: "user@example.com"}
	token, err := app.sessions.Create(context.Background(), userID)
	if err != nil {
		t.Fatalf("creating user session: %v", err)
	}
	return &http.Cookie{Name: "centrauth_session", Value: token}
}

func authorizeRequest(clientID, redirectURI, scope, nonce, challenge, method, state string) string {
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"state":                 {state},
		"scope":                 {scope},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {method},
	}
	return "/authorize?" + q.Encode()
}

func TestAuthorizeRejectsUnknownClient(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, authorizeRequest("nope", "https://app.example.com/callback", "openid", "n", oauth.PKCEChallenge(testPKCEVerifier), "S256", "state"), nil)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want no redirect", loc)
	}
}

func TestAuthorizeRejectsUnregisteredRedirectURI(t *testing.T) {
	app, _, _, applications, clients, _, _ := newTestApp()
	seedOAuthClient(t, app, applications, clients, "client-1", "public", "")

	req := httptest.NewRequest(http.MethodGet, authorizeRequest("client-1", "https://evil.example.com/callback", "openid", "n", oauth.PKCEChallenge(testPKCEVerifier), "S256", "state"), nil)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want no redirect to an unregistered URI", loc)
	}
}

func TestAuthorizeIssuesCodeForSignedInUser(t *testing.T) {
	app, users, _, applications, clients, _, _ := newTestApp()
	_, client := seedOAuthClient(t, app, applications, clients, "client-1", "public", "")
	cookie := signedInCookie(t, app, users, 7)

	challenge := oauth.PKCEChallenge(testPKCEVerifier)
	req := httptest.NewRequest(http.MethodGet, authorizeRequest("client-1", "https://app.example.com/callback", "openid profile", "nonce-1", challenge, "S256", "state-1"), nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusFound)
	}

	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("redirect missing code")
	}
	if location.Query().Get("state") != "state-1" {
		t.Errorf("state = %q", location.Query().Get("state"))
	}

	codes := app.codes.(*fakeCodeRepo)
	if len(codes.codes) != 1 {
		t.Fatalf("stored %d codes, want 1", len(codes.codes))
	}
	stored := codes.codes[0]
	if !bytes.Equal(stored.CodeHash, oauth.HashAuthorizationCode(code)) {
		t.Error("stored code hash does not match the issued code")
	}
	if stored.OAuthClientID != client.ID || stored.UserID != 7 {
		t.Errorf("stored client/user = %d/%d, want %d/7", stored.OAuthClientID, stored.UserID, client.ID)
	}
	if stored.RedirectURI != "https://app.example.com/callback" || stored.Scope != "openid profile" {
		t.Errorf("stored redirect/scope = %q/%q", stored.RedirectURI, stored.Scope)
	}
	if stored.Nonce == nil || *stored.Nonce != "nonce-1" {
		t.Errorf("stored nonce = %v", stored.Nonce)
	}
	if stored.CodeChallenge != challenge || stored.CodeChallengeMethod != "S256" {
		t.Errorf("stored challenge/method = %q/%q", stored.CodeChallenge, stored.CodeChallengeMethod)
	}
	if ttl := time.Until(stored.ExpiresAt); ttl < 50*time.Second || ttl > 61*time.Second {
		t.Errorf("code TTL = %v, want about 60s", ttl)
	}
}

func TestAuthorizeRedirectsRequestErrors(t *testing.T) {
	tests := []struct {
		name         string
		scope        string
		nonce        string
		challenge    string
		method       string
		responseType string
		wantError    string
	}{
		{"missing pkce", "openid", "n", "", "S256", "code", "invalid_request"},
		{"plain pkce", "openid", "n", oauth.PKCEChallenge(testPKCEVerifier), "plain", "code", "invalid_request"},
		{"missing nonce", "openid", "", oauth.PKCEChallenge(testPKCEVerifier), "S256", "code", "invalid_request"},
		{"bad response type", "openid", "n", oauth.PKCEChallenge(testPKCEVerifier), "S256", "token", "unsupported_response_type"},
		{"invalid scope", "admin:all", "n", oauth.PKCEChallenge(testPKCEVerifier), "S256", "code", "invalid_scope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, users, _, applications, clients, _, _ := newTestApp()
			seedOAuthClient(t, app, applications, clients, "client-1", "public", "")
			cookie := signedInCookie(t, app, users, 7)

			q := url.Values{
				"client_id":             {"client-1"},
				"redirect_uri":          {"https://app.example.com/callback"},
				"response_type":         {tt.responseType},
				"state":                 {"state-1"},
				"scope":                 {tt.scope},
				"nonce":                 {tt.nonce},
				"code_challenge":        {tt.challenge},
				"code_challenge_method": {tt.method},
			}
			req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			app.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Fatalf("got status %d, want %d", rec.Code, http.StatusFound)
			}
			location, _ := url.Parse(rec.Header().Get("Location"))
			if got := location.Query().Get("error"); got != tt.wantError {
				t.Errorf("error = %q, want %q", got, tt.wantError)
			}
			if location.Query().Get("state") != "state-1" {
				t.Errorf("state = %q, want state-1", location.Query().Get("state"))
			}
			if codes := app.codes.(*fakeCodeRepo); len(codes.codes) != 0 {
				t.Errorf("issued %d codes for an invalid request", len(codes.codes))
			}
		})
	}
}

func TestAuthorizeRendersPromptForAnonymousUser(t *testing.T) {
	app, _, _, applications, clients, _, _ := newTestApp()
	seedOAuthClient(t, app, applications, clients, "client-1", "public", "")

	req := httptest.NewRequest(http.MethodGet, authorizeRequest("client-1", "https://app.example.com/callback", "openid", "n", oauth.PKCEChallenge(testPKCEVerifier), "S256", "state-1"), nil)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "No sign-in method is configured") {
		t.Error("prompt missing placeholder message")
	}
	if !strings.Contains(string(body), "Test App") {
		t.Error("prompt missing app name")
	}

	var promptCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "centrauth_authz" {
			promptCookie = c
		}
	}
	if promptCookie == nil {
		t.Error("prompt did not preserve the authorization request")
	}
}

func exchangeCode(t *testing.T, app *App, form url.Values, basicID, basicSecret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)
	return rec
}

func issueCode(t *testing.T, app *App, users *fakeUserRepo, clientID string) (string, string) {
	t.Helper()
	cookie := signedInCookie(t, app, users, 7)
	req := httptest.NewRequest(http.MethodGet, authorizeRequest(clientID, "https://app.example.com/callback", "openid profile", "nonce-1", oauth.PKCEChallenge(testPKCEVerifier), "S256", "state-1"), nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize got status %d, want %d", rec.Code, http.StatusFound)
	}
	location, _ := url.Parse(rec.Header().Get("Location"))
	return location.Query().Get("code"), location.Query().Get("state")
}

func TestTokenExchangesCode(t *testing.T) {
	app, users, _, applications, clients, _, _ := newTestApp()
	seedOAuthClient(t, app, applications, clients, "client-1", "confidential", "secret-1")

	code, state := issueCode(t, app, users, "client-1")
	if code == "" || state != "state-1" {
		t.Fatalf("issueCode() = %q/%q", code, state)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"code_verifier": {testPKCEVerifier},
	}
	rec := exchangeCode(t, app, form, "client-1", "secret-1")

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q", got)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["token_type"] != "Bearer" || resp["expires_in"].(float64) != 600 {
		t.Errorf("response = %v", resp)
	}
	idToken, _ := resp["id_token"].(string)
	if idToken == "" {
		t.Fatal("response missing id_token for an openid request")
	}

	parsed, err := jose.ParseSigned(idToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse id_token: %v", err)
	}
	payload, err := parsed.Verify(app.keyManager.PublicKey())
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	var claims oidc.IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	if claims.Sub != "subject-1" || claims.Aud != "client-1" || claims.Nonce != "nonce-1" {
		t.Errorf("claims = %+v", claims)
	}

	// Replaying the code must fail.
	replay := exchangeCode(t, app, form, "client-1", "secret-1")
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want %d", replay.Code, http.StatusBadRequest)
	}
	var replayErr map[string]string
	_ = json.Unmarshal(replay.Body.Bytes(), &replayErr)
	if replayErr["error"] != "invalid_grant" {
		t.Errorf("replay error = %q, want invalid_grant", replayErr["error"])
	}
}

func TestTokenRejectsBadRequests(t *testing.T) {
	app, users, _, applications, clients, _, _ := newTestApp()
	seedOAuthClient(t, app, applications, clients, "client-1", "confidential", "secret-1")

	base := func() url.Values {
		code, _ := issueCode(t, app, users, "client-1")
		return url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://app.example.com/callback"},
			"code_verifier": {testPKCEVerifier},
		}
	}

	tests := []struct {
		name        string
		mutate      func(url.Values)
		basicID     string
		basicSecret string
		wantStatus  int
		wantError   string
	}{
		{"missing grant type", func(f url.Values) { f.Del("grant_type") }, "client-1", "secret-1", http.StatusBadRequest, "invalid_request"},
		{"wrong grant type", func(f url.Values) { f.Set("grant_type", "password") }, "client-1", "secret-1", http.StatusBadRequest, "unsupported_grant_type"},
		{"missing verifier", func(f url.Values) { f.Del("code_verifier") }, "client-1", "secret-1", http.StatusBadRequest, "invalid_request"},
		{"wrong verifier", func(f url.Values) { f.Set("code_verifier", strings.Repeat("z", 43)) }, "client-1", "secret-1", http.StatusBadRequest, "invalid_grant"},
		{"redirect mismatch", func(f url.Values) { f.Set("redirect_uri", "https://app.example.com/other") }, "client-1", "secret-1", http.StatusBadRequest, "invalid_grant"},
		{"wrong secret", func(f url.Values) {}, "client-1", "wrong", http.StatusUnauthorized, "invalid_client"},
		{"missing secret", func(f url.Values) { f.Set("client_id", "client-1") }, "", "", http.StatusUnauthorized, "invalid_client"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := base()
			tt.mutate(form)
			rec := exchangeCode(t, app, form, tt.basicID, tt.basicSecret)

			if rec.Code != tt.wantStatus {
				t.Fatalf("got status %d, want %d: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			var resp map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			if resp["error"] != tt.wantError {
				t.Errorf("error = %q, want %q", resp["error"], tt.wantError)
			}
		})
	}
}

func TestTokenRejectsExpiredCode(t *testing.T) {
	app, users, _, applications, clients, _, _ := newTestApp()
	seedOAuthClient(t, app, applications, clients, "client-1", "confidential", "secret-1")

	code, _ := issueCode(t, app, users, "client-1")
	codes := app.codes.(*fakeCodeRepo)
	codes.codes[0].ExpiresAt = time.Now().Add(-time.Second)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"code_verifier": {testPKCEVerifier},
	}
	rec := exchangeCode(t, app, form, "client-1", "secret-1")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", resp["error"])
	}
}

func TestTokenPublicClientWithoutSecret(t *testing.T) {
	app, users, _, applications, clients, _, _ := newTestApp()
	seedOAuthClient(t, app, applications, clients, "client-public", "public", "")

	code, _ := issueCode(t, app, users, "client-public")
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"code_verifier": {testPKCEVerifier},
		"client_id":     {"client-public"},
	}
	rec := exchangeCode(t, app, form, "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAdminAppRoutesRequireOperator(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	routes := []string{
		"/admin/apps",
		"/admin/apps/new",
		"/admin/apps/1",
		"/admin/apps/1/edit",
		"/admin/apps/1/clients/new",
		"/admin/clients/1",
	}

	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route, nil)
			rec := httptest.NewRecorder()
			app.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
			}
			if loc := rec.Header().Get("Location"); loc != "/admin/login" {
				t.Errorf("Location = %q, want /admin/login", loc)
			}
		})
	}
}

func TestAppListRendersApps(t *testing.T) {
	app, _, _, applications, clients, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "list@example.com")

	applications.apps = []db.Application{{
		ID:            1,
		Name:          "Todo App",
		Description:   "A todo app",
		FirstParty:    true,
		AllowedScopes: pq.StringArray{"openid", "profile"},
	}}
	clients.clients = []db.OAuthClient{{ID: 1, ApplicationID: 1, ClientID: "todo-web", ClientType: "public", Environment: "production"}}

	req := httptest.NewRequest(http.MethodGet, "/admin/apps", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{"Todo App", "A todo app", "production", `href="/admin/apps/1"`, `href="/admin/apps/new"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response body missing %q", want)
		}
	}
}

func TestAppDetailRendersMetadataAndClients(t *testing.T) {
	app, _, _, applications, clients, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "detail@example.com")

	applications.apps = []db.Application{{
		ID:            1,
		Name:          "Todo App",
		Description:   "A todo app",
		FirstParty:    true,
		AllowedScopes: pq.StringArray{"openid"},
	}}
	clients.clients = []db.OAuthClient{
		{ID: 1, ApplicationID: 1, ClientID: "todo-web", ClientType: "confidential", TokenEndpointAuthMethod: "client_secret_basic", Environment: "production", RedirectURIs: pq.StringArray{"https://todo.example.com/callback"}},
		{ID: 2, ApplicationID: 1, ClientID: "todo-mobile", ClientType: "public", Environment: "local"},
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/apps/1", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{"Todo App", "A todo app", "todo-web", "todo-mobile", "https://todo.example.com/callback", `href="/admin/apps/1/clients/new"`, `href="/admin/apps/1/edit"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response body missing %q", want)
		}
	}
}

func TestAppEditPersistsChanges(t *testing.T) {
	app, _, _, applications, _, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "edit@example.com")

	applications.apps = []db.Application{{ID: 1, Name: "Old Name", FirstParty: true, AllowedScopes: pq.StringArray{"openid"}}}

	form := url.Values{
		"name":           {"New Name"},
		"description":    {"Updated description"},
		"first_party":    {"on"},
		"allowed_scopes": {"openid profile"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/apps/1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/apps/1" {
		t.Errorf("Location = %q, want /admin/apps/1", loc)
	}
	if applications.apps[0].Name != "New Name" || applications.apps[0].Description != "Updated description" || len(applications.apps[0].AllowedScopes) != 2 {
		t.Errorf("updated app = %+v", applications.apps[0])
	}
}

func TestAppEditRejectsInvalidInput(t *testing.T) {
	app, _, _, applications, _, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "editbad@example.com")

	applications.apps = []db.Application{{ID: 1, Name: "Old Name", FirstParty: true, AllowedScopes: pq.StringArray{"openid"}}}

	form := url.Values{"name": {"Old Name"}, "allowed_scopes": {"admin:all"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/apps/1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "Unsupported scope") {
		t.Error("response body missing validation error")
	}
	if len(applications.apps[0].AllowedScopes) != 1 || applications.apps[0].AllowedScopes[0] != "openid" {
		t.Errorf("invalid edit changed scopes: %v", applications.apps[0].AllowedScopes)
	}
}

func TestAddClientUnderAppShowsSecretOnce(t *testing.T) {
	app, _, _, applications, clients, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "addclient@example.com")

	applications.apps = []db.Application{{ID: 1, Name: "Todo App", AllowedScopes: pq.StringArray{"openid"}}}

	form := url.Values{
		"client_type":   {"confidential"},
		"environment":   {"staging"},
		"redirect_uris": {"https://staging.example.com/callback"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/apps/1/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if len(clients.clients) != 1 {
		t.Fatalf("stored %d clients, want 1", len(clients.clients))
	}
	created := clients.clients[0]
	if created.ApplicationID != 1 || created.Environment != "staging" {
		t.Errorf("created client = %+v", created)
	}
	if len(created.ClientSecretHash) != 32 {
		t.Errorf("secret hash length = %d, want 32", len(created.ClientSecretHash))
	}

	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), created.ClientID) {
		t.Error("registered page missing client ID")
	}
	if !strings.Contains(string(body), "shown once") {
		t.Error("registered page missing one-time secret warning")
	}
}

func TestAddClientRejectsInvalidInput(t *testing.T) {
	app, _, _, applications, clients, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "addclientbad@example.com")

	applications.apps = []db.Application{{ID: 1, Name: "Todo App", AllowedScopes: pq.StringArray{"openid"}}}

	form := url.Values{"client_type": {"public"}, "environment": {"local"}, "redirect_uris": {"http://example.com/callback"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/apps/1/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if len(clients.clients) != 0 {
		t.Errorf("invalid client input stored %d clients", len(clients.clients))
	}
}

func TestClientDetailNeverShowsSecret(t *testing.T) {
	app, _, _, applications, clients, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "clientdetail@example.com")

	applications.apps = []db.Application{{ID: 1, Name: "Todo App", AllowedScopes: pq.StringArray{"openid"}}}
	hash := sha256.Sum256([]byte("the-secret"))
	clients.clients = []db.OAuthClient{{
		ID:                      1,
		ApplicationID:           1,
		ClientID:                "todo-web",
		ClientSecretHash:        hash[:],
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		Environment:             "production",
		RedirectURIs:            pq.StringArray{"https://todo.example.com/callback"},
		PostLogoutRedirectURIs:  pq.StringArray{"https://todo.example.com"},
		AllowedOrigins:          pq.StringArray{"https://todo.example.com"},
	}}

	req := httptest.NewRequest(http.MethodGet, "/admin/clients/1", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{"todo-web", "client_secret_basic", "production", "https://todo.example.com/callback"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response body missing %q", want)
		}
	}
	if strings.Contains(string(body), "the-secret") || strings.Contains(string(body), "client_secret_hash") {
		t.Error("client detail leaked secret material")
	}
}

func TestDashboardLinksIntoAppManagement(t *testing.T) {
	app, _, _, _, _, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "dashlinks@example.com")

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), `href="/admin/apps/new"`) {
		t.Error("dashboard missing register-app link")
	}
}

func TestProviderRoutesRequireOperator(t *testing.T) {
	app, _, _, _, _, _, _ := newTestApp()

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/apps/1/providers/new"},
		{http.MethodGet, "/admin/apps/1/providers/google/edit"},
		{http.MethodPost, "/admin/apps/1/providers"},
		{http.MethodPost, "/admin/apps/1/providers/google/toggle"},
		{http.MethodPost, "/admin/apps/1/providers/google/delete"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rec := httptest.NewRecorder()
			app.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
			}
			if loc := rec.Header().Get("Location"); loc != "/admin/login" {
				t.Errorf("Location = %q, want /admin/login", loc)
			}
		})
	}
}

func TestAddProviderEncryptsSecretAndListsOnAppDetail(t *testing.T) {
	app, _, _, applications, _, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "provider@example.com")

	applications.apps = []db.Application{{ID: 1, Name: "Todo App", AllowedScopes: pq.StringArray{"openid"}}}

	form := url.Values{
		"provider":      {"google"},
		"client_id":     {"google-client-id"},
		"client_secret": {"google-client-secret"},
		"enabled":       {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/apps/1/providers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}

	providers := app.providerRepo.(*fakeIdentityProviderRepo).providers
	if len(providers) != 1 {
		t.Fatalf("stored %d providers, want 1", len(providers))
	}
	if providers[0].Provider != "google" || providers[0].ClientID != "google-client-id" || !providers[0].Enabled {
		t.Errorf("stored provider = %+v", providers[0])
	}
	if strings.Contains(string(providers[0].ClientSecretEncrypted), "google-client-secret") {
		t.Fatal("provider secret was stored in plaintext")
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/apps/1", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{"google", "google-client-id", "enabled", `href="/admin/apps/1/providers/google/edit"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("app detail missing %q", want)
		}
	}
}

func TestProviderToggleAndDelete(t *testing.T) {
	app, _, _, applications, _, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "providertoggle@example.com")

	applications.apps = []db.Application{{ID: 1, Name: "Todo App"}}
	repo := app.providerRepo.(*fakeIdentityProviderRepo)
	repo.providers = []db.IdentityProvider{{ID: 1, ApplicationID: 1, Provider: "github", ClientID: "gh", Enabled: true}}

	post := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.routes().ServeHTTP(rec, req)
		return rec
	}

	if rec := post("/admin/apps/1/providers/github/toggle"); rec.Code != http.StatusSeeOther {
		t.Fatalf("toggle status = %d, want 303", rec.Code)
	}
	if repo.providers[0].Enabled {
		t.Error("toggle did not disable the provider")
	}

	if rec := post("/admin/apps/1/providers/github/delete"); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete status = %d, want 303", rec.Code)
	}
	if len(repo.providers) != 0 {
		t.Errorf("providers after delete = %d, want 0", len(repo.providers))
	}
}

func TestProviderEditKeepsSecretWhenBlank(t *testing.T) {
	app, _, _, applications, _, operators, _ := newTestApp()
	cookie := operatorSessionCookie(t, app, operators, "provideredit@example.com")

	applications.apps = []db.Application{{ID: 1, Name: "Todo App"}}

	form := url.Values{"provider": {"github"}, "client_id": {"gh-1"}, "client_secret": {"secret-1"}, "enabled": {"on"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/apps/1/providers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	repo := app.providerRepo.(*fakeIdentityProviderRepo)
	originalSecret := string(repo.providers[0].ClientSecretEncrypted)

	form = url.Values{"provider": {"github"}, "client_id": {"gh-2"}, "client_secret": {""}, "enabled": {"on"}, "is_edit": {"true"}}
	req = httptest.NewRequest(http.MethodPost, "/admin/apps/1/providers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit status = %d, want 303", rec.Code)
	}
	if repo.providers[0].ClientID != "gh-2" {
		t.Errorf("client ID = %q, want gh-2", repo.providers[0].ClientID)
	}
	if string(repo.providers[0].ClientSecretEncrypted) != originalSecret {
		t.Error("blank secret edit rotated the stored secret")
	}
}
