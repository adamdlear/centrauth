package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
	pq "github.com/lib/pq"
)

func TestClientRepo_GetByClientID(t *testing.T) {
	const seededClientID = "session-repo-test-client"

	tests := []struct {
		name     string
		clientID string
		wantErr  error
	}{
		{"existing client", seededClientID, nil},
		{"nonexistent client", "no-such-client", ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := newTestTx(t)
			app := seedApplication(t, tx, db.Application{Name: "Session Repo Test App"})
			seedClient(t, tx, db.OAuthClient{
				ApplicationID: app.ID,
				ClientID:      seededClientID,
				ClientType:    "confidential",
				RedirectURIs:  pq.StringArray{"https://example.com/callback"},
			})
			repo := NewGormClientRepo(tx)

			client, err := repo.GetByClientID(context.Background(), tt.clientID)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByClientID(%q) error = %v, want %v", tt.clientID, err, tt.wantErr)
			}
			if err == nil && client.ClientID != seededClientID {
				t.Errorf("GetByClientID(%q) returned clientID %q, want %q", tt.clientID, client.ClientID, seededClientID)
			}
			if err == nil && client.ApplicationID != app.ID {
				t.Errorf("GetByClientID(%q) returned applicationID %d, want %d", tt.clientID, client.ApplicationID, app.ID)
			}
		})
	}
}

func TestClientRepo_Create(t *testing.T) {
	tx := newTestTx(t)
	app := seedApplication(t, tx, db.Application{Name: "Client Repo Create App"})
	repo := NewGormClientRepo(tx)

	client, err := repo.Create(context.Background(), &db.OAuthClient{
		ApplicationID: app.ID,
		ClientID:      "client-repo-create",
		ClientType:    "public",
		RedirectURIs:  pq.StringArray{"https://example.com/callback"},
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if client.ID == 0 {
		t.Error("Create() did not backfill ID")
	}

	fetched, err := repo.GetByClientID(context.Background(), "client-repo-create")
	if err != nil {
		t.Fatalf("GetByClientID() after Create() error = %v", err)
	}
	if fetched.ApplicationID != app.ID {
		t.Errorf("GetByClientID() returned applicationID %d, want %d", fetched.ApplicationID, app.ID)
	}
	if len(fetched.RedirectURIs) != 1 || fetched.RedirectURIs[0] != "https://example.com/callback" {
		t.Errorf("GetByClientID() returned redirect URIs %v, want [https://example.com/callback]", fetched.RedirectURIs)
	}

	_, err = repo.Create(context.Background(), &db.OAuthClient{
		ApplicationID: app.ID,
		ClientID:      "client-repo-create",
		ClientType:    "confidential",
		RedirectURIs:  pq.StringArray{},
	})
	if err == nil {
		t.Error("Create() with duplicate client_id: want error, got nil")
	}
}

func TestClientRepo_Update(t *testing.T) {
	tx := newTestTx(t)
	app := seedApplication(t, tx, db.Application{Name: "Client Repo Update App"})
	repo := NewGormClientRepo(tx)

	seeded := seedClient(t, tx, db.OAuthClient{
		ApplicationID:           app.ID,
		ClientID:                "client-repo-update",
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		ClientSecretHash:        []byte("secret-hash"),
		RedirectURIs:            pq.StringArray{"https://example.com/callback"},
		Environment:             "production",
	})

	updated := seeded
	updated.ClientSecretHash = nil
	updated.TokenEndpointAuthMethod = "client_secret_post"
	updated.RedirectURIs = pq.StringArray{"https://new.example.com/callback"}
	updated.AllowedOrigins = pq.StringArray{"https://new.example.com"}
	updated.Environment = "staging"

	if _, err := repo.Update(context.Background(), &updated); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	fetched, err := repo.GetByClientID(context.Background(), "client-repo-update")
	if err != nil {
		t.Fatalf("GetByClientID() after Update() error = %v", err)
	}
	if fetched.ClientSecretHash != nil {
		t.Error("ClientSecretHash not cleared, want nil")
	}
	if fetched.TokenEndpointAuthMethod != "client_secret_post" {
		t.Errorf("TokenEndpointAuthMethod = %q, want %q", fetched.TokenEndpointAuthMethod, "client_secret_post")
	}
	if fetched.Environment != "staging" {
		t.Errorf("Environment = %q, want %q", fetched.Environment, "staging")
	}
	if len(fetched.RedirectURIs) != 1 || fetched.RedirectURIs[0] != "https://new.example.com/callback" {
		t.Errorf("RedirectURIs = %v, want [https://new.example.com/callback]", fetched.RedirectURIs)
	}
	if len(fetched.AllowedOrigins) != 1 || fetched.AllowedOrigins[0] != "https://new.example.com" {
		t.Errorf("AllowedOrigins = %v, want [https://new.example.com]", fetched.AllowedOrigins)
	}
	if fetched.ApplicationID != app.ID {
		t.Errorf("ApplicationID = %d, want unchanged %d", fetched.ApplicationID, app.ID)
	}
	if fetched.ID != seeded.ID {
		t.Errorf("ID = %d, want unchanged %d", fetched.ID, seeded.ID)
	}

	missing := db.OAuthClient{
		ID:            seeded.ID + 1_000_000,
		ApplicationID: app.ID,
		ClientID:      "client-repo-update-missing",
		ClientType:    "public",
		RedirectURIs:  pq.StringArray{},
	}
	if _, err := repo.Update(context.Background(), &missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update() with nonexistent ID error = %v, want ErrNotFound", err)
	}
}

func TestClientRepo_List(t *testing.T) {
	tx := newTestTx(t)
	app := seedApplication(t, tx, db.Application{Name: "Client Repo List App"})
	repo := NewGormClientRepo(tx)

	seedClient(t, tx, db.OAuthClient{
		ApplicationID: app.ID,
		ClientID:      "client-repo-list-a",
		ClientType:    "public",
		Environment:   "local",
		RedirectURIs:  pq.StringArray{},
	})
	seedClient(t, tx, db.OAuthClient{
		ApplicationID: app.ID,
		ClientID:      "client-repo-list-b",
		ClientType:    "confidential",
		Environment:   "production",
		RedirectURIs:  pq.StringArray{},
	})

	clients, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	found := map[string]bool{}
	for _, c := range clients {
		found[c.ClientID] = true
	}
	for _, want := range []string{"client-repo-list-a", "client-repo-list-b"} {
		if !found[want] {
			t.Errorf("List() missing seeded client %q", want)
		}
	}
}

func TestClientRepo_ListByEnvironment(t *testing.T) {
	tx := newTestTx(t)
	app := seedApplication(t, tx, db.Application{Name: "Client Repo Environment App"})
	repo := NewGormClientRepo(tx)

	seedClient(t, tx, db.OAuthClient{
		ApplicationID: app.ID,
		ClientID:      "client-repo-env-local",
		ClientType:    "public",
		Environment:   "local",
		RedirectURIs:  pq.StringArray{},
	})
	seedClient(t, tx, db.OAuthClient{
		ApplicationID: app.ID,
		ClientID:      "client-repo-env-production",
		ClientType:    "confidential",
		Environment:   "production",
		RedirectURIs:  pq.StringArray{},
	})

	clients, err := repo.ListByEnvironment(context.Background(), "local")
	if err != nil {
		t.Fatalf("ListByEnvironment(local) error = %v", err)
	}

	foundLocal := false
	for _, c := range clients {
		if c.Environment != "local" {
			t.Errorf("ListByEnvironment(local) returned client %q with environment %q", c.ClientID, c.Environment)
		}
		if c.ClientID == "client-repo-env-local" {
			foundLocal = true
		}
	}
	if !foundLocal {
		t.Error("ListByEnvironment(local) missing seeded client client-repo-env-local")
	}

	if clients, err = repo.ListByEnvironment(context.Background(), "staging"); err != nil {
		t.Fatalf("ListByEnvironment(staging) error = %v", err)
	}
	for _, c := range clients {
		if c.ClientID == "client-repo-env-local" || c.ClientID == "client-repo-env-production" {
			t.Errorf("ListByEnvironment(staging) returned client %q from another environment", c.ClientID)
		}
	}
}

func TestClientRepo_ListByApplicationID(t *testing.T) {
	tx := newTestTx(t)
	repo := NewGormClientRepo(tx)

	appA := seedApplication(t, tx, db.Application{Name: "App A"})
	appB := seedApplication(t, tx, db.Application{Name: "App B"})

	seedClient(t, tx, db.OAuthClient{
		ApplicationID: appA.ID,
		ClientID:      "client-repo-app-a-web",
		ClientType:    "confidential",
		RedirectURIs:  pq.StringArray{},
	})
	seedClient(t, tx, db.OAuthClient{
		ApplicationID: appA.ID,
		ClientID:      "client-repo-app-a-mobile",
		ClientType:    "public",
		RedirectURIs:  pq.StringArray{},
	})
	seedClient(t, tx, db.OAuthClient{
		ApplicationID: appB.ID,
		ClientID:      "client-repo-app-b-web",
		ClientType:    "confidential",
		RedirectURIs:  pq.StringArray{},
	})

	clients, err := repo.ListByApplicationID(context.Background(), appA.ID)
	if err != nil {
		t.Fatalf("ListByApplicationID(appA) error = %v", err)
	}

	found := map[string]bool{}
	for _, c := range clients {
		if c.ApplicationID != appA.ID {
			t.Errorf("ListByApplicationID(appA) returned client %q with applicationID %d", c.ClientID, c.ApplicationID)
		}
		found[c.ClientID] = true
	}
	if !found["client-repo-app-a-web"] || !found["client-repo-app-a-mobile"] {
		t.Errorf("ListByApplicationID(appA) missing seeded clients, found %v", found)
	}
	if found["client-repo-app-b-web"] {
		t.Error("ListByApplicationID(appA) returned client belonging to app B")
	}

	if clients, err = repo.ListByApplicationID(context.Background(), appB.ID); err != nil {
		t.Fatalf("ListByApplicationID(appB) error = %v", err)
	}
	if len(clients) != 1 || clients[0].ClientID != "client-repo-app-b-web" {
		t.Errorf("ListByApplicationID(appB) = %v, want exactly [client-repo-app-b-web]", clients)
	}

	empty := seedApplication(t, tx, db.Application{Name: "Empty App"})
	if clients, err = repo.ListByApplicationID(context.Background(), empty.ID); err != nil {
		t.Fatalf("ListByApplicationID(empty app) error = %v", err)
	}
	if len(clients) != 0 {
		t.Errorf("ListByApplicationID(empty app) = %v, want no clients", clients)
	}
}
