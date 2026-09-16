package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
	pq "github.com/lib/pq"
)

func TestApplicationRepo_Create(t *testing.T) {
	tx := newTestTx(t)
	repo := NewGormApplicationRepo(tx)

	app, err := repo.Create(context.Background(), &db.Application{
		Name:          "Todo",
		Description:   "A todo app",
		FirstParty:    true,
		AllowedScopes: pq.StringArray{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if app.ID == 0 {
		t.Error("Create() did not backfill ID")
	}

	fetched, err := repo.GetByID(context.Background(), app.ID)
	if err != nil {
		t.Fatalf("GetByID() after Create() error = %v", err)
	}
	if fetched.Name != "Todo" {
		t.Errorf("Name = %q, want %q", fetched.Name, "Todo")
	}
	if fetched.Description != "A todo app" {
		t.Errorf("Description = %q, want %q", fetched.Description, "A todo app")
	}
	if !fetched.FirstParty {
		t.Error("FirstParty = false, want true")
	}
	if len(fetched.AllowedScopes) != 2 || fetched.AllowedScopes[0] != "openid" || fetched.AllowedScopes[1] != "profile" {
		t.Errorf("AllowedScopes = %v, want [openid profile]", fetched.AllowedScopes)
	}
}

func TestApplicationRepo_GetByID(t *testing.T) {
	tx := newTestTx(t)
	seeded := seedApplication(t, tx, db.Application{Name: "Get By ID App"})
	repo := NewGormApplicationRepo(tx)

	tests := []struct {
		name    string
		id      int64
		wantErr error
	}{
		{"existing app", seeded.ID, nil},
		{"nonexistent app", seeded.ID + 1_000_000, ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, err := repo.GetByID(context.Background(), tt.id)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByID(%d) error = %v, want %v", tt.id, err, tt.wantErr)
			}
			if err == nil && app.ID != seeded.ID {
				t.Errorf("GetByID(%d) returned ID %d, want %d", tt.id, app.ID, seeded.ID)
			}
		})
	}
}

func TestApplicationRepo_Update(t *testing.T) {
	tx := newTestTx(t)
	repo := NewGormApplicationRepo(tx)

	seeded := seedApplication(t, tx, db.Application{
		Name:          "Original Name",
		Description:   "original description",
		FirstParty:    true,
		AllowedScopes: pq.StringArray{"openid", "profile"},
	})

	updated := seeded
	updated.Name = "Updated Name"
	updated.Description = ""
	updated.FirstParty = false
	updated.AllowedScopes = pq.StringArray{"openid"}

	if _, err := repo.Update(context.Background(), &updated); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	fetched, err := repo.GetByID(context.Background(), seeded.ID)
	if err != nil {
		t.Fatalf("GetByID() after Update() error = %v", err)
	}
	if fetched.Name != "Updated Name" {
		t.Errorf("Name = %q, want %q", fetched.Name, "Updated Name")
	}
	if fetched.Description != "" {
		t.Errorf("Description = %q, want cleared to empty string", fetched.Description)
	}
	if fetched.FirstParty {
		t.Error("FirstParty = true, want false")
	}
	if len(fetched.AllowedScopes) != 1 || fetched.AllowedScopes[0] != "openid" {
		t.Errorf("AllowedScopes = %v, want [openid]", fetched.AllowedScopes)
	}
	if fetched.ID != seeded.ID {
		t.Errorf("ID = %d, want unchanged %d", fetched.ID, seeded.ID)
	}

	missing := db.Application{
		ID:   seeded.ID + 1_000_000,
		Name: "Missing App",
	}
	if _, err := repo.Update(context.Background(), &missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update() with nonexistent ID error = %v, want ErrNotFound", err)
	}
}

func TestApplicationRepo_List(t *testing.T) {
	tx := newTestTx(t)
	repo := NewGormApplicationRepo(tx)

	seedApplication(t, tx, db.Application{Name: "List App A"})
	seedApplication(t, tx, db.Application{Name: "List App B"})

	apps, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	found := map[string]bool{}
	for _, a := range apps {
		found[a.Name] = true
	}
	for _, want := range []string{"List App A", "List App B"} {
		if !found[want] {
			t.Errorf("List() missing seeded app %q", want)
		}
	}
}

func TestApplicationRepo_GetWithClients(t *testing.T) {
	tx := newTestTx(t)
	repo := NewGormApplicationRepo(tx)

	parent := seedApplication(t, tx, db.Application{
		Name:          "Parent App",
		Description:   "has clients",
		FirstParty:    true,
		AllowedScopes: pq.StringArray{"openid"},
	})
	other := seedApplication(t, tx, db.Application{Name: "Other App"})

	seedClient(t, tx, db.OAuthClient{
		ApplicationID: parent.ID,
		ClientID:      "app-repo-parent-web",
		ClientType:    "confidential",
		RedirectURIs:  pq.StringArray{"https://parent.example.com/callback"},
	})
	seedClient(t, tx, db.OAuthClient{
		ApplicationID: parent.ID,
		ClientID:      "app-repo-parent-mobile",
		ClientType:    "public",
		RedirectURIs:  pq.StringArray{},
	})
	seedClient(t, tx, db.OAuthClient{
		ApplicationID: other.ID,
		ClientID:      "app-repo-other-web",
		ClientType:    "confidential",
		RedirectURIs:  pq.StringArray{},
	})

	app, clients, err := repo.GetWithClients(context.Background(), parent.ID)
	if err != nil {
		t.Fatalf("GetWithClients(parent) error = %v", err)
	}
	if app.Name != "Parent App" {
		t.Errorf("GetWithClients(parent) returned app name %q, want %q", app.Name, "Parent App")
	}

	found := map[string]bool{}
	for _, c := range clients {
		found[c.ClientID] = true
	}
	if !found["app-repo-parent-web"] || !found["app-repo-parent-mobile"] {
		t.Errorf("GetWithClients(parent) missing parent's clients, found %v", found)
	}
	if found["app-repo-other-web"] {
		t.Error("GetWithClients(parent) returned a client belonging to another app")
	}

	if _, _, err = repo.GetWithClients(context.Background(), parent.ID+1_000_000); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetWithClients(nonexistent) error = %v, want ErrNotFound", err)
	}

	empty := seedApplication(t, tx, db.Application{Name: "Clientless App"})
	if _, clients, err = repo.GetWithClients(context.Background(), empty.ID); err != nil {
		t.Fatalf("GetWithClients(clientless app) error = %v", err)
	}
	if len(clients) != 0 {
		t.Errorf("GetWithClients(clientless app) = %v clients, want none", clients)
	}
}
