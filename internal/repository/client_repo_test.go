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
			seedClient(t, tx, db.OAuthClient{
				ClientID:     seededClientID,
				ClientType:   "confidential",
				RedirectURIs: pq.StringArray{"https://example.com/callback"},
			})
			repo := NewGormClientRepo(tx)

			client, err := repo.GetByClientID(context.Background(), tt.clientID)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByClientID(%q) error = %v, want %v", tt.clientID, err, tt.wantErr)
			}
			if err == nil && client.ClientID != seededClientID {
				t.Errorf("GetByClientID(%q) returned clientID %q, want %q", tt.clientID, client.ClientID, seededClientID)
			}
		})
	}
}

func TestClientRepo_Create(t *testing.T) {
	tx := newTestTx(t)
	repo := NewGormClientRepo(tx)

	client, err := repo.Create(context.Background(), &db.OAuthClient{
		ClientID:     "client-repo-create",
		ClientType:   "public",
		RedirectURIs: pq.StringArray{"https://example.com/callback"},
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
	if len(fetched.RedirectURIs) != 1 || fetched.RedirectURIs[0] != "https://example.com/callback" {
		t.Errorf("GetByClientID() returned redirect URIs %v, want [https://example.com/callback]", fetched.RedirectURIs)
	}

	_, err = repo.Create(context.Background(), &db.OAuthClient{
		ClientID:     "client-repo-create",
		ClientType:   "confidential",
		RedirectURIs: pq.StringArray{},
	})
	if err == nil {
		t.Error("Create() with duplicate client_id: want error, got nil")
	}
}
