package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	pq "github.com/lib/pq"
	"gorm.io/gorm"
)

func seedCodePrereqs(t *testing.T, tx *gorm.DB) (db.User, db.OAuthClient) {
	t.Helper()
	user := seedUser(t, tx, db.User{Subject: "code-repo-test-subject", Email: "code-repo-test@example.com"})
	app := seedApplication(t, tx, db.Application{Name: "Code Repo Test App"})
	client := seedClient(t, tx, db.OAuthClient{
		ApplicationID: app.ID,
		ClientID:      "code-repo-test-client",
		ClientType:    "confidential",
		RedirectURIs:  pq.StringArray{"https://example.com/callback"},
	})
	return user, client
}

func TestCodeRepo_CreateAndGetByCodeHash(t *testing.T) {
	tx := newTestTx(t)
	user, client := seedCodePrereqs(t, tx)
	repo := NewGormCodeRepo(tx)

	created, err := repo.Create(context.Background(), &db.OAuthAuthorizationCode{
		CodeHash:      []byte("code-repo-test-hash"),
		OAuthClientID: client.ID,
		UserID:        user.ID,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID == 0 {
		t.Error("Create() did not backfill ID")
	}

	tests := []struct {
		name     string
		codeHash []byte
		wantErr  error
	}{
		{"existing code", []byte("code-repo-test-hash"), nil},
		{"unknown code hash", []byte("code-repo-no-such-hash"), ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := repo.GetByCodeHash(context.Background(), tt.codeHash)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByCodeHash(%q) error = %v, want %v", tt.codeHash, err, tt.wantErr)
			}
			if err == nil && code.UserID != user.ID {
				t.Errorf("GetByCodeHash() returned userID %d, want %d", code.UserID, user.ID)
			}
		})
	}
}

func TestCodeRepo_Consume(t *testing.T) {
	tx := newTestTx(t)
	user, client := seedCodePrereqs(t, tx)
	code := seedCode(t, tx, db.OAuthAuthorizationCode{
		CodeHash:      []byte("code-repo-consume-hash"),
		OAuthClientID: client.ID,
		UserID:        user.ID,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	})
	repo := NewGormCodeRepo(tx)

	if err := repo.Consume(context.Background(), code.ID); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}

	got, err := repo.GetByCodeHash(context.Background(), []byte("code-repo-consume-hash"))
	if err != nil {
		t.Fatalf("GetByCodeHash() after Consume() error = %v", err)
	}
	if got.ConsumedAt == nil {
		t.Error("Consume() did not set ConsumedAt")
	}

	if err := repo.Consume(context.Background(), code.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume() on already-consumed code: error = %v, want %v", err, ErrNotFound)
	}

	if err := repo.Consume(context.Background(), code.ID+1000); !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume() on nonexistent ID: error = %v, want %v", err, ErrNotFound)
	}
}
