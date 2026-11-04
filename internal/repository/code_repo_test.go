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

	nonce := "nonce-123"
	created, err := repo.Create(context.Background(), &db.OAuthAuthorizationCode{
		CodeHash:            []byte("code-repo-test-hash"),
		OAuthClientID:       client.ID,
		UserID:              user.ID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		Nonce:               &nonce,
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID == 0 {
		t.Error("Create() did not backfill ID")
	}

	code, err := repo.GetByCodeHash(context.Background(), []byte("code-repo-test-hash"))
	if err != nil {
		t.Fatalf("GetByCodeHash() error = %v", err)
	}
	if code.UserID != user.ID {
		t.Errorf("GetByCodeHash() returned userID %d, want %d", code.UserID, user.ID)
	}
	if code.OAuthClientID != client.ID {
		t.Errorf("GetByCodeHash() returned clientID %d, want %d", code.OAuthClientID, client.ID)
	}
	if code.RedirectURI != "https://example.com/callback" {
		t.Errorf("RedirectURI = %q, want %q", code.RedirectURI, "https://example.com/callback")
	}
	if code.Scope != "openid profile" {
		t.Errorf("Scope = %q, want %q", code.Scope, "openid profile")
	}
	if code.Nonce == nil || *code.Nonce != nonce {
		t.Errorf("Nonce = %v, want %q", code.Nonce, nonce)
	}
	if code.CodeChallenge != "challenge-value" {
		t.Errorf("CodeChallenge = %q, want %q", code.CodeChallenge, "challenge-value")
	}
	if code.CodeChallengeMethod != "S256" {
		t.Errorf("CodeChallengeMethod = %q, want %q", code.CodeChallengeMethod, "S256")
	}
	if IsConsumed(&code) {
		t.Error("IsConsumed() = true for a fresh code, want false")
	}

	if _, err := repo.GetByCodeHash(context.Background(), []byte("code-repo-no-such-hash")); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByCodeHash() for unknown hash error = %v, want %v", err, ErrNotFound)
	}
}

func TestCodeRepo_NonceNullable(t *testing.T) {
	tx := newTestTx(t)
	user, client := seedCodePrereqs(t, tx)
	repo := NewGormCodeRepo(tx)

	if _, err := repo.Create(context.Background(), &db.OAuthAuthorizationCode{
		CodeHash:      []byte("code-repo-no-nonce-hash"),
		OAuthClientID: client.ID,
		UserID:        user.ID,
		RedirectURI:   "https://example.com/callback",
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	code, err := repo.GetByCodeHash(context.Background(), []byte("code-repo-no-nonce-hash"))
	if err != nil {
		t.Fatalf("GetByCodeHash() error = %v", err)
	}
	if code.Nonce != nil {
		t.Errorf("Nonce = %v, want nil", code.Nonce)
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
	if !IsConsumed(&got) {
		t.Error("IsConsumed() = false after Consume(), want true")
	}

	if err := repo.Consume(context.Background(), code.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume() on already-consumed code: error = %v, want %v", err, ErrNotFound)
	}

	if err := repo.Consume(context.Background(), code.ID+1000); !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume() on nonexistent ID: error = %v, want %v", err, ErrNotFound)
	}
}

func TestCodeRepo_ConsumeRejectsExpiredCode(t *testing.T) {
	tx := newTestTx(t)
	user, client := seedCodePrereqs(t, tx)
	code := seedCode(t, tx, db.OAuthAuthorizationCode{
		CodeHash:      []byte("code-repo-expired-hash"),
		OAuthClientID: client.ID,
		UserID:        user.ID,
		ExpiresAt:     time.Now().Add(-time.Minute),
	})
	repo := NewGormCodeRepo(tx)

	if err := repo.Consume(context.Background(), code.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume() on expired code: error = %v, want %v", err, ErrNotFound)
	}
}
