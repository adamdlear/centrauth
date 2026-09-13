package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
)

func TestSessionRepo_CreateAndGetByTokenHash(t *testing.T) {
	tx := newTestTx(t)
	user := seedUser(t, tx, db.User{Subject: "session-repo-test-subject", Email: "session-repo-test@example.com"})
	repo := NewGormSessionRepo(tx)

	created, err := repo.Create(context.Background(), &db.Session{
		TokenHash: []byte("session-repo-test-token-hash"),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Microsecond),
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID == 0 {
		t.Error("Create() did not backfill ID")
	}

	tests := []struct {
		name      string
		tokenHash []byte
		wantErr   error
	}{
		{"existing session", []byte("session-repo-test-token-hash"), nil},
		{"unknown token hash", []byte("session-repo-no-such-hash"), ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := repo.GetByTokenHash(context.Background(), tt.tokenHash)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByTokenHash(%q) error = %v, want %v", tt.tokenHash, err, tt.wantErr)
			}
			if err == nil && session.UserID != user.ID {
				t.Errorf("GetByTokenHash() returned userID %d, want %d", session.UserID, user.ID)
			}
		})
	}
}

func TestSessionRepo_Revoke(t *testing.T) {
	tx := newTestTx(t)
	user := seedUser(t, tx, db.User{Subject: "session-repo-revoke-subject", Email: "session-repo-revoke@example.com"})
	expires := time.Now().Add(time.Hour)
	target := seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-revoke-target"), UserID: user.ID, ExpiresAt: expires})
	other := seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-revoke-other"), UserID: user.ID, ExpiresAt: expires})
	repo := NewGormSessionRepo(tx)

	if err := repo.Revoke(context.Background(), target.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	got, err := repo.GetByTokenHash(context.Background(), []byte("session-repo-revoke-target"))
	if err != nil {
		t.Fatalf("GetByTokenHash() after Revoke() error = %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("Revoke() did not set RevokedAt on the target session")
	}

	got, err = repo.GetByTokenHash(context.Background(), []byte("session-repo-revoke-other"))
	if err != nil {
		t.Fatalf("GetByTokenHash() error = %v", err)
	}
	if got.RevokedAt != nil {
		t.Error("Revoke() set RevokedAt on an unrelated session")
	}

	if err := repo.Revoke(context.Background(), other.ID+1000); !errors.Is(err, ErrNotFound) {
		t.Errorf("Revoke() on nonexistent ID: error = %v, want %v", err, ErrNotFound)
	}
}

func TestSessionRepo_DeleteInactive(t *testing.T) {
	tx := newTestTx(t)
	user := seedUser(t, tx, db.User{Subject: "session-repo-delete-subject", Email: "session-repo-delete@example.com"})
	future := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	past := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	revokedAt := time.Now().Add(-time.Minute).Truncate(time.Microsecond)

	seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-delete-active"), UserID: user.ID, ExpiresAt: future})
	seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-delete-expired"), UserID: user.ID, ExpiresAt: past})
	seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-delete-revoked"), UserID: user.ID, ExpiresAt: future, RevokedAt: &revokedAt})
	seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-delete-revoked-expired"), UserID: user.ID, ExpiresAt: past, RevokedAt: &revokedAt})
	repo := NewGormSessionRepo(tx)

	deleted, err := repo.DeleteInactive(context.Background())
	if err != nil {
		t.Fatalf("DeleteInactive() error = %v", err)
	}
	if deleted != 3 {
		t.Errorf("DeleteInactive() deleted %d sessions, want 3", deleted)
	}

	tests := []struct {
		name      string
		tokenHash []byte
		wantErr   error
	}{
		{"active session kept", []byte("session-repo-delete-active"), nil},
		{"expired session deleted", []byte("session-repo-delete-expired"), ErrNotFound},
		{"revoked session deleted", []byte("session-repo-delete-revoked"), ErrNotFound},
		{"revoked and expired session deleted", []byte("session-repo-delete-revoked-expired"), ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := repo.GetByTokenHash(context.Background(), tt.tokenHash)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByTokenHash(%q) after DeleteInactive() error = %v, want %v", tt.tokenHash, err, tt.wantErr)
			}
			if err == nil && session.RevokedAt != nil {
				t.Errorf("surviving session %q has RevokedAt set", tt.tokenHash)
			}
		})
	}
}

func TestSessionRepo_RevokeAllForUser(t *testing.T) {
	tx := newTestTx(t)
	userA := seedUser(t, tx, db.User{Subject: "session-repo-user-a", Email: "session-repo-a@example.com"})
	userB := seedUser(t, tx, db.User{Subject: "session-repo-user-b", Email: "session-repo-b@example.com"})
	expires := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour).Truncate(time.Microsecond)

	seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-a-active-1"), UserID: userA.ID, ExpiresAt: expires})
	seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-a-active-2"), UserID: userA.ID, ExpiresAt: expires})
	seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-a-revoked"), UserID: userA.ID, ExpiresAt: expires, RevokedAt: &past})
	seedSession(t, tx, db.Session{TokenHash: []byte("session-repo-b-active"), UserID: userB.ID, ExpiresAt: expires})
	repo := NewGormSessionRepo(tx)

	if err := repo.RevokeAllForUser(context.Background(), userA.ID); err != nil {
		t.Fatalf("RevokeAllForUser() error = %v", err)
	}

	for _, tt := range []struct {
		tokenHash   []byte
		wantRevoked bool
		wantSameAt  bool
	}{
		{[]byte("session-repo-a-active-1"), true, false},
		{[]byte("session-repo-a-active-2"), true, false},
		{[]byte("session-repo-a-revoked"), true, true},
		{[]byte("session-repo-b-active"), false, false},
	} {
		got, err := repo.GetByTokenHash(context.Background(), tt.tokenHash)
		if err != nil {
			t.Fatalf("GetByTokenHash(%q) error = %v", tt.tokenHash, err)
		}
		if (got.RevokedAt != nil) != tt.wantRevoked {
			t.Errorf("session %q revoked = %v, want %v", tt.tokenHash, got.RevokedAt != nil, tt.wantRevoked)
			continue
		}
		if tt.wantSameAt && !got.RevokedAt.Equal(past) {
			t.Errorf("session %q RevokedAt = %v, want original %v", tt.tokenHash, got.RevokedAt, past)
		}
	}
}
