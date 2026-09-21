package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
)

func TestOperatorSessionRepo_CreateAndGetByTokenHash(t *testing.T) {
	tx := newTestTx(t)
	operator := seedOperator(t, tx, db.Operator{Email: "operator-session-repo-test@example.com", PasswordHash: "hash"})
	repo := NewGormOperatorSessionRepo(tx)

	created, err := repo.Create(context.Background(), &db.OperatorSession{
		TokenHash:  []byte("operator-session-repo-test-token-hash"),
		OperatorID: operator.ID,
		ExpiresAt:  time.Now().Add(time.Hour).Truncate(time.Microsecond),
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
		{"existing session", []byte("operator-session-repo-test-token-hash"), nil},
		{"unknown token hash", []byte("operator-session-repo-no-such-hash"), ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := repo.GetByTokenHash(context.Background(), tt.tokenHash)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByTokenHash(%q) error = %v, want %v", tt.tokenHash, err, tt.wantErr)
			}
			if err == nil && session.OperatorID != operator.ID {
				t.Errorf("GetByTokenHash() returned operatorID %d, want %d", session.OperatorID, operator.ID)
			}
		})
	}
}

func TestOperatorSessionRepo_Revoke(t *testing.T) {
	tx := newTestTx(t)
	operator := seedOperator(t, tx, db.Operator{Email: "operator-session-repo-revoke@example.com", PasswordHash: "hash"})
	expires := time.Now().Add(time.Hour)
	target := seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-revoke-target"), OperatorID: operator.ID, ExpiresAt: expires})
	other := seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-revoke-other"), OperatorID: operator.ID, ExpiresAt: expires})
	repo := NewGormOperatorSessionRepo(tx)

	if err := repo.Revoke(context.Background(), target.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	got, err := repo.GetByTokenHash(context.Background(), []byte("operator-session-repo-revoke-target"))
	if err != nil {
		t.Fatalf("GetByTokenHash() after Revoke() error = %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("Revoke() did not set RevokedAt on the target session")
	}

	got, err = repo.GetByTokenHash(context.Background(), []byte("operator-session-repo-revoke-other"))
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

func TestOperatorSessionRepo_DeleteInactive(t *testing.T) {
	tx := newTestTx(t)
	operator := seedOperator(t, tx, db.Operator{Email: "operator-session-repo-delete@example.com", PasswordHash: "hash"})
	future := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	past := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	revokedAt := time.Now().Add(-time.Minute).Truncate(time.Microsecond)

	seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-delete-active"), OperatorID: operator.ID, ExpiresAt: future})
	seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-delete-expired"), OperatorID: operator.ID, ExpiresAt: past})
	seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-delete-revoked"), OperatorID: operator.ID, ExpiresAt: future, RevokedAt: &revokedAt})
	seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-delete-revoked-expired"), OperatorID: operator.ID, ExpiresAt: past, RevokedAt: &revokedAt})
	repo := NewGormOperatorSessionRepo(tx)

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
		{"active session kept", []byte("operator-session-repo-delete-active"), nil},
		{"expired session deleted", []byte("operator-session-repo-delete-expired"), ErrNotFound},
		{"revoked session deleted", []byte("operator-session-repo-delete-revoked"), ErrNotFound},
		{"revoked and expired session deleted", []byte("operator-session-repo-delete-revoked-expired"), ErrNotFound},
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

func TestOperatorSessionRepo_RevokeAllForOperator(t *testing.T) {
	tx := newTestTx(t)
	operatorA := seedOperator(t, tx, db.Operator{Email: "operator-session-repo-a@example.com", PasswordHash: "hash"})
	operatorB := seedOperator(t, tx, db.Operator{Email: "operator-session-repo-b@example.com", PasswordHash: "hash"})
	expires := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour).Truncate(time.Microsecond)

	seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-a-active-1"), OperatorID: operatorA.ID, ExpiresAt: expires})
	seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-a-active-2"), OperatorID: operatorA.ID, ExpiresAt: expires})
	seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-a-revoked"), OperatorID: operatorA.ID, ExpiresAt: expires, RevokedAt: &past})
	seedOperatorSession(t, tx, db.OperatorSession{TokenHash: []byte("operator-session-repo-b-active"), OperatorID: operatorB.ID, ExpiresAt: expires})
	repo := NewGormOperatorSessionRepo(tx)

	if err := repo.RevokeAllForOperator(context.Background(), operatorA.ID); err != nil {
		t.Fatalf("RevokeAllForOperator() error = %v", err)
	}

	for _, tt := range []struct {
		tokenHash   []byte
		wantRevoked bool
		wantSameAt  bool
	}{
		{[]byte("operator-session-repo-a-active-1"), true, false},
		{[]byte("operator-session-repo-a-active-2"), true, false},
		{[]byte("operator-session-repo-a-revoked"), true, true},
		{[]byte("operator-session-repo-b-active"), false, false},
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
