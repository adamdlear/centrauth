package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
)

func TestCredentialRepo_GetByUserIDAndMethod(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		bogusUser bool
		wantErr   error
	}{
		{"existing credential", "password", false, nil},
		{"wrong method", "webauthn", false, ErrNotFound},
		{"wrong user", "password", true, ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := newTestTx(t)
			user := seedUser(t, tx, db.User{Subject: "cred-repo-test-subject", Email: "cred-repo-test@example.com"})
			hash := "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
			seedCredential(t, tx, db.UserCredential{UserID: user.ID, Method: "password", PasswordHash: &hash})
			repo := NewGormCredentialRepo(tx)

			userID := user.ID
			if tt.bogusUser {
				userID = user.ID + 1000
			}

			cred, err := repo.GetByUserIDAndMethod(context.Background(), userID, tt.method)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByUserIDAndMethod(%d, %q) error = %v, want %v", userID, tt.method, err, tt.wantErr)
			}
			if err == nil && cred.UserID != user.ID {
				t.Errorf("GetByUserIDAndMethod() returned userID %d, want %d", cred.UserID, user.ID)
			}
		})
	}
}

func TestCredentialRepo_Create(t *testing.T) {
	tx := newTestTx(t)
	user := seedUser(t, tx, db.User{Subject: "cred-repo-create-subject", Email: "cred-repo-create@example.com"})
	repo := NewGormCredentialRepo(tx)

	hash := "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
	cred, err := repo.Create(context.Background(), &db.UserCredential{
		UserID:       user.ID,
		Method:       "password",
		PasswordHash: &hash,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if cred.ID == 0 {
		t.Error("Create() did not backfill ID")
	}
	if cred.PasswordHash == nil || *cred.PasswordHash != hash {
		t.Error("Create() lost the password hash")
	}

	_, err = repo.Create(context.Background(), &db.UserCredential{
		UserID:       user.ID,
		Method:       "password",
		PasswordHash: &hash,
	})
	if err == nil {
		t.Error("Create() with duplicate (user_id, method): want error, got nil")
	}
}
