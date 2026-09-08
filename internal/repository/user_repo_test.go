package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
)

func TestUserRepo_GetByEmail(t *testing.T) {
	const seededEmail = "user-repo-test@example.com"

	tests := []struct {
		name    string
		email   string
		wantErr error
	}{
		{"existing user", seededEmail, nil},
		{"nonexistent user", "no-such-user@example.com", ErrNotFound},
		{"case-insensitive email match", "USER-REPO-TEST@example.com", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := newTestTx(t)
			seedUser(t, tx, db.User{Subject: "user-repo-test-subject", Email: seededEmail})
			repo := NewGormUserRepo(tx)

			user, err := repo.GetByEmail(context.Background(), tt.email)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByEmail(%q) error = %v, want %v", tt.email, err, tt.wantErr)
			}
			if err == nil && user.Email != seededEmail {
				t.Errorf("GetByEmail(%q) returned email %q, want %q", tt.email, user.Email, seededEmail)
			}
		})
	}
}

func TestUserRepo_GetByID(t *testing.T) {
	tests := []struct {
		name    string
		bogusID bool
		wantErr error
	}{
		{"existing user", false, nil},
		{"nonexistent user", true, ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := newTestTx(t)
			user := seedUser(t, tx, db.User{Subject: "user-repo-by-id-subject", Email: "user-repo-by-id@example.com"})
			repo := NewGormUserRepo(tx)

			id := user.ID
			if tt.bogusID {
				id = user.ID + 1000
			}

			got, err := repo.GetByID(context.Background(), id)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByID(%d) error = %v, want %v", id, err, tt.wantErr)
			}
			if err == nil && got.ID != user.ID {
				t.Errorf("GetByID(%d) returned ID %d, want %d", id, got.ID, user.ID)
			}
		})
	}
}

func TestUserRepo_Create(t *testing.T) {
	tx := newTestTx(t)
	repo := NewGormUserRepo(tx)

	user, err := repo.Create(context.Background(), &db.User{
		Subject: "user-repo-create-subject",
		Email:   "user-repo-create@example.com",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if user.ID == 0 {
		t.Error("Create() did not backfill ID")
	}
	if user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() {
		t.Error("Create() did not set timestamps")
	}

	fetched, err := repo.GetByEmail(context.Background(), "user-repo-create@example.com")
	if err != nil {
		t.Fatalf("GetByEmail() after Create() error = %v", err)
	}
	if fetched.ID != user.ID {
		t.Errorf("GetByEmail() returned ID %d, want %d", fetched.ID, user.ID)
	}

	_, err = repo.Create(context.Background(), &db.User{
		Subject: "user-repo-create-dup-subject",
		Email:   "user-repo-create@example.com",
	})
	if err == nil {
		t.Error("Create() with duplicate email: want error, got nil")
	}
}
