package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
)

func TestUserIdentityRepo_CreateWithUser(t *testing.T) {
	tx := newTestTx(t)
	repo := NewGormUserIdentityRepo(tx)
	ctx := context.Background()

	user := &db.User{Subject: "identity-create-subject", Email: "identity-create@example.com"}
	identity := &db.UserIdentity{
		Provider:        "google",
		ProviderSubject: "google-subject-1",
		Email:           "identity-create@example.com",
		EmailVerified:   true,
		Name:            "Identity Person",
	}

	if err := repo.CreateWithUser(ctx, user, identity); err != nil {
		t.Fatalf("CreateWithUser() error = %v", err)
	}
	if user.ID == 0 || identity.ID == 0 {
		t.Fatalf("CreateWithUser() did not backfill IDs: user=%d identity=%d", user.ID, identity.ID)
	}
	if identity.UserID != user.ID {
		t.Errorf("identity UserID = %d, want %d", identity.UserID, user.ID)
	}

	got, err := repo.GetByProviderSubject(ctx, "google", "google-subject-1")
	if err != nil {
		t.Fatalf("GetByProviderSubject() error = %v", err)
	}
	if got.UserID != user.ID || !got.EmailVerified {
		t.Errorf("identity = %+v", got)
	}

	list, err := repo.ListByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListByUserID() error = %v", err)
	}
	if len(list) != 1 {
		t.Errorf("identities = %d, want 1", len(list))
	}

	if _, err := repo.GetByProviderSubject(ctx, "google", "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByProviderSubject(missing) error = %v, want ErrNotFound", err)
	}
}

func TestUserIdentityRepo_UniqueProviderSubject(t *testing.T) {
	tx := newTestTx(t)
	repo := NewGormUserIdentityRepo(tx)
	ctx := context.Background()

	first := seedUser(t, tx, db.User{Subject: "identity-unique-1", Email: "identity-unique-1@example.com"})
	second := seedUser(t, tx, db.User{Subject: "identity-unique-2", Email: "identity-unique-2@example.com"})

	if _, err := repo.Create(ctx, &db.UserIdentity{UserID: first.ID, Provider: "github", ProviderSubject: "same-subject"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := repo.Create(ctx, &db.UserIdentity{UserID: second.ID, Provider: "github", ProviderSubject: "same-subject"}); err == nil {
		t.Error("Create() with a duplicate provider subject succeeded")
	}
}
