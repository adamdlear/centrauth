package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
)

func TestIdentityProviderRepo_UpsertAndGet(t *testing.T) {
	tx := newTestTx(t)
	app := seedApplication(t, tx, db.Application{Name: "Provider Repo App"})
	repo := NewGormIdentityProviderRepo(tx)
	ctx := context.Background()

	created, err := repo.Upsert(ctx, &db.IdentityProvider{
		ApplicationID:         app.ID,
		Provider:              "google",
		ClientID:              "google-client",
		ClientSecretEncrypted: []byte("encrypted-1"),
		Enabled:               true,
	})
	if err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	if created.ID == 0 {
		t.Error("Upsert() did not backfill ID")
	}

	got, err := repo.GetByApplicationAndProvider(ctx, app.ID, "google")
	if err != nil {
		t.Fatalf("GetByApplicationAndProvider() error = %v", err)
	}
	if got.ClientID != "google-client" || !got.Enabled {
		t.Errorf("provider = %+v", got)
	}

	if _, err := repo.Upsert(ctx, &db.IdentityProvider{
		ApplicationID:         app.ID,
		Provider:              "google",
		ClientID:              "google-client-2",
		ClientSecretEncrypted: []byte("encrypted-2"),
		Enabled:               false,
	}); err != nil {
		t.Fatalf("Upsert() update error = %v", err)
	}

	got, err = repo.GetByApplicationAndProvider(ctx, app.ID, "google")
	if err != nil {
		t.Fatalf("GetByApplicationAndProvider() after update error = %v", err)
	}
	if got.ClientID != "google-client-2" || got.Enabled {
		t.Errorf("provider after update = %+v", got)
	}
	if string(got.ClientSecretEncrypted) != "encrypted-2" {
		t.Errorf("secret = %q, want encrypted-2", got.ClientSecretEncrypted)
	}

	if _, err := repo.GetByApplicationAndProvider(ctx, app.ID, "github"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByApplicationAndProvider(missing) error = %v, want ErrNotFound", err)
	}
}

func TestIdentityProviderRepo_ListSetEnabledDelete(t *testing.T) {
	tx := newTestTx(t)
	app := seedApplication(t, tx, db.Application{Name: "Provider List App"})
	repo := NewGormIdentityProviderRepo(tx)
	ctx := context.Background()

	for _, provider := range []string{"google", "github"} {
		if _, err := repo.Upsert(ctx, &db.IdentityProvider{
			ApplicationID: app.ID, Provider: provider, ClientID: provider + "-client",
			ClientSecretEncrypted: []byte("enc"), Enabled: true,
		}); err != nil {
			t.Fatalf("seed %s: %v", provider, err)
		}
	}

	providers, err := repo.ListByApplicationID(ctx, app.ID)
	if err != nil {
		t.Fatalf("ListByApplicationID() error = %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(providers))
	}

	if err := repo.SetEnabled(ctx, app.ID, "github", false); err != nil {
		t.Fatalf("SetEnabled() error = %v", err)
	}
	got, _ := repo.GetByApplicationAndProvider(ctx, app.ID, "github")
	if got.Enabled {
		t.Error("SetEnabled() did not disable the provider")
	}

	if err := repo.Delete(ctx, app.ID, "google"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repo.GetByApplicationAndProvider(ctx, app.ID, "google"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByApplicationAndProvider(deleted) error = %v, want ErrNotFound", err)
	}

	if err := repo.SetEnabled(ctx, app.ID, "missing", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetEnabled(missing) error = %v, want ErrNotFound", err)
	}
	if err := repo.Delete(ctx, app.ID, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(missing) error = %v, want ErrNotFound", err)
	}
}
