package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/secrets"
	"github.com/adamdlear/centrauth/internal/upstream"
)

type fakeUsers struct {
	users   map[int64]db.User
	byEmail map[string]db.User
	nextID  int64
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{users: map[int64]db.User{}, byEmail: map[string]db.User{}}
}

func (f *fakeUsers) GetByEmail(_ context.Context, email string) (db.User, error) {
	if u, ok := f.byEmail[strings.ToLower(email)]; ok {
		return u, nil
	}
	return db.User{}, repository.ErrNotFound
}

func (f *fakeUsers) GetByID(_ context.Context, id int64) (db.User, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return db.User{}, repository.ErrNotFound
}

func (f *fakeUsers) Create(_ context.Context, u *db.User) (db.User, error) {
	f.nextID++
	u.ID = f.nextID
	f.users[u.ID] = *u
	f.byEmail[strings.ToLower(u.Email)] = *u
	return *u, nil
}

type fakeIdentityProviders struct {
	providers []db.IdentityProvider
	nextID    int64
}

func (f *fakeIdentityProviders) ListByApplicationID(_ context.Context, applicationID int64) ([]db.IdentityProvider, error) {
	var out []db.IdentityProvider
	for _, p := range f.providers {
		if p.ApplicationID == applicationID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeIdentityProviders) GetByApplicationAndProvider(_ context.Context, applicationID int64, provider string) (db.IdentityProvider, error) {
	for _, p := range f.providers {
		if p.ApplicationID == applicationID && p.Provider == provider {
			return p, nil
		}
	}
	return db.IdentityProvider{}, repository.ErrNotFound
}

func (f *fakeIdentityProviders) Upsert(_ context.Context, provider *db.IdentityProvider) (db.IdentityProvider, error) {
	for i := range f.providers {
		if f.providers[i].ApplicationID == provider.ApplicationID && f.providers[i].Provider == provider.Provider {
			provider.ID = f.providers[i].ID
			f.providers[i] = *provider
			return *provider, nil
		}
	}
	f.nextID++
	provider.ID = f.nextID
	f.providers = append(f.providers, *provider)
	return *provider, nil
}

func (f *fakeIdentityProviders) SetEnabled(_ context.Context, applicationID int64, provider string, enabled bool) error {
	for i := range f.providers {
		if f.providers[i].ApplicationID == applicationID && f.providers[i].Provider == provider {
			f.providers[i].Enabled = enabled
			return nil
		}
	}
	return repository.ErrNotFound
}

func (f *fakeIdentityProviders) Delete(_ context.Context, applicationID int64, provider string) error {
	for i := range f.providers {
		if f.providers[i].ApplicationID == applicationID && f.providers[i].Provider == provider {
			f.providers = append(f.providers[:i], f.providers[i+1:]...)
			return nil
		}
	}
	return repository.ErrNotFound
}

type fakeIdentities struct {
	identities []db.UserIdentity
	users      *fakeUsers
	nextID     int64
}

func (f *fakeIdentities) GetByProviderSubject(_ context.Context, provider, subject string) (db.UserIdentity, error) {
	for _, identity := range f.identities {
		if identity.Provider == provider && identity.ProviderSubject == subject {
			return identity, nil
		}
	}
	return db.UserIdentity{}, repository.ErrNotFound
}

func (f *fakeIdentities) ListByUserID(_ context.Context, userID int64) ([]db.UserIdentity, error) {
	var out []db.UserIdentity
	for _, identity := range f.identities {
		if identity.UserID == userID {
			out = append(out, identity)
		}
	}
	return out, nil
}

func (f *fakeIdentities) Create(_ context.Context, identity *db.UserIdentity) (db.UserIdentity, error) {
	f.nextID++
	identity.ID = f.nextID
	f.identities = append(f.identities, *identity)
	return *identity, nil
}

func (f *fakeIdentities) CreateWithUser(ctx context.Context, user *db.User, identity *db.UserIdentity) error {
	if f.users != nil {
		if _, err := f.users.Create(ctx, user); err != nil {
			return err
		}
	}
	if user.ID == 0 {
		user.ID = int64(len(f.identities) + 1)
	}
	identity.UserID = user.ID
	_, err := f.Create(ctx, identity)
	return err
}

func newProviderService(t *testing.T) (*ProviderService, *fakeIdentityProviders, *fakeIdentities, *fakeUsers) {
	t.Helper()
	box, err := secrets.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewBox() error = %v", err)
	}
	providers := &fakeIdentityProviders{}
	identities := &fakeIdentities{}
	users := newFakeUsers()
	identities.users = users
	return NewProviderService(providers, users, identities, box), providers, identities, users
}

func TestProviderService_UpsertEncryptsSecret(t *testing.T) {
	svc, providers, _, _ := newProviderService(t)

	if err := svc.Upsert(context.Background(), 1, ProviderInput{
		Provider:     "google",
		ClientID:     "google-client",
		ClientSecret: "super-secret",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	if len(providers.providers) != 1 {
		t.Fatalf("stored %d providers, want 1", len(providers.providers))
	}
	record := providers.providers[0]
	if strings.Contains(string(record.ClientSecretEncrypted), "super-secret") {
		t.Fatal("stored provider secret contains plaintext")
	}

	got, secret, err := svc.Get(context.Background(), 1, "google")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ClientID != "google-client" || secret != "super-secret" {
		t.Errorf("Get() = %+v secret=%q", got, secret)
	}
}

func TestProviderService_UpsertKeepsSecretWhenBlank(t *testing.T) {
	svc, providers, _, _ := newProviderService(t)

	if err := svc.Upsert(context.Background(), 1, ProviderInput{Provider: "github", ClientID: "first", ClientSecret: "secret", Enabled: true}); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	if err := svc.Upsert(context.Background(), 1, ProviderInput{Provider: "github", ClientID: "second", ClientSecret: "", Enabled: false}); err != nil {
		t.Fatalf("Upsert() with blank secret error = %v", err)
	}

	_, secret, err := svc.Get(context.Background(), 1, "github")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if secret != "secret" {
		t.Errorf("secret = %q, want preserved", secret)
	}
	if providers.providers[0].ClientID != "second" || providers.providers[0].Enabled {
		t.Errorf("updated provider = %+v", providers.providers[0])
	}
}

func TestProviderService_Validation(t *testing.T) {
	tests := []struct {
		name  string
		input ProviderInput
		field string
	}{
		{"unknown provider", ProviderInput{Provider: "okta", ClientID: "c", ClientSecret: "s"}, "provider"},
		{"missing client id", ProviderInput{Provider: "google", ClientID: "", ClientSecret: "s"}, "client_id"},
		{"missing secret on create", ProviderInput{Provider: "google", ClientID: "c", ClientSecret: ""}, "client_secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, _, _ := newProviderService(t)
			err := svc.Upsert(context.Background(), 1, tt.input)
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("Upsert() error = %v, want *ValidationError", err)
			}
			if verr.Fields[tt.field] == "" {
				t.Errorf("fields = %v, want %q", verr.Fields, tt.field)
			}
		})
	}
}

func TestProvisionUser_ExistingIdentity(t *testing.T) {
	svc, _, identities, users := newProviderService(t)

	existing := db.User{ID: 5, Subject: "existing", Email: "existing@example.com"}
	users.users[5] = existing
	users.byEmail["existing@example.com"] = existing
	_, _ = identities.Create(context.Background(), &db.UserIdentity{UserID: 5, Provider: "google", ProviderSubject: "sub-1"})

	user, err := svc.ProvisionUser(context.Background(), upstream.Identity{
		Provider: "google", Subject: "sub-1", Email: "different@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("ProvisionUser() error = %v", err)
	}
	if user.ID != 5 {
		t.Errorf("user ID = %d, want existing 5", user.ID)
	}
	if len(identities.identities) != 1 {
		t.Errorf("identities = %d, want unchanged", len(identities.identities))
	}
}

func TestProvisionUser_LinksVerifiedEmail(t *testing.T) {
	svc, _, identities, users := newProviderService(t)

	existing := db.User{ID: 5, Subject: "existing", Email: "person@example.com"}
	users.users[5] = existing
	users.byEmail["person@example.com"] = existing

	user, err := svc.ProvisionUser(context.Background(), upstream.Identity{
		Provider: "google", Subject: "google-sub-1", Email: "person@example.com", EmailVerified: true, Name: "Person",
	})
	if err != nil {
		t.Fatalf("ProvisionUser() error = %v", err)
	}
	if user.ID != 5 {
		t.Errorf("user ID = %d, want linked existing 5", user.ID)
	}
	if len(identities.identities) != 1 || identities.identities[0].UserID != 5 {
		t.Errorf("identity = %+v, want linked to user 5", identities.identities)
	}
}

func TestProvisionUser_DoesNotLinkUnverifiedEmail(t *testing.T) {
	svc, _, identities, users := newProviderService(t)

	victim := db.User{ID: 5, Subject: "victim", Email: "victim@example.com"}
	users.users[5] = victim
	users.byEmail["victim@example.com"] = victim

	user, err := svc.ProvisionUser(context.Background(), upstream.Identity{
		Provider: "github", Subject: "attacker-sub-1", Email: "victim@example.com", EmailVerified: false,
	})
	if err != nil {
		t.Fatalf("ProvisionUser() error = %v", err)
	}
	if user.ID == 5 {
		t.Fatal("unverified email linked to an existing user")
	}
	if user.Email == "victim@example.com" {
		t.Error("unverified email was written to users.email")
	}
	if !strings.HasSuffix(user.Email, "@users.centrauth.invalid") {
		t.Errorf("synthetic email = %q", user.Email)
	}
	if len(identities.identities) != 1 || identities.identities[0].UserID != user.ID {
		t.Errorf("identity = %+v, want linked to the new user", identities.identities)
	}
}

func TestProvisionUser_CreatesUserWithVerifiedEmail(t *testing.T) {
	svc, _, identities, users := newProviderService(t)

	user, err := svc.ProvisionUser(context.Background(), upstream.Identity{
		Provider: "google", Subject: "new-sub", Email: "new@example.com", EmailVerified: true, Name: "New",
	})
	if err != nil {
		t.Fatalf("ProvisionUser() error = %v", err)
	}
	if user.Email != "new@example.com" {
		t.Errorf("email = %q", user.Email)
	}
	if user.Subject == "" {
		t.Error("subject is empty")
	}
	if len(users.users) != 1 || len(identities.identities) != 1 {
		t.Errorf("users/identities = %d/%d, want 1/1", len(users.users), len(identities.identities))
	}
}
