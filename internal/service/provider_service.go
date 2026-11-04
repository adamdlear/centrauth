package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/secrets"
	"github.com/adamdlear/centrauth/internal/upstream"
)

type ProviderInput struct {
	Provider     string
	ClientID     string
	ClientSecret string
	Enabled      bool
}

// ProviderService manages per-app identity provider configuration and
// provisions local users from upstream identities.
type ProviderService struct {
	providers  repository.IdentityProviderRepository
	users      repository.UserRepository
	identities repository.UserIdentityRepository
	box        *secrets.Box
}

func NewProviderService(
	providers repository.IdentityProviderRepository,
	users repository.UserRepository,
	identities repository.UserIdentityRepository,
	box *secrets.Box,
) *ProviderService {
	return &ProviderService{
		providers:  providers,
		users:      users,
		identities: identities,
		box:        box,
	}
}

func (s *ProviderService) Upsert(ctx context.Context, applicationID int64, input ProviderInput) error {
	verr := newValidationError()

	provider := strings.ToLower(strings.TrimSpace(input.Provider))
	if !upstream.IsSupported(provider) {
		verr.add("provider", "Provider must be google or github")
	}

	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" {
		verr.add("client_id", "Client ID is required")
	}

	existing, err := s.providers.GetByApplicationAndProvider(ctx, applicationID, provider)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	existed := err == nil

	var encrypted []byte
	switch {
	case strings.TrimSpace(input.ClientSecret) != "":
		encrypted, err = s.box.Encrypt([]byte(input.ClientSecret))
		if err != nil {
			return fmt.Errorf("encrypt provider secret: %w", err)
		}
	case existed:
		encrypted = existing.ClientSecretEncrypted
	default:
		verr.add("client_secret", "Client secret is required")
	}

	if !verr.empty() {
		return verr
	}

	_, err = s.providers.Upsert(ctx, &db.IdentityProvider{
		ApplicationID:         applicationID,
		Provider:              provider,
		ClientID:              clientID,
		ClientSecretEncrypted: encrypted,
		Enabled:               input.Enabled,
	})
	if err != nil {
		return fmt.Errorf("save identity provider: %w", err)
	}
	return nil
}

// Get returns the provider configuration with its decrypted client secret.
func (s *ProviderService) Get(ctx context.Context, applicationID int64, provider string) (db.IdentityProvider, string, error) {
	record, err := s.providers.GetByApplicationAndProvider(ctx, applicationID, provider)
	if err != nil {
		return db.IdentityProvider{}, "", err
	}
	secret, err := s.box.Decrypt(record.ClientSecretEncrypted)
	if err != nil {
		return db.IdentityProvider{}, "", fmt.Errorf("decrypt provider secret: %w", err)
	}
	return record, string(secret), nil
}

func (s *ProviderService) List(ctx context.Context, applicationID int64) ([]db.IdentityProvider, error) {
	return s.providers.ListByApplicationID(ctx, applicationID)
}

func (s *ProviderService) SetEnabled(ctx context.Context, applicationID int64, provider string, enabled bool) error {
	return s.providers.SetEnabled(ctx, applicationID, provider, enabled)
}

func (s *ProviderService) Delete(ctx context.Context, applicationID int64, provider string) error {
	return s.providers.Delete(ctx, applicationID, provider)
}

// ProvisionUser resolves an upstream identity to a local user. Linking is
// conservative: an existing identity always wins, and email-based linking only
// happens when the provider says the email is verified. Unverified emails are
// never written to users.email, which prevents an attacker from pre-claiming an
// address and later being linked to the victim's verified identity.
func (s *ProviderService) ProvisionUser(ctx context.Context, identity upstream.Identity) (db.User, error) {
	existingIdentity, err := s.identities.GetByProviderSubject(ctx, identity.Provider, identity.Subject)
	switch {
	case err == nil:
		return s.users.GetByID(ctx, existingIdentity.UserID)
	case !errors.Is(err, repository.ErrNotFound):
		return db.User{}, err
	}

	verifiedEmail := ""
	if identity.EmailVerified {
		verifiedEmail = strings.TrimSpace(identity.Email)
	}

	if verifiedEmail != "" {
		existingUser, err := s.users.GetByEmail(ctx, verifiedEmail)
		switch {
		case err == nil:
			record := &db.UserIdentity{
				UserID:          existingUser.ID,
				Provider:        identity.Provider,
				ProviderSubject: identity.Subject,
				Email:           verifiedEmail,
				EmailVerified:   true,
				Name:            identity.Name,
			}
			if _, err := s.identities.Create(ctx, record); err != nil {
				return db.User{}, fmt.Errorf("link identity: %w", err)
			}
			return existingUser, nil
		case !errors.Is(err, repository.ErrNotFound):
			return db.User{}, err
		}
	}

	email := verifiedEmail
	if email == "" {
		email = syntheticEmail(identity)
	}

	subject, err := randomSubject()
	if err != nil {
		return db.User{}, err
	}

	user := &db.User{Subject: subject, Email: email}
	record := &db.UserIdentity{
		Provider:        identity.Provider,
		ProviderSubject: identity.Subject,
		Email:           identity.Email,
		EmailVerified:   identity.EmailVerified,
		Name:            identity.Name,
	}
	if err := s.identities.CreateWithUser(ctx, user, record); err != nil {
		return db.User{}, fmt.Errorf("create user from provider identity: %w", err)
	}
	return *user, nil
}

func syntheticEmail(identity upstream.Identity) string {
	suffix := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, identity.Subject)
	return fmt.Sprintf("%s-%s@users.centrauth.invalid", identity.Provider, suffix)
}

func randomSubject() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
