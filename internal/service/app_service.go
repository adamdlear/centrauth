package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/oauth"
	"github.com/adamdlear/centrauth/internal/repository"
	pq "github.com/lib/pq"
)

var (
	clientTypes  = []string{"confidential", "public"}
	environments = []string{"local", "staging", "production"}
)

// ValidationError carries per-field validation messages for re-rendering forms.
type ValidationError struct {
	Fields map[string]string
}

func (e *ValidationError) Error() string {
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %s", k, e.Fields[k]))
	}
	return "validation failed: " + strings.Join(parts, "; ")
}

func newValidationError() *ValidationError {
	return &ValidationError{Fields: map[string]string{}}
}

func (e *ValidationError) add(field, message string) {
	if _, exists := e.Fields[field]; !exists {
		e.Fields[field] = message
	}
}

func (e *ValidationError) empty() bool { return len(e.Fields) == 0 }

// ClientInput describes the protocol-level registration for a client.
type ClientInput struct {
	ClientType              string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	AllowedOrigins          []string
	Environment             string
	TokenEndpointAuthMethod string
}

// RegisterAppInput registers an app and its first client in a single unit.
type RegisterAppInput struct {
	Name          string
	Description   string
	FirstParty    bool
	AllowedScopes []string
	Client        ClientInput
}

type RegisterAppOutput struct {
	App          db.Application
	Client       db.OAuthClient
	ClientSecret string
}

type CreateClientOutput struct {
	Client       db.OAuthClient
	ClientSecret string
}

// AppMetadataInput updates product-level app metadata. Clients are managed
// separately and are not touched.
type AppMetadataInput struct {
	Name          string
	Description   string
	FirstParty    bool
	AllowedScopes []string
}

// AppService owns app registration and client credential generation. The raw
// client secret is returned only from these methods and is never persisted.
type AppService struct {
	apps    repository.ApplicationRepository
	clients repository.ClientRepository
}

func NewAppService(apps repository.ApplicationRepository, clients repository.ClientRepository) *AppService {
	return &AppService{apps: apps, clients: clients}
}

func (s *AppService) RegisterApp(ctx context.Context, input RegisterAppInput) (*RegisterAppOutput, error) {
	app, client, secret, err := buildRegistration(input)
	if err != nil {
		return nil, err
	}

	if err := s.apps.CreateWithClient(ctx, app, client); err != nil {
		return nil, fmt.Errorf("create application with client: %w", err)
	}

	return &RegisterAppOutput{
		App:          *app,
		Client:       *client,
		ClientSecret: secret,
	}, nil
}

func (s *AppService) UpdateApp(ctx context.Context, app db.Application, input AppMetadataInput) (db.Application, error) {
	verr := newValidationError()

	name := strings.TrimSpace(input.Name)
	if name == "" {
		verr.add("name", "App name is required")
	}

	scopes, scopeErr := normalizeScopes(input.AllowedScopes)
	if scopeErr != "" {
		verr.add("allowed_scopes", scopeErr)
	}
	if !verr.empty() {
		return db.Application{}, verr
	}

	app.Name = name
	app.Description = strings.TrimSpace(input.Description)
	app.FirstParty = input.FirstParty
	app.AllowedScopes = pq.StringArray(scopes)

	return s.apps.Update(ctx, &app)
}

func (s *AppService) CreateClient(ctx context.Context, applicationID int64, input ClientInput) (*CreateClientOutput, error) {
	client, secret, verr := buildClient(input)
	if verr != nil {
		return nil, verr
	}
	client.ApplicationID = applicationID

	created, err := s.clients.Create(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	return &CreateClientOutput{Client: created, ClientSecret: secret}, nil
}

func buildRegistration(input RegisterAppInput) (*db.Application, *db.OAuthClient, string, error) {
	verr := newValidationError()

	name := strings.TrimSpace(input.Name)
	if name == "" {
		verr.add("name", "App name is required")
	}

	scopes, scopeErr := normalizeScopes(input.AllowedScopes)
	if scopeErr != "" {
		verr.add("allowed_scopes", scopeErr)
	}

	client, secret, clientErr := buildClient(input.Client)
	if clientErr != nil {
		for field, message := range clientErr.Fields {
			verr.add("client_"+field, message)
		}
	}

	if !verr.empty() {
		return nil, nil, "", verr
	}

	app := &db.Application{
		Name:          name,
		Description:   strings.TrimSpace(input.Description),
		FirstParty:    input.FirstParty,
		AllowedScopes: pq.StringArray(scopes),
	}

	return app, client, secret, nil
}

func buildClient(input ClientInput) (*db.OAuthClient, string, *ValidationError) {
	verr := newValidationError()

	clientType := strings.ToLower(strings.TrimSpace(input.ClientType))
	if !contains(clientTypes, clientType) {
		verr.add("client_type", "Client type must be confidential or public")
	}

	environment := strings.ToLower(strings.TrimSpace(input.Environment))
	if environment == "" {
		environment = "local"
	}
	if !contains(environments, environment) {
		verr.add("environment", "Environment must be local, staging, or production")
	}

	redirectURIs := normalizeList(input.RedirectURIs)
	if len(redirectURIs) == 0 {
		verr.add("redirect_uris", "At least one redirect URI is required")
	}
	validateURIs(verr, "redirect_uris", redirectURIs)

	postLogoutURIs := normalizeList(input.PostLogoutRedirectURIs)
	validateURIs(verr, "post_logout_redirect_uris", postLogoutURIs)

	origins := normalizeList(input.AllowedOrigins)
	for _, origin := range origins {
		if err := validateOrigin(origin); err != nil {
			verr.add("allowed_origins", err.Error())
			break
		}
	}

	if !verr.empty() {
		return nil, "", verr
	}

	authMethod := strings.TrimSpace(input.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = "none"
		if clientType == "confidential" {
			authMethod = "client_secret_basic"
		}
	}
	if clientType == "public" {
		authMethod = "none"
	}

	clientID, err := generateClientID()
	if err != nil {
		return nil, "", validationErrorFor("client_id", "Failed to generate client ID")
	}

	var secret string
	var secretHash []byte
	if clientType == "confidential" {
		secret, err = generateClientSecret()
		if err != nil {
			return nil, "", validationErrorFor("client_secret", "Failed to generate client secret")
		}
		sum := sha256.Sum256([]byte(secret))
		secretHash = sum[:]
	}

	client := &db.OAuthClient{
		ClientID:                clientID,
		ClientSecretHash:        secretHash,
		ClientType:              clientType,
		TokenEndpointAuthMethod: authMethod,
		RedirectURIs:            pq.StringArray(redirectURIs),
		PostLogoutRedirectURIs:  pq.StringArray(postLogoutURIs),
		AllowedOrigins:          pq.StringArray(origins),
		Environment:             environment,
	}

	return client, secret, nil
}

func validationErrorFor(field, message string) *ValidationError {
	verr := newValidationError()
	verr.add(field, message)
	return verr
}

func normalizeScopes(scopes []string) ([]string, string) {
	seen := make(map[string]bool, len(scopes))
	out := make([]string, 0, len(scopes))

	for _, raw := range scopes {
		for _, scope := range strings.Fields(raw) {
			scope = strings.ToLower(strings.TrimSpace(scope))
			if scope == "" || seen[scope] {
				continue
			}
			if !oauth.IsSupportedScope(scope) {
				return nil, fmt.Sprintf("Unsupported scope %q", scope)
			}
			seen[scope] = true
			out = append(out, scope)
		}
	}
	return out, ""
}

func normalizeList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		for _, value := range strings.Fields(strings.ReplaceAll(raw, "\r\n", "\n")) {
			value = strings.TrimSpace(value)
			if value != "" {
				out = append(out, value)
			}
		}
	}
	return out
}

func validateURIs(verr *ValidationError, field string, uris []string) {
	for _, uri := range uris {
		if err := oauth.ValidateRedirectURI(uri); err != nil {
			verr.add(field, err.Error())
			return
		}
	}
}

func validateOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid origin %q", raw)
	}
	if !u.IsAbs() || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("origin %q must be an absolute http(s) origin", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("origin %q must not contain a path", raw)
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
