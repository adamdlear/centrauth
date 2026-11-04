package upstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/signing"
)

type fakeOIDCProvider struct {
	server   *httptest.Server
	km       *signing.KeyManager
	clientID string
	subject  string
	email    string
	verified bool
}

func newFakeOIDCProvider(t *testing.T, clientID string) *fakeOIDCProvider {
	t.Helper()
	km, err := signing.NewKeyManager(filepath.Join(t.TempDir(), "upstream-key.pem"))
	if err != nil {
		t.Fatalf("NewKeyManager() error = %v", err)
	}
	fake := &fakeOIDCProvider{km: km, clientID: clientID, subject: "upstream-subject", email: "upstream@example.com", verified: true}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := fake.server.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/auth",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(km.JWKS())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.FormValue("code") != "good-code" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "upstream-access-token",
			"id_token":     fake.signIDToken(t),
		})
	})

	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeOIDCProvider) signIDToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":            f.server.URL,
		"sub":            f.subject,
		"aud":            f.clientID,
		"exp":            now.Add(time.Minute).Unix(),
		"iat":            now.Unix(),
		"email":          f.email,
		"email_verified": f.verified,
		"name":           "Upstream Person",
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signer, err := f.km.Signer()
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() error = %v", err)
	}
	return serialized
}

func TestGoogleExchange(t *testing.T) {
	fake := newFakeOIDCProvider(t, "google-client")
	cfg := Config{
		Name:         "google",
		ClientID:     "google-client",
		ClientSecret: "google-secret",
		RedirectURL:  "https://auth.example.com/auth/upstream/google/callback",
		TokenURL:     fake.server.URL + "/token",
		Issuer:       fake.server.URL,
		Scopes:       []string{"openid", "email", "profile"},
		UsePKCE:      true,
		OIDC:         true,
	}

	client := NewClient(cfg)
	identity, err := client.Exchange(context.Background(), "good-code", "verifier")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if identity.Subject != "upstream-subject" {
		t.Errorf("Subject = %q", identity.Subject)
	}
	if identity.Email != "upstream@example.com" || !identity.EmailVerified {
		t.Errorf("email = %q verified=%v", identity.Email, identity.EmailVerified)
	}
	if identity.Name != "Upstream Person" {
		t.Errorf("Name = %q", identity.Name)
	}
	if identity.Provider != "google" {
		t.Errorf("Provider = %q", identity.Provider)
	}
}

func TestGoogleExchange_RejectsBadCode(t *testing.T) {
	fake := newFakeOIDCProvider(t, "google-client")
	client := NewClient(Config{
		Name: "google", ClientID: "google-client", ClientSecret: "secret",
		TokenURL: fake.server.URL + "/token", Issuer: fake.server.URL, OIDC: true,
	})

	if _, err := client.Exchange(context.Background(), "bad-code", ""); err == nil {
		t.Fatal("Exchange() with a bad code succeeded")
	}
}

func TestAuthCodeURL_GoogleUsesPKCE(t *testing.T) {
	client := NewClient(Config{
		Name: "google", ClientID: "client", RedirectURL: "https://auth.example.com/cb",
		AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", Scopes: []string{"openid", "email"}, UsePKCE: true,
	})

	authURL, err := url.Parse(client.AuthCodeURL("state-1", "challenge-1"))
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	query := authURL.Query()
	if query.Get("state") != "state-1" || query.Get("code_challenge") != "challenge-1" || query.Get("code_challenge_method") != "S256" {
		t.Errorf("auth URL query = %v", query)
	}
	if query.Get("client_id") != "client" || query.Get("redirect_uri") != "https://auth.example.com/cb" {
		t.Errorf("auth URL missing client params: %v", query)
	}
}

func TestGitHubExchange(t *testing.T) {
	var tokenCalls, userCalls, emailCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		if err := r.ParseForm(); err != nil || r.FormValue("code") != "good-code" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "github-token"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		userCalls++
		if r.Header.Get("Authorization") != "Bearer github-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12345, "login": "octocat", "name": "Octo Cat", "email": "public@example.com",
		})
	})
	mux.HandleFunc("/emails", func(w http.ResponseWriter, r *http.Request) {
		emailCalls++
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"email": "secondary@example.com", "primary": false, "verified": true},
			{"email": "octo@example.com", "primary": true, "verified": true},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(Config{
		Name: "github", ClientID: "gh-client", ClientSecret: "gh-secret",
		TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/user", EmailsURL: server.URL + "/emails",
	})

	identity, err := client.Exchange(context.Background(), "good-code", "")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if identity.Subject != "12345" {
		t.Errorf("Subject = %q, want 12345", identity.Subject)
	}
	if identity.Email != "octo@example.com" || !identity.EmailVerified {
		t.Errorf("email = %q verified=%v, want primary verified email", identity.Email, identity.EmailVerified)
	}
	if identity.Name != "Octo Cat" {
		t.Errorf("Name = %q", identity.Name)
	}
	if tokenCalls != 1 || userCalls != 1 || emailCalls != 1 {
		t.Errorf("calls = %d/%d/%d, want 1/1/1", tokenCalls, userCalls, emailCalls)
	}
}

func TestGitHubExchange_UnverifiedEmail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "github-token"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "user", "email": "maybe@example.com"})
	})
	mux.HandleFunc("/emails", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{"email": "maybe@example.com", "primary": true, "verified": false}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	identity, err := NewClient(Config{
		Name: "github", ClientID: "c", ClientSecret: "s",
		TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/user", EmailsURL: server.URL + "/emails",
	}).Exchange(context.Background(), "code", "")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if identity.EmailVerified {
		t.Error("EmailVerified = true for an unverified address")
	}
}

func TestConfigFor(t *testing.T) {
	for _, name := range SupportedProviders {
		cfg, err := ConfigFor(name, "client", "secret", "https://example.com/cb")
		if err != nil {
			t.Fatalf("ConfigFor(%q) error = %v", name, err)
		}
		if cfg.Name != name || cfg.AuthURL == "" || cfg.TokenURL == "" || len(cfg.Scopes) == 0 {
			t.Errorf("ConfigFor(%q) = %+v", name, cfg)
		}
	}
	if _, err := ConfigFor("okta", "c", "s", "u"); err == nil {
		t.Error("ConfigFor(unknown) error = nil")
	}
}

func TestIdentityTokenSigned(t *testing.T) {
	// Guards against accidentally skipping verification in exchangeOIDC.
	fake := newFakeOIDCProvider(t, "google-client")
	fake.verified = false

	_, err := NewClient(Config{
		Name: "google", ClientID: "wrong-client", ClientSecret: "secret",
		TokenURL: fake.server.URL + "/token", Issuer: fake.server.URL, OIDC: true,
	}).Exchange(context.Background(), "good-code", "")
	if err == nil {
		t.Fatal("Exchange() accepted an ID token with the wrong audience")
	}
}
