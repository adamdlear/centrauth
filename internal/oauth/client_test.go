package oauth

import (
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
	pq "github.com/lib/pq"
)

func TestIsConfidential(t *testing.T) {
	tests := []struct {
		name       string
		clientType string
		want       bool
	}{
		{"confidential client", "confidential", true},
		{"public client", "public", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := db.OAuthClient{ClientType: tt.clientType}

			if got := IsConfidential(client); got != tt.want {
				t.Errorf("IsConfidential(client with type %q) = %v, want %v", tt.clientType, got, tt.want)
			}
		})
	}
}

func TestIsRedirectURIAllowed(t *testing.T) {
	client := db.OAuthClient{
		RedirectURIs: pq.StringArray{"https://example.com/callback", "https://app.example.com/auth"},
	}

	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{"exact match", "https://example.com/callback", true},
		{"second registered uri", "https://app.example.com/auth", true},
		{"unregistered uri", "https://evil.example.com/callback", false},
		{"trailing slash mismatch", "https://example.com/callback/", false},
		{"scheme mismatch", "http://example.com/callback", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRedirectURIAllowed(client, tt.uri); got != tt.want {
				t.Errorf("IsRedirectURIAllowed(%q) = %v, want %v", tt.uri, got, tt.want)
			}
		})
	}
}

func TestIsRedirectURIAllowed_EmptyList(t *testing.T) {
	client := db.OAuthClient{}

	if IsRedirectURIAllowed(client, "https://example.com/callback") {
		t.Error("IsRedirectURIAllowed() with no registered URIs = true, want false")
	}
}

func TestIsScopeAllowed(t *testing.T) {
	app := db.Application{
		AllowedScopes: pq.StringArray{"openid", "profile", "email"},
	}

	tests := []struct {
		name  string
		scope string
		want  bool
	}{
		{"allowed scope", "openid", true},
		{"another allowed scope", "email", true},
		{"disallowed scope", "tasks:write", false},
		{"prefix of allowed scope", "prof", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsScopeAllowed(app, tt.scope); got != tt.want {
				t.Errorf("IsScopeAllowed(%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestIsScopeAllowed_EmptyList(t *testing.T) {
	app := db.Application{}

	if IsScopeAllowed(app, "openid") {
		t.Error("IsScopeAllowed() with no allowed scopes = true, want false")
	}
}

func TestValidateRequestedScopes(t *testing.T) {
	client := db.OAuthClient{
		ID:            1,
		ApplicationID: 7,
		ClientID:      "todo-web",
		ClientType:    "confidential",
	}
	app := db.Application{
		ID:            client.ApplicationID,
		Name:          "Todo",
		AllowedScopes: pq.StringArray{"openid", "profile", "email"},
	}

	tests := []struct {
		name       string
		scopeParam string
		want       bool
	}{
		{"all requested scopes allowed", "openid profile", true},
		{"single allowed scope", "email", true},
		{"one disallowed scope", "openid tasks:write", false},
		{"only disallowed scopes", "admin:all", false},
		{"empty scope param", "", true},
		{"extra whitespace between scopes", "openid   profile", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateRequestedScopes(app, tt.scopeParam); got != tt.want {
				t.Errorf("ValidateRequestedScopes(%q) = %v, want %v", tt.scopeParam, got, tt.want)
			}
		})
	}
}
