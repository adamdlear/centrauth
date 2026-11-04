package oauth

import (
	"errors"
	"testing"
)

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr error
	}{
		{"https", "https://example.com/callback", nil},
		{"http localhost", "http://localhost:3000/callback", nil},
		{"http loopback ipv4", "http://127.0.0.1:8080/callback", nil},
		{"http loopback ipv6", "http://[::1]:8080/callback", nil},
		{"https with query", "https://example.com/callback?tenant=a", nil},
		{"relative", "/callback", ErrRedirectURINotAbsolute},
		{"no host", "https:///callback", ErrRedirectURINotAbsolute},
		{"empty", "", ErrRedirectURINotAbsolute},
		{"plain http remote", "http://example.com/callback", ErrRedirectURIInsecure},
		{"fragment", "https://example.com/callback#frag", ErrRedirectURIHasFragment},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURI(tt.uri)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateRedirectURI(%q) error = %v, want %v", tt.uri, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRedirectURI_RejectsWildcard(t *testing.T) {
	if err := ValidateRedirectURI("https://*.example.com/callback"); err == nil {
		t.Error("ValidateRedirectURI() accepted a wildcard host")
	}
}
