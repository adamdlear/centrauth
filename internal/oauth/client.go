package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"slices"
	"strings"

	"github.com/adamdlear/centrauth/internal/db"
)

// SupportedScopes are the scopes this provider understands. An app's allowed
// scopes must be a subset of these.
var SupportedScopes = []string{"openid", "profile", "email"}

func IsConfidential(c db.OAuthClient) bool {
	return c.ClientType == "confidential"
}

// IsSupportedScope reports whether scope is one the provider can issue.
func IsSupportedScope(scope string) bool {
	return slices.Contains(SupportedScopes, scope)
}

// ValidateClientSecret reports whether submittedSecret matches the client's
// stored secret hash. The comparison is constant time.
func ValidateClientSecret(c db.OAuthClient, submittedSecret string) bool {
	if len(c.ClientSecretHash) == 0 || submittedSecret == "" {
		return false
	}
	sum := sha256.Sum256([]byte(submittedSecret))
	return subtle.ConstantTimeCompare(sum[:], c.ClientSecretHash) == 1
}

func IsRedirectURIAllowed(c db.OAuthClient, uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

func IsScopeAllowed(app db.Application, scope string) bool {
	return slices.Contains(app.AllowedScopes, scope)
}

func ValidateRequestedScopes(app db.Application, scopeParam string) bool {
	for _, scope := range strings.Fields(scopeParam) {
		if !IsScopeAllowed(app, scope) {
			return false
		}
	}
	return true
}
