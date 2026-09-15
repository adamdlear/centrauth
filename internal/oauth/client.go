package oauth

import (
	"slices"
	"strings"

	"github.com/adamdlear/centrauth/internal/db"
)

func IsConfidential(c db.OAuthClient) bool {
	return c.ClientType == "confidential"
}

func IsRedirectURIAllowed(c db.OAuthClient, uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

func IsScopeAllowed(c db.OAuthClient, scope string) bool {
	return slices.Contains(c.AllowedScopes, scope)
}

func ValidateRequestedScopes(c db.OAuthClient, scopeParam string) bool {
	for _, scope := range strings.Fields(scopeParam) {
		if !IsScopeAllowed(c, scope) {
			return false
		}
	}
	return true
}
