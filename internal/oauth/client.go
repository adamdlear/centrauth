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
