package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	ErrRedirectURINotAbsolute = errors.New("redirect URI must be absolute")
	ErrRedirectURIInsecure    = errors.New("redirect URI must use https (http is allowed for localhost only)")
	ErrRedirectURIHasFragment = errors.New("redirect URI must not contain a fragment")
)

// ValidateRedirectURI checks that a registered redirect URI is absolute and
// safe. Loopback HTTP URIs are allowed for local development; everything else
// must use HTTPS. Wildcards are rejected because redirect URIs are matched
// exactly.
func ValidateRedirectURI(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ErrRedirectURINotAbsolute
	}
	if strings.Contains(raw, "*") {
		return fmt.Errorf("redirect URI %q must not contain a wildcard", raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse redirect URI %q: %w", raw, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return ErrRedirectURINotAbsolute
	}
	if u.Fragment != "" {
		return ErrRedirectURIHasFragment
	}

	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return ErrRedirectURIInsecure
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}
