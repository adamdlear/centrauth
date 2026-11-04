package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// AuthorizationCodeTTL is how long an authorization code may be exchanged for
// tokens. Codes are short-lived because they travel through the browser.
const AuthorizationCodeTTL = 60 * time.Second

// GenerateAuthorizationCode returns a random, URL-safe authorization code. The
// raw code is sent to the client; only its SHA-256 hash is persisted.
func GenerateAuthorizationCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateAccessToken returns an opaque bearer token. Phase 1 does not expose a
// resource endpoint that accepts it; it exists so standard OAuth2 clients can
// complete the authorization code exchange.
func GenerateAccessToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashAuthorizationCode hashes a raw authorization code for storage and lookup.
func HashAuthorizationCode(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}
