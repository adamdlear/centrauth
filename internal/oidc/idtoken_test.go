package oidc

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/signing"
	"github.com/go-jose/go-jose/v4"
)

func newTestIssuer(t *testing.T, ttl time.Duration) (*IDTokenIssuer, *signing.KeyManager) {
	t.Helper()
	km, err := signing.NewKeyManager(filepath.Join(t.TempDir(), "signing-key.pem"))
	if err != nil {
		t.Fatalf("NewKeyManager() error = %v", err)
	}
	return NewIDTokenIssuer(km, "https://auth.example.com", ttl), km
}

func parseAndVerify(t *testing.T, token string, km *signing.KeyManager) IDTokenClaims {
	t.Helper()

	parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned() error = %v", err)
	}
	if len(parsed.Signatures) != 1 {
		t.Fatalf("signatures = %d, want 1", len(parsed.Signatures))
	}
	if got := string(parsed.Signatures[0].Header.KeyID); got != km.KeyID() {
		t.Errorf("kid = %q, want %q", got, km.KeyID())
	}

	payload, err := parsed.Verify(km.PublicKey())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func TestIDTokenIssuer_Issue(t *testing.T) {
	issuer, km := newTestIssuer(t, 10*time.Minute)

	user := &db.User{ID: 99, Subject: "subject-abc", Email: "user@example.com"}
	authTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)

	token, err := issuer.Issue(context.Background(), IssueParams{
		User:     user,
		ClientID: "client-123",
		Nonce:    "nonce-xyz",
		AuthTime: authTime,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token %q is not a compact JWT", token)
	}

	claims := parseAndVerify(t, token, km)
	if claims.Iss != "https://auth.example.com" {
		t.Errorf("iss = %q", claims.Iss)
	}
	if claims.Sub != user.Subject {
		t.Errorf("sub = %q, want %q", claims.Sub, user.Subject)
	}
	if claims.Aud != "client-123" {
		t.Errorf("aud = %q", claims.Aud)
	}
	if claims.Nonce != "nonce-xyz" {
		t.Errorf("nonce = %q", claims.Nonce)
	}
	if claims.AuthTime != authTime.Unix() {
		t.Errorf("auth_time = %d, want %d", claims.AuthTime, authTime.Unix())
	}
	if claims.Exp <= claims.Iat {
		t.Errorf("exp = %d, iat = %d, want exp after iat", claims.Exp, claims.Iat)
	}
	if got := time.Unix(claims.Exp, 0).Sub(time.Unix(claims.Iat, 0)); got != 10*time.Minute {
		t.Errorf("ttl = %v, want 10m", got)
	}
}

func TestIDTokenIssuer_OmitsEmptyNonce(t *testing.T) {
	issuer, km := newTestIssuer(t, time.Minute)

	token, err := issuer.Issue(context.Background(), IssueParams{
		User:     &db.User{Subject: "subject-no-nonce"},
		ClientID: "client",
		AuthTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	claims := parseAndVerify(t, token, km)
	if claims.Nonce != "" {
		t.Errorf("nonce = %q, want empty", claims.Nonce)
	}
}

func TestIDTokenIssuer_AudienceIsClientSpecific(t *testing.T) {
	issuer, km := newTestIssuer(t, time.Minute)

	token, err := issuer.Issue(context.Background(), IssueParams{
		User:     &db.User{Subject: "subject"},
		ClientID: "client-a",
		AuthTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	claims := parseAndVerify(t, token, km)
	if claims.Aud == "client-b" {
		t.Fatal("token audience unexpectedly matches another client")
	}
}
