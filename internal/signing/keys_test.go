package signing

import (
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func newTestKeyManager(t *testing.T) (*KeyManager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	km, err := NewKeyManager(path)
	if err != nil {
		t.Fatalf("NewKeyManager() error = %v", err)
	}
	return km, path
}

func TestNewKeyManager_GeneratesAndPersistsKey(t *testing.T) {
	km, path := newTestKeyManager(t)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat signing key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("signing key permissions = %v, want 0600", info.Mode().Perm())
	}
	if km.KeyID() == "" {
		t.Error("KeyID() is empty")
	}
	if km.PublicKey().N.BitLen() != rsaKeySize {
		t.Errorf("key size = %d, want %d", km.PublicKey().N.BitLen(), rsaKeySize)
	}
}

func TestNewKeyManager_LoadsExistingKey(t *testing.T) {
	first, path := newTestKeyManager(t)
	second, err := NewKeyManager(path)
	if err != nil {
		t.Fatalf("NewKeyManager() on existing file error = %v", err)
	}

	if first.KeyID() != second.KeyID() {
		t.Errorf("key ID changed across load: %q vs %q", first.KeyID(), second.KeyID())
	}
	if first.PublicKey().N.Cmp(second.PublicKey().N) != 0 {
		t.Error("loaded key differs from generated key")
	}
}

func TestKeyManager_JWKS(t *testing.T) {
	km, _ := newTestKeyManager(t)

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(km.JWKS(), &jwks); err != nil {
		t.Fatalf("JWKS() is not valid JSON: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("JWKS keys = %d, want 1", len(jwks.Keys))
	}

	key := jwks.Keys[0]
	if key.KeyID != km.KeyID() {
		t.Errorf("JWKS kid = %q, want %q", key.KeyID, km.KeyID())
	}
	if key.Algorithm != "RS256" || key.Use != "sig" {
		t.Errorf("JWKS alg/use = %q/%q, want RS256/sig", key.Algorithm, key.Use)
	}
	if _, ok := key.Key.(*rsa.PublicKey); !ok {
		t.Fatalf("JWKS key type = %T, want *rsa.PublicKey", key.Key)
	}

	var raw map[string]any
	if err := json.Unmarshal(km.JWKS(), &raw); err != nil {
		t.Fatalf("unmarshal raw JWKS: %v", err)
	}
	keys := raw["keys"].([]any)
	for _, field := range []string{"d", "p", "q"} {
		if _, found := keys[0].(map[string]any)[field]; found {
			t.Errorf("JWKS leaked private key field %q", field)
		}
	}
}

func TestKeyManager_SignerRoundTrip(t *testing.T) {
	km, _ := newTestKeyManager(t)

	signer, err := km.Signer()
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}

	object, err := signer.Sign([]byte(`{"sub":"user"}`))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() error = %v", err)
	}

	parsed, err := jose.ParseSigned(serialized, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned() error = %v", err)
	}
	if len(parsed.Signatures) != 1 {
		t.Fatalf("signatures = %d, want 1", len(parsed.Signatures))
	}
	if got := string(parsed.Signatures[0].Header.KeyID); got != km.KeyID() {
		t.Errorf("JWS kid = %q, want %q", got, km.KeyID())
	}
	if got := parsed.Signatures[0].Header.ExtraHeaders[jose.HeaderKey("typ")]; got != "JWT" {
		t.Errorf("JWS typ = %v, want JWT", got)
	}

	payload, err := parsed.Verify(km.PublicKey())
	if err != nil {
		t.Fatalf("Verify() with published public key error = %v", err)
	}
	if string(payload) != `{"sub":"user"}` {
		t.Errorf("payload = %q", payload)
	}
}
