package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestGenerateAuthorizationCode(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		code, err := GenerateAuthorizationCode()
		if err != nil {
			t.Fatalf("GenerateAuthorizationCode() error = %v", err)
		}
		if code == "" {
			t.Fatal("GenerateAuthorizationCode() returned an empty code")
		}
		if _, err := base64.RawURLEncoding.DecodeString(code); err != nil {
			t.Fatalf("GenerateAuthorizationCode() returned a non-base64url code %q: %v", code, err)
		}
		if seen[code] {
			t.Fatalf("GenerateAuthorizationCode() returned a duplicate code %q", code)
		}
		seen[code] = true
	}
}

func TestHashAuthorizationCode(t *testing.T) {
	code := "a-raw-code"

	got := HashAuthorizationCode(code)
	want := sha256.Sum256([]byte(code))

	if len(got) != len(want) {
		t.Fatalf("HashAuthorizationCode() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("HashAuthorizationCode() = %x, want %x", got, want)
		}
	}

	if string(HashAuthorizationCode("other")) == string(got) {
		t.Error("HashAuthorizationCode() returned the same hash for different codes")
	}
}
