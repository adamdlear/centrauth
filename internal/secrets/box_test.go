package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func newTestBox(t *testing.T) *Box {
	t.Helper()
	box, err := NewBoxFromKeyFile(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("NewBoxFromKeyFile() error = %v", err)
	}
	return box
}

func TestBox_RoundTrip(t *testing.T) {
	box := newTestBox(t)

	plaintext := []byte("github-client-secret")
	encrypted, err := box.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if bytes.Contains(encrypted, plaintext) {
		t.Fatal("ciphertext contains the plaintext")
	}

	decrypted, err := box.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestBox_FreshNonce(t *testing.T) {
	box := newTestBox(t)

	first, _ := box.Encrypt([]byte("same"))
	second, _ := box.Encrypt([]byte("same"))
	if bytes.Equal(first, second) {
		t.Error("Encrypt() produced identical ciphertext for the same plaintext")
	}
}

func TestBox_DetectsTampering(t *testing.T) {
	box := newTestBox(t)

	encrypted, _ := box.Encrypt([]byte("secret"))
	encrypted[len(encrypted)-1] ^= 0xff

	if _, err := box.Decrypt(encrypted); err == nil {
		t.Error("Decrypt() accepted tampered ciphertext")
	}
}

func TestNewBoxFromKeyFile_PersistsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	first, err := NewBoxFromKeyFile(path)
	if err != nil {
		t.Fatalf("NewBoxFromKeyFile() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key permissions = %v, want 0600", info.Mode().Perm())
	}

	second, err := NewBoxFromKeyFile(path)
	if err != nil {
		t.Fatalf("reload key: %v", err)
	}

	encrypted, _ := first.Encrypt([]byte("value"))
	if _, err := second.Decrypt(encrypted); err != nil {
		t.Errorf("reloaded box could not decrypt: %v", err)
	}
}

func TestNewBox_RejectsWrongKeySize(t *testing.T) {
	if _, err := NewBox([]byte("short")); err == nil {
		t.Error("NewBox() accepted a short key")
	}
}
