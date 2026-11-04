// Package secrets encrypts provider credentials at rest.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const keySize = 32

// Box encrypts and decrypts small secrets with AES-256-GCM.
type Box struct {
	aead cipher.AEAD
}

// NewBoxFromKeyFile loads a 32-byte key from keyPath, generating and saving one
// on first use.
func NewBoxFromKeyFile(keyPath string) (*Box, error) {
	key, err := loadOrGenerateKey(keyPath)
	if err != nil {
		return nil, err
	}
	return NewBox(key)
}

// NewBox builds a Box from a 32-byte key.
func NewBox(key []byte) (*Box, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("encryption key must be %d bytes, got %d", keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Encrypt returns nonce||ciphertext. A fresh nonce is used for every call.
func (b *Box) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. It fails if the ciphertext was tampered with.
func (b *Box) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := b.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext is too short")
	}
	nonce, payload := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return b.aead.Open(nil, nonce, payload, nil)
}

func loadOrGenerateKey(keyPath string) ([]byte, error) {
	key, err := os.ReadFile(keyPath)
	if err == nil {
		if len(key) != keySize {
			return nil, fmt.Errorf("encryption key %q must be %d bytes, got %d", keyPath, keySize, len(key))
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read encryption key %q: %w", keyPath, err)
	}

	key = make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if dir := filepath.Dir(keyPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, fmt.Errorf("write encryption key %q: %w", keyPath, err)
	}
	return key, nil
}
