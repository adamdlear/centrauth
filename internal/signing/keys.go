package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-jose/go-jose/v4"
)

const rsaKeySize = 2048

// KeyManager owns the provider's token-signing key. The private key is loaded
// from disk, or generated and persisted on first use for local development.
type KeyManager struct {
	privateKey *rsa.PrivateKey
	keyID      string
	jwks       jose.JSONWebKeySet
}

// NewKeyManager loads the RSA signing key at keyPath, generating and saving a
// new 2048-bit key when the file does not exist.
func NewKeyManager(keyPath string) (*KeyManager, error) {
	key, err := loadOrGenerateKey(keyPath)
	if err != nil {
		return nil, err
	}

	keyID := keyIDFor(&key.PublicKey)
	km := &KeyManager{
		privateKey: key,
		keyID:      keyID,
		jwks: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       &key.PublicKey,
				KeyID:     keyID,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			}},
		},
	}
	return km, nil
}

// Signer returns a signer that emits RS256 JWTs with the current key ID.
func (km *KeyManager) Signer() (jose.Signer, error) {
	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader(jose.HeaderKey("kid"), km.keyID)
	return jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: km.privateKey}, opts)
}

// JWKS returns the public JSON Web Key Set.
func (km *KeyManager) JWKS() []byte {
	data, err := json.Marshal(km.jwks)
	if err != nil {
		// A JSONWebKeySet of one RSA public key always marshals.
		return []byte(`{"keys":[]}`)
	}
	return data
}

// KeyID returns the stable identifier for the current signing key.
func (km *KeyManager) KeyID() string { return km.keyID }

// PublicKey returns the public half of the signing key.
func (km *KeyManager) PublicKey() *rsa.PublicKey { return &km.privateKey.PublicKey }

func loadOrGenerateKey(keyPath string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(keyPath)
	if err == nil {
		return parsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read signing key %q: %w", keyPath, err)
	}

	key, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal signing key: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if dir := filepath.Dir(keyPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create signing key directory: %w", err)
		}
	}
	if err := os.WriteFile(keyPath, block, 0o600); err != nil {
		return nil, fmt.Errorf("write signing key %q: %w", keyPath, err)
	}

	return key, nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key file does not contain a PEM block")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("signing key is not an RSA key")
		}
		return rsaKey, nil
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	return key, nil
}

func keyIDFor(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}
