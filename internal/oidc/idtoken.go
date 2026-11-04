package oidc

import (
	"context"
	"encoding/json"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/signing"
)

// IDTokenClaims are the OIDC ID token claims centrauth issues.
type IDTokenClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	AuthTime int64  `json:"auth_time"`
	Nonce    string `json:"nonce,omitempty"`
	Email    string `json:"email,omitempty"`
}

// IDTokenIssuer signs ID tokens with the provider's current signing key.
type IDTokenIssuer struct {
	keyManager *signing.KeyManager
	issuerURL  string
	ttl        time.Duration
}

func NewIDTokenIssuer(keyManager *signing.KeyManager, issuerURL string, ttl time.Duration) *IDTokenIssuer {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &IDTokenIssuer{keyManager: keyManager, issuerURL: issuerURL, ttl: ttl}
}

// TTL returns the configured ID token lifetime.
func (i *IDTokenIssuer) TTL() time.Duration { return i.ttl }

type IssueParams struct {
	User     *db.User
	ClientID string
	Nonce    string
	AuthTime time.Time
	Email    string
}

// Issue produces a signed compact JWT ID token.
func (i *IDTokenIssuer) Issue(_ context.Context, params IssueParams) (string, error) {
	now := time.Now()
	claims := IDTokenClaims{
		Iss:      i.issuerURL,
		Sub:      params.User.Subject,
		Aud:      params.ClientID,
		Exp:      now.Add(i.ttl).Unix(),
		Iat:      now.Unix(),
		AuthTime: params.AuthTime.Unix(),
		Nonce:    params.Nonce,
		Email:    params.Email,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signer, err := i.keyManager.Signer()
	if err != nil {
		return "", err
	}

	object, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return object.CompactSerialize()
}
