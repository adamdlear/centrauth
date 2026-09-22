package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
)

type OperatorManager struct {
	sessions repository.OperatorSessionRepository
	config   Config
}

func NewOperatorManager(sessions repository.OperatorSessionRepository, config Config) *OperatorManager {
	return &OperatorManager{sessions: sessions, config: config}
}

func (m *OperatorManager) Create(ctx context.Context, operatorID int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	hash := sha256.Sum256([]byte(token))
	session := &db.OperatorSession{
		TokenHash:  hash[:],
		OperatorID: operatorID,
		ExpiresAt:  time.Now().Add(m.config.TTL),
	}

	if _, err := m.sessions.Create(ctx, session); err != nil {
		return "", err
	}
	return token, nil
}

func (m *OperatorManager) Validate(ctx context.Context, token string) (*db.OperatorSession, error) {
	hash := sha256.Sum256([]byte(token))
	session, err := m.sessions.GetByTokenHash(ctx, hash[:])
	if err != nil {
		return nil, err
	}
	if session.RevokedAt != nil {
		return nil, ErrSessionRevoked
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	return &session, nil
}

func (m *OperatorManager) Revoke(ctx context.Context, id int64) error {
	return m.sessions.Revoke(ctx, id)
}

func (m *OperatorManager) RevokeAllForOperator(ctx context.Context, operatorID int64) error {
	return m.sessions.RevokeAllForOperator(ctx, operatorID)
}

func (m *OperatorManager) GetCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie(m.config.CookieName)
}

func (m *OperatorManager) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.config.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.config.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.config.TTL.Seconds()),
	})
}

func (m *OperatorManager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.config.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.config.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (m *OperatorManager) DeleteInactive(ctx context.Context) (int, error) {
	return m.sessions.DeleteInactive(ctx)
}
