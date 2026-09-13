package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
)

var (
	ErrSessionExpired = errors.New("session expired")
	ErrSessionRevoked = errors.New("session revoked")
)

type Config struct {
	CookieName string
	TTL        time.Duration
	Secure     bool
}

type Manager struct {
	sessions repository.SessionRepository
	config   Config
}

func NewManager(sessions repository.SessionRepository, config Config) *Manager {
	return &Manager{sessions: sessions, config: config}
}

func (m *Manager) Create(ctx context.Context, userID int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	hash := sha256.Sum256([]byte(token))
	session := &db.Session{
		TokenHash: hash[:],
		UserID:    userID,
		ExpiresAt: time.Now().Add(m.config.TTL),
	}

	if _, err := m.sessions.Create(ctx, session); err != nil {
		return "", err
	}
	return token, nil
}

func (m *Manager) Validate(ctx context.Context, token string) (*db.Session, error) {
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

func (m *Manager) Revoke(ctx context.Context, id int64) error {
	return m.sessions.Revoke(ctx, id)
}

func (m *Manager) RevokeAllForUser(ctx context.Context, userID int64) error {
	return m.sessions.RevokeAllForUser(ctx, userID)
}

func (m *Manager) GetCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie(m.config.CookieName)
}

func (m *Manager) SetCookie(w http.ResponseWriter, token string) {
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

func (m *Manager) ClearCookie(w http.ResponseWriter) {
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

func (m *Manager) DeleteInactive(ctx context.Context) (int, error) {
	return m.sessions.DeleteInactive(ctx)
}
