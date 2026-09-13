package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
)

type fakeSessionRepo struct {
	sessions []db.Session
	nextID   int64
}

func (f *fakeSessionRepo) Create(_ context.Context, s *db.Session) (db.Session, error) {
	f.nextID++
	s.ID = f.nextID
	f.sessions = append(f.sessions, *s)
	return *s, nil
}

func (f *fakeSessionRepo) GetByTokenHash(_ context.Context, tokenHash []byte) (db.Session, error) {
	for _, s := range f.sessions {
		if bytes.Equal(s.TokenHash, tokenHash) {
			return s, nil
		}
	}
	return db.Session{}, repository.ErrNotFound
}

func (f *fakeSessionRepo) Revoke(_ context.Context, id int64) error {
	for i := range f.sessions {
		if f.sessions[i].ID == id {
			now := time.Now()
			f.sessions[i].RevokedAt = &now
			return nil
		}
	}
	return repository.ErrNotFound
}

func (f *fakeSessionRepo) RevokeAllForUser(_ context.Context, userID int64) error {
	now := time.Now()
	for i := range f.sessions {
		if f.sessions[i].UserID == userID && f.sessions[i].RevokedAt == nil {
			f.sessions[i].RevokedAt = &now
		}
	}
	return nil
}

func (f *fakeSessionRepo) DeleteInactive(_ context.Context) (int, error) {
	kept := make([]db.Session, 0, len(f.sessions))
	deleted := 0
	for _, s := range f.sessions {
		if s.ExpiresAt.Before(time.Now()) || s.RevokedAt != nil {
			deleted++
			continue
		}
		kept = append(kept, s)
	}
	f.sessions = kept
	return deleted, nil
}

func testConfig() Config {
	return Config{CookieName: "centrauth_session", TTL: time.Hour, Secure: false}
}

func TestManagerCreateStoresHashedToken(t *testing.T) {
	repo := &fakeSessionRepo{}
	manager := NewManager(repo, testConfig())

	token, err := manager.Create(context.Background(), 42)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if token == "" {
		t.Fatal("Create() returned an empty token")
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not raw URL-encoded base64: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("token entropy = %d bytes, want 32", len(raw))
	}

	if len(repo.sessions) != 1 {
		t.Fatalf("stored %d sessions, want 1", len(repo.sessions))
	}
	stored := repo.sessions[0]

	hash := sha256.Sum256([]byte(token))
	if !bytes.Equal(stored.TokenHash, hash[:]) {
		t.Error("stored TokenHash is not sha256(token)")
	}
	if bytes.Equal(stored.TokenHash, []byte(token)) {
		t.Error("raw token stored instead of a hash")
	}
	if stored.UserID != 42 {
		t.Errorf("stored UserID = %d, want 42", stored.UserID)
	}

	now := time.Now()
	if !stored.ExpiresAt.After(now) {
		t.Errorf("stored ExpiresAt = %v, want after %v", stored.ExpiresAt, now)
	}
	if want := now.Add(time.Hour); stored.ExpiresAt.Sub(want) > time.Minute {
		t.Errorf("stored ExpiresAt = %v, want within a minute of %v", stored.ExpiresAt, want)
	}
}

func TestManagerCreateTokensAreUnique(t *testing.T) {
	manager := NewManager(&fakeSessionRepo{}, testConfig())

	first, err := manager.Create(context.Background(), 1)
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	second, err := manager.Create(context.Background(), 1)
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}

	if first == second {
		t.Error("two Create() calls produced the same token")
	}
}

func TestManagerValidate(t *testing.T) {
	const (
		validToken   = "valid-session-token"
		expiredToken = "expired-session-token"
		revokedToken = "revoked-session-token"
	)

	revokedAt := time.Now().Add(-time.Minute)
	repo := &fakeSessionRepo{}
	manager := NewManager(repo, testConfig())

	seed := func(token string, expires time.Time, revokedAt *time.Time) {
		t.Helper()
		hash := sha256.Sum256([]byte(token))
		if _, err := repo.Create(context.Background(), &db.Session{
			TokenHash: hash[:],
			UserID:    7,
			ExpiresAt: expires,
			RevokedAt: revokedAt,
		}); err != nil {
			t.Fatalf("seeding session: %v", err)
		}
	}

	seed(validToken, time.Now().Add(time.Hour), nil)
	seed(expiredToken, time.Now().Add(-time.Minute), nil)
	seed(revokedToken, time.Now().Add(time.Hour), &revokedAt)

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{"valid token", validToken, nil},
		{"expired token", expiredToken, ErrSessionExpired},
		{"revoked token", revokedToken, ErrSessionRevoked},
		{"unknown token", "no-such-token", repository.ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := manager.Validate(context.Background(), tt.token)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate(%q) error = %v, want %v", tt.token, err, tt.wantErr)
			}
			if err == nil && s == nil {
				t.Error("Validate() returned nil session with nil error")
			}
			if err == nil && s.UserID != 7 {
				t.Errorf("Validate() returned userID %d, want 7", s.UserID)
			}
		})
	}
}

func TestManagerRevokeLifecycle(t *testing.T) {
	repo := &fakeSessionRepo{}
	manager := NewManager(repo, testConfig())

	token, err := manager.Create(context.Background(), 7)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	s, err := manager.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate() before Revoke() error = %v", err)
	}
	if err := manager.Revoke(context.Background(), s.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	if _, err := manager.Validate(context.Background(), token); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Validate() after Revoke() error = %v, want %v", err, ErrSessionRevoked)
	}
}

func TestManagerRevokeAllForUser(t *testing.T) {
	manager := NewManager(&fakeSessionRepo{}, testConfig())

	first, err := manager.Create(context.Background(), 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	second, err := manager.Create(context.Background(), 1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	other, err := manager.Create(context.Background(), 2)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := manager.RevokeAllForUser(context.Background(), 1); err != nil {
		t.Fatalf("RevokeAllForUser() error = %v", err)
	}

	for _, token := range []string{first, second} {
		if _, err := manager.Validate(context.Background(), token); !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("Validate(%q) after RevokeAllForUser() error = %v, want %v", token, err, ErrSessionRevoked)
		}
	}
	if _, err := manager.Validate(context.Background(), other); err != nil {
		t.Errorf("Validate() for other user's session error = %v, want nil", err)
	}
}

func TestManagerSetCookieAttributes(t *testing.T) {
	tests := []struct {
		name       string
		secure     bool
		wantSecure bool
	}{
		{"production", true, true},
		{"local dev", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager(&fakeSessionRepo{}, Config{
				CookieName: "centrauth_session",
				TTL:        24 * time.Hour,
				Secure:     tt.secure,
			})

			rec := httptest.NewRecorder()
			manager.SetCookie(rec, "some-token")

			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("SetCookie() set %d cookies, want 1", len(cookies))
			}
			c := cookies[0]

			if c.Name != "centrauth_session" {
				t.Errorf("cookie name = %q, want %q", c.Name, "centrauth_session")
			}
			if c.Value != "some-token" {
				t.Errorf("cookie value = %q, want %q", c.Value, "some-token")
			}
			if !c.HttpOnly {
				t.Error("cookie missing HttpOnly")
			}
			if c.Secure != tt.wantSecure {
				t.Errorf("cookie Secure = %v, want %v", c.Secure, tt.wantSecure)
			}
			if c.Path != "/" {
				t.Errorf("cookie Path = %q, want %q", c.Path, "/")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("cookie SameSite = %v, want %v", c.SameSite, http.SameSiteLaxMode)
			}
			if c.MaxAge != 86400 {
				t.Errorf("cookie MaxAge = %d, want 86400", c.MaxAge)
			}
		})
	}
}

func TestManagerClearCookie(t *testing.T) {
	manager := NewManager(&fakeSessionRepo{}, Config{
		CookieName: "centrauth_session",
		TTL:        24 * time.Hour,
		Secure:     true,
	})

	rec := httptest.NewRecorder()
	manager.ClearCookie(rec)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("ClearCookie() set %d cookies, want 1", len(cookies))
	}
	c := cookies[0]

	if c.Name != "centrauth_session" {
		t.Errorf("cookie name = %q, want %q", c.Name, "centrauth_session")
	}
	if c.Value != "" {
		t.Errorf("cookie value = %q, want empty", c.Value)
	}
	if c.Path != "/" {
		t.Errorf("cookie Path = %q, want %q", c.Path, "/")
	}
	if c.MaxAge != -1 {
		t.Errorf("cookie MaxAge = %d, want -1", c.MaxAge)
	}
}
