package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
)

type fakeOperatorSessionRepo struct {
	sessions []db.OperatorSession
	nextID   int64
}

func (f *fakeOperatorSessionRepo) Create(_ context.Context, s *db.OperatorSession) (db.OperatorSession, error) {
	f.nextID++
	s.ID = f.nextID
	f.sessions = append(f.sessions, *s)
	return *s, nil
}

func (f *fakeOperatorSessionRepo) GetByTokenHash(_ context.Context, tokenHash []byte) (db.OperatorSession, error) {
	for _, s := range f.sessions {
		if bytes.Equal(s.TokenHash, tokenHash) {
			return s, nil
		}
	}
	return db.OperatorSession{}, repository.ErrNotFound
}

func (f *fakeOperatorSessionRepo) Revoke(_ context.Context, id int64) error {
	for i := range f.sessions {
		if f.sessions[i].ID == id {
			now := time.Now()
			f.sessions[i].RevokedAt = &now
			return nil
		}
	}
	return repository.ErrNotFound
}

func (f *fakeOperatorSessionRepo) RevokeAllForOperator(_ context.Context, operatorID int64) error {
	now := time.Now()
	for i := range f.sessions {
		if f.sessions[i].OperatorID == operatorID && f.sessions[i].RevokedAt == nil {
			f.sessions[i].RevokedAt = &now
		}
	}
	return nil
}

func (f *fakeOperatorSessionRepo) DeleteInactive(_ context.Context) (int, error) {
	kept := make([]db.OperatorSession, 0, len(f.sessions))
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

func TestOperatorManagerCreateStoresHashedToken(t *testing.T) {
	repo := &fakeOperatorSessionRepo{}
	manager := NewOperatorManager(repo, testConfig())

	token, err := manager.Create(context.Background(), 42)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if token == "" {
		t.Fatal("Create() returned an empty token")
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
	if stored.OperatorID != 42 {
		t.Errorf("stored OperatorID = %d, want 42", stored.OperatorID)
	}

	now := time.Now()
	if !stored.ExpiresAt.After(now) {
		t.Errorf("stored ExpiresAt = %v, want after %v", stored.ExpiresAt, now)
	}
}

func TestOperatorManagerValidate(t *testing.T) {
	const (
		validToken   = "valid-operator-session-token"
		expiredToken = "expired-operator-session-token"
		revokedToken = "revoked-operator-session-token"
	)

	revokedAt := time.Now().Add(-time.Minute)
	repo := &fakeOperatorSessionRepo{}
	manager := NewOperatorManager(repo, testConfig())

	seed := func(token string, expires time.Time, revokedAt *time.Time) {
		t.Helper()
		hash := sha256.Sum256([]byte(token))
		if _, err := repo.Create(context.Background(), &db.OperatorSession{
			TokenHash:  hash[:],
			OperatorID: 7,
			ExpiresAt:  expires,
			RevokedAt:  revokedAt,
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
			if err == nil && s.OperatorID != 7 {
				t.Errorf("Validate() returned operatorID %d, want 7", s.OperatorID)
			}
		})
	}
}

func TestOperatorManagerRevokeLifecycle(t *testing.T) {
	repo := &fakeOperatorSessionRepo{}
	manager := NewOperatorManager(repo, testConfig())

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

func TestOperatorManagerRevokeAllForOperator(t *testing.T) {
	repo := &fakeOperatorSessionRepo{}
	manager := NewOperatorManager(repo, testConfig())

	first, err := manager.Create(context.Background(), 1)
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	second, err := manager.Create(context.Background(), 1)
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}
	other, err := manager.Create(context.Background(), 2)
	if err != nil {
		t.Fatalf("other Create() error = %v", err)
	}

	if err := manager.RevokeAllForOperator(context.Background(), 1); err != nil {
		t.Fatalf("RevokeAllForOperator() error = %v", err)
	}

	for _, token := range []string{first, second} {
		if _, err := manager.Validate(context.Background(), token); !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("Validate(%q) after RevokeAllForOperator() error = %v, want %v", token, err, ErrSessionRevoked)
		}
	}
	if _, err := manager.Validate(context.Background(), other); err != nil {
		t.Errorf("Validate() for other operator's session error = %v, want nil", err)
	}
}

func TestOperatorManagerCookieAttributes(t *testing.T) {
	manager := NewOperatorManager(&fakeOperatorSessionRepo{}, Config{
		CookieName: "centrauth_operator",
		TTL:        24 * time.Hour,
		Secure:     true,
	})

	rec := httptest.NewRecorder()
	manager.SetCookie(rec, "some-token")

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("SetCookie() set %d cookies, want 1", len(cookies))
	}
	c := cookies[0]

	if c.Name != "centrauth_operator" {
		t.Errorf("cookie name = %q, want %q", c.Name, "centrauth_operator")
	}
	if !c.HttpOnly {
		t.Error("cookie missing HttpOnly")
	}
	if !c.Secure {
		t.Error("cookie missing Secure")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite = %v, want %v", c.SameSite, http.SameSiteLaxMode)
	}
	if c.MaxAge != 86400 {
		t.Errorf("cookie MaxAge = %d, want 86400", c.MaxAge)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	got, err := manager.GetCookie(req)
	if err != nil {
		t.Fatalf("GetCookie() error = %v", err)
	}
	if got.Name != "centrauth_operator" {
		t.Errorf("GetCookie() name = %q, want %q", got.Name, "centrauth_operator")
	}

	rec = httptest.NewRecorder()
	manager.ClearCookie(rec)
	if len(rec.Result().Cookies()) != 1 || rec.Result().Cookies()[0].MaxAge != -1 {
		t.Error("ClearCookie() did not clear the cookie")
	}
}
