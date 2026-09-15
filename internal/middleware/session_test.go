package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/session"
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

type fakeUserRepo struct {
	byID map[int64]db.User
}

func (f *fakeUserRepo) GetByEmail(_ context.Context, email string) (db.User, error) {
	return db.User{}, repository.ErrNotFound
}

func (f *fakeUserRepo) GetByID(_ context.Context, id int64) (db.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return db.User{}, repository.ErrNotFound
}

func (f *fakeUserRepo) Create(_ context.Context, u *db.User) (db.User, error) {
	return *u, nil
}

func (f *fakeUserRepo) CreateWithCredential(_ context.Context, u *db.User, c *db.UserCredential) (db.User, error) {
	c.UserID = u.ID
	return *u, nil
}

func TestSessionMiddleware(t *testing.T) {
	sessions := &fakeSessionRepo{}
	users := &fakeUserRepo{byID: map[int64]db.User{
		7: {ID: 7, Email: "user7@example.com"},
	}}
	manager := session.NewManager(sessions, session.Config{
		CookieName: "centrauth_session",
		TTL:        time.Hour,
	})

	validToken, err := manager.Create(context.Background(), 7)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	revokedToken, err := manager.Create(context.Background(), 7)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	if s, err := manager.Validate(context.Background(), revokedToken); err != nil {
		t.Fatalf("validating session: %v", err)
	} else if err := sessions.Revoke(context.Background(), s.ID); err != nil {
		t.Fatalf("revoking session: %v", err)
	}

	expiredHash := sha256.Sum256([]byte("expired-token"))
	if _, err := sessions.Create(context.Background(), &db.Session{
		TokenHash: expiredHash[:],
		UserID:    7,
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seeding expired session: %v", err)
	}

	tests := []struct {
		name     string
		cookie   *http.Cookie
		wantUser bool
	}{
		{
			name:     "valid session sets user in context",
			cookie:   &http.Cookie{Name: "centrauth_session", Value: validToken},
			wantUser: true,
		},
		{
			name:     "no cookie continues as anonymous",
			cookie:   nil,
			wantUser: false,
		},
		{
			name:     "unknown token continues as anonymous",
			cookie:   &http.Cookie{Name: "centrauth_session", Value: "bogus-token"},
			wantUser: false,
		},
		{
			name:     "revoked session continues as anonymous",
			cookie:   &http.Cookie{Name: "centrauth_session", Value: revokedToken},
			wantUser: false,
		},
		{
			name:     "expired session continues as anonymous",
			cookie:   &http.Cookie{Name: "centrauth_session", Value: "expired-token"},
			wantUser: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *db.User
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = UserFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			handler := Session(next, manager, users)

			req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d (middleware must never block)", rec.Code, http.StatusOK)
			}
			if (got != nil) != tt.wantUser {
				t.Fatalf("user in context = %v, want present = %v", got, tt.wantUser)
			}
			if tt.wantUser && got.Email != "user7@example.com" {
				t.Errorf("user email = %q, want %q", got.Email, "user7@example.com")
			}
		})
	}
}

func TestRequireAuthRedirectsAnonymous(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()

	RequireAuth(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want %q", loc, "/login")
	}
	if called {
		t.Error("next handler was called for an anonymous request")
	}
}

func TestRequireAuthAllowsAuthenticated(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	ctx := context.WithValue(req.Context(), userKey, &db.User{ID: 7})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	RequireAuth(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Error("next handler was not called for an authenticated request")
	}
}
