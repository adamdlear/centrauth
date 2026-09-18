package internal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/admin/templates"
	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/service"
	"github.com/adamdlear/centrauth/internal/session"
)

type fakeUserRepo struct {
	byID    map[int64]db.User
	byEmail map[string]db.User
	nextID  int64
}

func (f *fakeUserRepo) GetByEmail(_ context.Context, email string) (db.User, error) {
	if u, ok := f.byEmail[email]; ok {
		return u, nil
	}
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
	f.nextID++
	u.ID = f.nextID
	c.UserID = u.ID
	f.byID[u.ID] = *u
	f.byEmail[u.Email] = *u
	return *u, nil
}

type fakeClientRepo struct {
	clients []db.OAuthClient
}

func (f *fakeClientRepo) GetByClientID(_ context.Context, clientID string) (db.OAuthClient, error) {
	for _, c := range f.clients {
		if c.ClientID == clientID {
			return c, nil
		}
	}
	return db.OAuthClient{}, repository.ErrNotFound
}

func (f *fakeClientRepo) Create(_ context.Context, c *db.OAuthClient) (db.OAuthClient, error) {
	return *c, nil
}

func (f *fakeClientRepo) Update(_ context.Context, c *db.OAuthClient) (db.OAuthClient, error) {
	for i := range f.clients {
		if f.clients[i].ID == c.ID {
			f.clients[i] = *c
			return *c, nil
		}
	}
	return db.OAuthClient{}, repository.ErrNotFound
}

func (f *fakeClientRepo) List(_ context.Context) ([]db.OAuthClient, error) {
	return f.clients, nil
}

func (f *fakeClientRepo) ListByEnvironment(_ context.Context, environment string) ([]db.OAuthClient, error) {
	var clients []db.OAuthClient
	for _, c := range f.clients {
		if c.Environment == environment {
			clients = append(clients, c)
		}
	}
	return clients, nil
}

func (f *fakeClientRepo) ListByApplicationID(_ context.Context, applicationID int64) ([]db.OAuthClient, error) {
	var clients []db.OAuthClient
	for _, c := range f.clients {
		if c.ApplicationID == applicationID {
			clients = append(clients, c)
		}
	}
	return clients, nil
}

type fakeApplicationRepo struct {
	apps       []db.Application
	nextID     int64
	clientRepo *fakeClientRepo
}

func (f *fakeApplicationRepo) Create(_ context.Context, a *db.Application) (db.Application, error) {
	f.nextID++
	a.ID = f.nextID
	f.apps = append(f.apps, *a)
	return *a, nil
}

func (f *fakeApplicationRepo) GetByID(_ context.Context, id int64) (db.Application, error) {
	for _, a := range f.apps {
		if a.ID == id {
			return a, nil
		}
	}
	return db.Application{}, repository.ErrNotFound
}

func (f *fakeApplicationRepo) List(_ context.Context) ([]db.Application, error) {
	return f.apps, nil
}

func (f *fakeApplicationRepo) Update(_ context.Context, a *db.Application) (db.Application, error) {
	for i := range f.apps {
		if f.apps[i].ID == a.ID {
			f.apps[i] = *a
			return *a, nil
		}
	}
	return db.Application{}, repository.ErrNotFound
}

func (f *fakeApplicationRepo) GetWithClients(_ context.Context, id int64) (db.Application, []db.OAuthClient, error) {
	for _, a := range f.apps {
		if a.ID == id {
			clients, err := f.clientRepo.ListByApplicationID(context.Background(), id)
			return a, clients, err
		}
	}
	return db.Application{}, nil, repository.ErrNotFound
}

type fakeCredentialRepo struct {
	creds map[int64]db.UserCredential
}

func (f *fakeCredentialRepo) GetByUserIDAndMethod(_ context.Context, userID int64, method string) (db.UserCredential, error) {
	if c, ok := f.creds[userID]; ok && method == "password" {
		return c, nil
	}
	return db.UserCredential{}, repository.ErrNotFound
}

func (f *fakeCredentialRepo) Create(_ context.Context, c *db.UserCredential) (db.UserCredential, error) {
	return *c, nil
}

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

func newTestApp() (*App, *fakeUserRepo, *fakeCredentialRepo, *fakeSessionRepo, *fakeApplicationRepo, *fakeClientRepo) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := &fakeUserRepo{byID: map[int64]db.User{}, byEmail: map[string]db.User{}}
	creds := &fakeCredentialRepo{creds: map[int64]db.UserCredential{}}
	sessions := &fakeSessionRepo{}
	clients := &fakeClientRepo{}
	applications := &fakeApplicationRepo{clientRepo: clients}

	app := &App{
		logger:       logger,
		templates:    templates.New(),
		login:        service.NewLoginService(logger, users, creds),
		sessions:     session.NewManager(sessions, session.Config{CookieName: "centrauth_session", TTL: time.Hour}),
		users:        users,
		clients:      clients,
		applications: applications,
	}

	return app, users, creds, sessions, applications, clients
}

func TestHealthRoute(t *testing.T) {
	app, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestLoginPageRenders(t *testing.T) {
	app, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	for _, want := range []string{
		`action="/auth/login"`,
		`action="/auth/register"`,
		`name="email"`,
		`name="password"`,
		`name="password_confirm"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response body missing %q", want)
		}
	}
}

func TestRoutesRejectCrossSitePost(t *testing.T) {
	app, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodPost, "/auth/register", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRoutesAllowSameOriginPost(t *testing.T) {
	app, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodPost, "/auth/register", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
}

func TestRootRedirectsToDashboard(t *testing.T) {
	app, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("Location = %q, want %q", loc, "/dashboard")
	}
}

func TestDashboardRedirectsAnonymousToLogin(t *testing.T) {
	app, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want %q", loc, "/login")
	}
}

func TestDashboardRendersForAuthenticatedUser(t *testing.T) {
	app, users, _, _, applications, clients := newTestApp()

	user := db.User{ID: 7, Subject: "dashboard-subject", Email: "dash@example.com"}
	users.byID[7] = user

	applications.apps = []db.Application{{ID: 1, Name: "Todo App"}}
	clients.clients = []db.OAuthClient{
		{ID: 1, ApplicationID: 1, ClientID: "todo-web", ClientType: "confidential"},
		{ID: 2, ApplicationID: 1, ClientID: "todo-mobile", ClientType: "public"},
	}

	token, err := app.sessions.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "centrauth_session", Value: token})
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	for _, want := range []string{
		"dash@example.com",
		`action="/auth/logout"`,
		"Todo App",
		`class="count-n">2<`,
		`action="/apps" method="post" class="app-form"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response body missing %q", want)
		}
	}
}

func TestCreateAppRoute(t *testing.T) {
	app, users, _, _, applications, _ := newTestApp()

	user := db.User{ID: 7, Subject: "create-app-subject", Email: "createapp@example.com"}
	users.byID[7] = user

	token, err := app.sessions.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	form := url.Values{"name": {"Todo App"}, "description": {"A todo app"}, "allowed_scopes": {"openid profile"}}
	req := httptest.NewRequest(http.MethodPost, "/apps", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "centrauth_session", Value: token})
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("Location = %q, want %q", loc, "/dashboard")
	}

	if len(applications.apps) != 1 {
		t.Fatalf("stored %d apps, want 1", len(applications.apps))
	}
	created := applications.apps[0]
	if created.Name != "Todo App" {
		t.Errorf("Name = %q, want %q", created.Name, "Todo App")
	}
	if created.Description != "A todo app" {
		t.Errorf("Description = %q, want %q", created.Description, "A todo app")
	}
	if !created.FirstParty {
		t.Error("FirstParty = false, want true")
	}
	if len(created.AllowedScopes) != 2 || created.AllowedScopes[0] != "openid" || created.AllowedScopes[1] != "profile" {
		t.Errorf("AllowedScopes = %v, want [openid profile]", created.AllowedScopes)
	}
}

func TestCreateAppRequiresName(t *testing.T) {
	app, users, _, _, applications, _ := newTestApp()

	user := db.User{ID: 7, Subject: "create-app-empty-subject", Email: "createappempty@example.com"}
	users.byID[7] = user

	token, err := app.sessions.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	form := url.Values{"name": {"   "}}
	req := httptest.NewRequest(http.MethodPost, "/apps", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "centrauth_session", Value: token})
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (dashboard re-rendered)", rec.Code, http.StatusOK)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !strings.Contains(string(body), "App name is required") {
		t.Error("response body missing error message")
	}
	if !strings.Contains(string(body), `action="/apps"`) {
		t.Error("response body missing create-app form")
	}

	if len(applications.apps) != 0 {
		t.Errorf("created %d apps with blank name, want 0", len(applications.apps))
	}
}

func TestCreateAppRedirectsAnonymousToLogin(t *testing.T) {
	app, _, _, _, _, _ := newTestApp()

	form := url.Values{"name": {"Todo App"}}
	req := httptest.NewRequest(http.MethodPost, "/apps", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want %q", loc, "/login")
	}
}

func TestLoginCreatesSessionAndCookie(t *testing.T) {
	app, users, creds, sessions, _, _ := newTestApp()

	hash, err := service.HashPassword("correct-password", &service.PasswordHashParams{
		Memory:      64,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   32,
		SaltLength:  16,
	})
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}

	user := db.User{ID: 7, Subject: "login-subject", Email: "login@example.com"}
	users.byID[7] = user
	users.byEmail[user.Email] = user
	creds.creds[7] = db.UserCredential{UserID: 7, Method: "password", PasswordHash: &hash}

	form := url.Values{"email": {user.Email}, "password": {"correct-password"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("Location = %q, want %q", loc, "/dashboard")
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "centrauth_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("login did not set a session cookie")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}

	if len(sessions.sessions) != 1 {
		t.Fatalf("stored %d sessions, want 1", len(sessions.sessions))
	}
	if sessions.sessions[0].UserID != user.ID {
		t.Errorf("stored session UserID = %d, want %d", sessions.sessions[0].UserID, user.ID)
	}

	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard with session cookie: got status %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestLoginRejectsWrongPasswordWithoutSession(t *testing.T) {
	app, users, creds, sessions, _, _ := newTestApp()

	hash, err := service.HashPassword("correct-password", &service.PasswordHashParams{
		Memory:      64,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   32,
		SaltLength:  16,
	})
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}

	user := db.User{ID: 7, Subject: "wrongpw-subject", Email: "wrongpw@example.com"}
	users.byID[7] = user
	users.byEmail[user.Email] = user
	creds.creds[7] = db.UserCredential{UserID: 7, Method: "password", PasswordHash: &hash}

	form := url.Values{"email": {user.Email}, "password": {"wrong-password"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (login page re-rendered)", rec.Code, http.StatusOK)
	}
	if len(sessions.sessions) != 0 {
		t.Errorf("created %d sessions on failed login, want 0", len(sessions.sessions))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "centrauth_session" {
			t.Error("failed login set a session cookie")
		}
	}
}

func TestLogoutRevokesSessionAndClearsCookie(t *testing.T) {
	app, users, _, _, _, _ := newTestApp()

	user := db.User{ID: 7, Subject: "logout-subject", Email: "logout@example.com"}
	users.byID[7] = user

	token, err := app.sessions.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "centrauth_session", Value: token})
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want %q", loc, "/login")
	}

	var cleared *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "centrauth_session" {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatal("logout did not clear the session cookie")
	}
	if cleared.MaxAge != -1 {
		t.Errorf("clearing cookie MaxAge = %d, want -1", cleared.MaxAge)
	}

	if _, err := app.sessions.Validate(context.Background(), token); !errors.Is(err, session.ErrSessionRevoked) {
		t.Errorf("Validate() after logout error = %v, want %v", err, session.ErrSessionRevoked)
	}

	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "centrauth_session", Value: token})
	rec = httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("dashboard with revoked session: got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
}
