package internal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestApp() *App {
	return &App{templates: newTemplates()}
}

func TestHealthRoute(t *testing.T) {
	app := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestLoginPageRenders(t *testing.T) {
	app := newTestApp()

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
	app := newTestApp()

	req := httptest.NewRequest(http.MethodPost, "/auth/register", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRoutesAllowSameOriginPost(t *testing.T) {
	app := newTestApp()

	req := httptest.NewRequest(http.MethodPost, "/auth/register", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
}
