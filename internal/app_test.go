package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func testConfig() AppConfig {
	return AppConfig{}
}

func TestHealthRoute(t *testing.T) {
	app := NewApp(testConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	app.server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}
