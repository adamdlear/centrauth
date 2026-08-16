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
	app := NewApp(testConfig())

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	app.server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
}
