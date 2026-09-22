package internal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	app, _, _, _, _, _, _, _ := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	app.routes().ServeHTTP(rr, req)

	resp := rr.Result()
	defer resp.Body.Close()

	if status := rr.Code; status != http.StatusServiceUnavailable {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusServiceUnavailable)
	}

	expectedHeader := "application/json"
	if contentType := rr.Header().Get("Content-Type"); contentType != expectedHeader {
		t.Errorf("handler returned wrong content type: got %v want %v", contentType, expectedHeader)
	}

	expectedBody := `{"status":"unavailable"}`
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	if string(body) != expectedBody {
		t.Errorf("Expected '%s', got %s", expectedBody, string(body))
	}
}
