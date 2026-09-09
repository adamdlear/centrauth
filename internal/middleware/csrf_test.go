package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRF(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRF(next)

	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{
			name:    "cross-site POST rejected",
			method:  http.MethodPost,
			headers: map[string]string{"Sec-Fetch-Site": "cross-site"},
			want:    http.StatusForbidden,
		},
		{
			name:    "same-site POST rejected",
			method:  http.MethodPost,
			headers: map[string]string{"Sec-Fetch-Site": "same-site"},
			want:    http.StatusForbidden,
		},
		{
			name:    "same-origin POST allowed",
			method:  http.MethodPost,
			headers: map[string]string{"Sec-Fetch-Site": "same-origin"},
			want:    http.StatusOK,
		},
		{
			name:    "top-level navigation POST allowed",
			method:  http.MethodPost,
			headers: map[string]string{"Sec-Fetch-Site": "none"},
			want:    http.StatusOK,
		},
		{
			name:    "mismatched Origin rejected",
			method:  http.MethodPost,
			headers: map[string]string{"Origin": "https://evil.example"},
			want:    http.StatusForbidden,
		},
		{
			name:    "Origin matching Host allowed",
			method:  http.MethodPost,
			headers: map[string]string{"Origin": "http://example.com"},
			want:    http.StatusOK,
		},
		{
			name:   "POST without origin headers allowed",
			method: http.MethodPost,
			want:   http.StatusOK,
		},
		{
			name:    "cross-site GET allowed",
			method:  http.MethodGet,
			headers: map[string]string{"Sec-Fetch-Site": "cross-site"},
			want:    http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://example.com/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("got status %d, want %d", rec.Code, tt.want)
			}
		})
	}
}
