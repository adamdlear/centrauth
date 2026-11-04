package middleware

import "net/http"

func CSRF(next http.Handler) http.Handler {
	return http.NewCrossOriginProtection().Handler(next)
}

// CSRFExcept applies cross-origin protection to every path except the given
// exempt paths. Server-to-server API endpoints such as /token are not browser
// form submissions and must not depend on the browser's Fetch Metadata
// headers.
func CSRFExcept(next http.Handler, exempt ...string) http.Handler {
	protected := http.NewCrossOriginProtection().Handler(next)
	skip := make(map[string]bool, len(exempt))
	for _, path := range exempt {
		skip[path] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if skip[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		protected.ServeHTTP(w, r)
	})
}
