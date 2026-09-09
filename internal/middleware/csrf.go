package middleware

import "net/http"

func CSRF(next http.Handler) http.Handler {
	return http.NewCrossOriginProtection().Handler(next)
}
