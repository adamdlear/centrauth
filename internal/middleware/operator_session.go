package middleware

import (
	"context"
	"net/http"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/session"
)

type operatorContextKey string

const operatorKey operatorContextKey = "operator"

func OperatorSession(next http.Handler, manager *session.OperatorManager, operators repository.OperatorRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := manager.GetCookie(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		s, err := manager.Validate(r.Context(), cookie.Value)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		operator, err := operators.GetByID(r.Context(), s.OperatorID)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), operatorKey, &operator)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RequireOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if OperatorFromContext(r.Context()) == nil {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func OperatorFromContext(ctx context.Context) *db.Operator {
	o, _ := ctx.Value(operatorKey).(*db.Operator)
	return o
}
