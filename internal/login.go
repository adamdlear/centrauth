package internal

import (
	"errors"
	"net/http"

	"github.com/adamdlear/centrauth/internal/service"
)

type loginPageData struct {
	Title string
	Error string
}

func (a *App) loginPageHandler(w http.ResponseWriter, r *http.Request) {
	a.renderLogin(w, loginPageData{Title: "Sign In"})
}

func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := r.FormValue("email")
	pwd := r.FormValue("password")

	user, err := a.login.VerifyUserWithEmailAndPassword(ctx, email, pwd)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			a.renderLogin(w, loginPageData{Title: "Sign In", Error: "Invalid email or password"})
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	token, err := a.sessions.Create(ctx, user.ID)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	a.sessions.SetCookie(w, token)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (a *App) registerHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) renderLogin(w http.ResponseWriter, data loginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.login.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
