package internal

import (
	"errors"
	"net/http"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/service"
)

type setupPageData struct {
	Title string
	Error string
}

func (a *App) setupPageHandler(w http.ResponseWriter, r *http.Request) {
	if !a.setupAvailable(w, r) {
		return
	}
	a.renderSetup(w, setupPageData{Title: "Setup"})
}

func (a *App) setupHandler(w http.ResponseWriter, r *http.Request) {
	if !a.setupAvailable(w, r) {
		return
	}

	ctx := r.Context()
	email := r.FormValue("email")
	pwd := r.FormValue("password")
	conf := r.FormValue("password_confirm")

	if pwd != conf {
		a.renderSetup(w, setupPageData{Title: "Setup", Error: "Passwords must match"})
		return
	}

	pwdHash, err := service.HashPassword(pwd, &service.DefaultPasswordHashParams)
	if err != nil {
		a.logger.Error("failed to hash operator password", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	created, err := a.operators.CreateFirstOperator(ctx, &db.Operator{
		Email:        email,
		PasswordHash: pwdHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		if errors.Is(err, repository.ErrSeatTaken) {
			a.logger.Warn("setup attempted after operator already exists")
			http.Redirect(w, r, "/admin/login", http.StatusTemporaryRedirect)
			return
		}
		a.logger.Error("failed to create first operator", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	a.logger.Info("setup completed", "operator_id", created.ID)

	token, err := a.operatorSessions.Create(ctx, created.ID)
	if err != nil {
		a.logger.Error("failed to create operator session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	a.operatorSessions.SetCookie(w, token)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *App) setupAvailable(w http.ResponseWriter, r *http.Request) bool {
	count, err := a.operators.Count(r.Context())
	if err != nil {
		a.logger.Error("failed to count operators", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return false
	}
	if count >= 1 {
		http.Redirect(w, r, "/admin/login", http.StatusTemporaryRedirect)
		return false
	}
	return true
}

func (a *App) renderSetup(w http.ResponseWriter, data setupPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.Setup.ExecuteTemplate(w, "setup.html", data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
