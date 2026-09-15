package internal

import (
	"net/http"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/middleware"
)

func (a *App) rootHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

type dashboardPageData struct {
	Title   string
	Email   string
	Clients []db.OAuthClient
}

func (a *App) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user := middleware.UserFromContext(ctx)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	clients, err := a.clients.List(ctx)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	a.renderDashboard(w, dashboardPageData{Title: "Dashboard", Email: user.Email, Clients: clients})
}

func (a *App) renderDashboard(w http.ResponseWriter, data dashboardPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.dashboard.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
