package internal

import (
	"net/http"

	"github.com/adamdlear/centrauth/internal/middleware"
)

func (a *App) rootHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

type dashboardPageData struct {
	Title string
	Email string
}

func (a *App) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	a.renderDashboard(w, dashboardPageData{Title: "Dashboard", Email: user.Email})
}

func (a *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := a.sessions.GetCookie(r); err == nil {
		if s, verr := a.sessions.Validate(r.Context(), cookie.Value); verr == nil {
			_ = a.sessions.Revoke(r.Context(), s.ID)
		}
	}
	a.sessions.ClearCookie(w)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) renderDashboard(w http.ResponseWriter, data dashboardPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.dashboard.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
