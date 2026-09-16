package internal

import (
	"net/http"

	"github.com/adamdlear/centrauth/internal/middleware"
)

func (a *App) rootHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

type dashboardAppView struct {
	Name        string
	ClientCount int
}

type dashboardPageData struct {
	Title string
	Email string
	Apps  []dashboardAppView
}

func (a *App) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user := middleware.UserFromContext(ctx)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	apps, err := a.applications.List(ctx)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	clients, err := a.clients.List(ctx)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	clientCounts := make(map[int64]int, len(clients))
	for _, c := range clients {
		clientCounts[c.ApplicationID]++
	}

	views := make([]dashboardAppView, 0, len(apps))
	for _, app := range apps {
		views = append(views, dashboardAppView{Name: app.Name, ClientCount: clientCounts[app.ID]})
	}

	a.renderDashboard(w, dashboardPageData{Title: "Dashboard", Email: user.Email, Apps: views})
}

func (a *App) renderDashboard(w http.ResponseWriter, data dashboardPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.dashboard.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
