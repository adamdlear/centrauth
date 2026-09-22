package admin

import (
	"context"
	"net/http"

	"github.com/adamdlear/centrauth/internal/middleware"
)

type dashboardAppView struct {
	Name        string
	Description string
	Scopes      []string
	ClientCount int
	Created     string
}

type dashboardPageData struct {
	Title string
	Email string
	Error string
	Apps  []dashboardAppView
}

func (h *Handler) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	operator := middleware.OperatorFromContext(ctx)
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	data, err := h.dashboardData(ctx)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	data.Email = operator.Email

	h.renderDashboard(w, data)
}

func (h *Handler) dashboardData(ctx context.Context) (dashboardPageData, error) {
	apps, err := h.applications.List(ctx)
	if err != nil {
		return dashboardPageData{}, err
	}
	clients, err := h.clients.List(ctx)
	if err != nil {
		return dashboardPageData{}, err
	}

	clientCounts := make(map[int64]int, len(clients))
	for _, c := range clients {
		clientCounts[c.ApplicationID]++
	}

	views := make([]dashboardAppView, 0, len(apps))
	for _, app := range apps {
		created := ""
		if !app.CreatedAt.IsZero() {
			created = app.CreatedAt.Format("2006-01-02")
		}
		views = append(views, dashboardAppView{
			Name:        app.Name,
			Description: app.Description,
			Scopes:      []string(app.AllowedScopes),
			ClientCount: clientCounts[app.ID],
			Created:     created,
		})
	}

	return dashboardPageData{Title: "Dashboard", Apps: views}, nil
}

func (h *Handler) renderDashboard(w http.ResponseWriter, data dashboardPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.Dashboard.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
