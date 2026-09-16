package internal

import (
	"net/http"
	"strings"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/middleware"
	pq "github.com/lib/pq"
)

func (a *App) createAppHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user := middleware.UserFromContext(ctx)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))
	allowedScopes := strings.Fields(r.FormValue("allowed_scopes"))

	if name == "" {
		data, err := a.dashboardData(ctx)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		data.Email = user.Email
		data.Error = "App name is required"
		a.renderDashboard(w, data)
		return
	}

	if _, err := a.applications.Create(ctx, &db.Application{
		Name:          name,
		Description:   description,
		FirstParty:    true,
		AllowedScopes: pq.StringArray(allowedScopes),
	}); err != nil {
		a.logger.Error("failed to create application", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
