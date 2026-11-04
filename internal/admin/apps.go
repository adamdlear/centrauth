package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/middleware"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/service"
)

type appListItem struct {
	ID           int64
	Name         string
	Description  string
	FirstParty   bool
	Scopes       []string
	ClientCount  int
	Environments []string
	Created      string
}

type appListPageData struct {
	Title string
	Email string
	Apps  []appListItem
}

type appFormData struct {
	Title                  string
	Email                  string
	Error                  string
	Errors                 map[string]string
	Name                   string
	Description            string
	FirstParty             bool
	Scopes                 string
	ClientType             string
	RedirectURIs           string
	PostLogoutRedirectURIs string
	Environment            string
}

type appRegisteredPageData struct {
	Title        string
	Email        string
	App          appView
	Client       clientView
	ClientSecret string
}

func (h *Handler) appListHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	operator := middleware.OperatorFromContext(ctx)
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	apps, err := h.applications.List(ctx)
	if err != nil {
		h.logger.Error("failed to list applications", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	clients, err := h.clients.List(ctx)
	if err != nil {
		h.logger.Error("failed to list clients", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	byApp := make(map[int64][]db.OAuthClient, len(apps))
	for _, c := range clients {
		byApp[c.ApplicationID] = append(byApp[c.ApplicationID], c)
	}

	items := make([]appListItem, 0, len(apps))
	for _, app := range apps {
		appClients := byApp[app.ID]
		envSet := map[string]bool{}
		for _, c := range appClients {
			envSet[c.Environment] = true
		}
		envs := make([]string, 0, len(envSet))
		for _, name := range []string{"local", "staging", "production"} {
			if envSet[name] {
				envs = append(envs, name)
			}
		}
		created := ""
		if !app.CreatedAt.IsZero() {
			created = app.CreatedAt.Format("2006-01-02")
		}
		items = append(items, appListItem{
			ID:           app.ID,
			Name:         app.Name,
			Description:  app.Description,
			FirstParty:   app.FirstParty,
			Scopes:       []string(app.AllowedScopes),
			ClientCount:  len(appClients),
			Environments: envs,
			Created:      created,
		})
	}

	h.render(w, "app_list.html", appListPageData{
		Title: "Applications",
		Email: operator.Email,
		Apps:  items,
	})
}

func (h *Handler) appNewHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	operator := middleware.OperatorFromContext(ctx)
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	h.renderAppNew(w, http.StatusOK, appFormData{
		Title:       "Register application",
		Email:       operator.Email,
		FirstParty:  true,
		ClientType:  "confidential",
		Environment: "local",
		Errors:      map[string]string{},
	})
}

func (h *Handler) appCreateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	operator := middleware.OperatorFromContext(ctx)
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	input := service.RegisterAppInput{
		Name:          r.FormValue("name"),
		Description:   r.FormValue("description"),
		FirstParty:    r.FormValue("first_party") != "",
		AllowedScopes: strings.Fields(r.FormValue("allowed_scopes")),
		Client: service.ClientInput{
			ClientType:             r.FormValue("client_type"),
			RedirectURIs:           splitLines(r.FormValue("redirect_uris")),
			PostLogoutRedirectURIs: splitLines(r.FormValue("post_logout_redirect_uris")),
			Environment:            r.FormValue("environment"),
		},
	}

	output, err := h.apps.RegisterApp(ctx, input)
	if err != nil {
		var verr *service.ValidationError
		if errors.As(err, &verr) {
			h.renderAppNew(w, http.StatusBadRequest, appFormData{
				Title:                  "Register application",
				Email:                  operator.Email,
				Error:                  "Fix the errors below and try again.",
				Errors:                 verr.Fields,
				Name:                   input.Name,
				Description:            input.Description,
				FirstParty:             input.FirstParty,
				Scopes:                 strings.Join(input.AllowedScopes, " "),
				ClientType:             input.Client.ClientType,
				RedirectURIs:           strings.Join(input.Client.RedirectURIs, "\n"),
				PostLogoutRedirectURIs: strings.Join(input.Client.PostLogoutRedirectURIs, "\n"),
				Environment:            input.Client.Environment,
			})
			return
		}
		h.logger.Error("failed to register application", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("application registered", "application_id", output.App.ID, "client_id", output.Client.ClientID)

	w.Header().Set("Cache-Control", "no-store")
	h.render(w, "app_registered.html", appRegisteredPageData{
		Title:        "Application registered",
		Email:        operator.Email,
		App:          appViewFromModel(output.App, 1),
		Client:       clientViewFromModel(output.Client),
		ClientSecret: output.ClientSecret,
	})
}

func (h *Handler) appEditHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	operator := middleware.OperatorFromContext(ctx)
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	app, ok := h.loadApp(w, r)
	if !ok {
		return
	}

	h.renderAppEdit(w, http.StatusOK, appEditPageData{
		Title:       "Edit " + app.Name,
		Email:       operator.Email,
		AppID:       app.ID,
		Name:        app.Name,
		Description: app.Description,
		FirstParty:  app.FirstParty,
		Scopes:      strings.Join([]string(app.AllowedScopes), " "),
		Errors:      map[string]string{},
	})
}

func (h *Handler) appUpdateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	operator := middleware.OperatorFromContext(ctx)
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	app, ok := h.loadApp(w, r)
	if !ok {
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	input := service.AppMetadataInput{
		Name:          r.FormValue("name"),
		Description:   r.FormValue("description"),
		FirstParty:    r.FormValue("first_party") != "",
		AllowedScopes: strings.Fields(r.FormValue("allowed_scopes")),
	}

	updated, err := h.apps.UpdateApp(ctx, app, input)
	if err != nil {
		var verr *service.ValidationError
		if errors.As(err, &verr) {
			h.renderAppEdit(w, http.StatusBadRequest, appEditPageData{
				Title:       "Edit " + app.Name,
				Email:       operator.Email,
				AppID:       app.ID,
				Error:       "Fix the errors below and try again.",
				Errors:      verr.Fields,
				Name:        input.Name,
				Description: input.Description,
				FirstParty:  input.FirstParty,
				Scopes:      strings.Join(input.AllowedScopes, " "),
			})
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		h.logger.Error("failed to update application", "application_id", app.ID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/apps/"+strconv.FormatInt(updated.ID, 10), http.StatusSeeOther)
}

type appEditPageData struct {
	Title       string
	Email       string
	AppID       int64
	Error       string
	Errors      map[string]string
	Name        string
	Description string
	FirstParty  bool
	Scopes      string
}

func (h *Handler) loadApp(w http.ResponseWriter, r *http.Request) (db.Application, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return db.Application{}, false
	}

	app, err := h.applications.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			http.NotFound(w, r)
			return db.Application{}, false
		}
		h.logger.Error("failed to load application", "application_id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return db.Application{}, false
	}
	return app, true
}

func (h *Handler) renderAppNew(w http.ResponseWriter, status int, data appFormData) {
	h.renderStatus(w, status, "app_new.html", data)
}

func (h *Handler) renderAppEdit(w http.ResponseWriter, status int, data appEditPageData) {
	h.renderStatus(w, status, "app_edit.html", data)
}

func splitLines(raw string) []string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
