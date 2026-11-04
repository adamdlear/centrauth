package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/middleware"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/service"
)

type appView struct {
	ID          int64
	Name        string
	Description string
	FirstParty  bool
	Scopes      []string
	Created     string
	ClientCount int
}

type clientView struct {
	ID                     int64
	ApplicationID          int64
	ClientID               string
	Type                   string
	AuthMethod             string
	Environment            string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	AllowedOrigins         []string
	Created                string
}

type envView struct {
	Name  string
	Count int
}

type appDetailPageData struct {
	Title   string
	Email   string
	App     appView
	Clients []clientView
	Envs    []envView
}

type clientNewPageData struct {
	Title                  string
	Email                  string
	Error                  string
	Errors                 map[string]string
	App                    appView
	ClientType             string
	Environment            string
	RedirectURIs           string
	PostLogoutRedirectURIs string
	AllowedOrigins         string
}

type clientRegisteredPageData struct {
	Title        string
	Email        string
	App          appView
	Client       clientView
	ClientSecret string
}

type clientDetailPageData struct {
	Title  string
	Email  string
	App    appView
	Client clientView
}

func (h *Handler) appDetailHandler(w http.ResponseWriter, r *http.Request) {
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

	clients, err := h.clients.ListByApplicationID(ctx, app.ID)
	if err != nil {
		h.logger.Error("failed to load clients", "application_id", app.ID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	data := buildAppDetailPageData(app, clients)
	data.Email = operator.Email
	h.render(w, "clients.html", data)
}

func (h *Handler) clientNewHandler(w http.ResponseWriter, r *http.Request) {
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

	h.renderClientNew(w, http.StatusOK, clientNewPageData{
		Title:       "Add client to " + app.Name,
		Email:       operator.Email,
		App:         appViewFromModel(app, 0),
		ClientType:  "confidential",
		Environment: "local",
		Errors:      map[string]string{},
	})
}

func (h *Handler) clientCreateHandler(w http.ResponseWriter, r *http.Request) {
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

	input := service.ClientInput{
		ClientType:             r.FormValue("client_type"),
		RedirectURIs:           splitLines(r.FormValue("redirect_uris")),
		PostLogoutRedirectURIs: splitLines(r.FormValue("post_logout_redirect_uris")),
		AllowedOrigins:         splitLines(r.FormValue("allowed_origins")),
		Environment:            r.FormValue("environment"),
	}

	output, err := h.apps.CreateClient(ctx, app.ID, input)
	if err != nil {
		var verr *service.ValidationError
		if errors.As(err, &verr) {
			h.renderClientNew(w, http.StatusBadRequest, clientNewPageData{
				Title:                  "Add client to " + app.Name,
				Email:                  operator.Email,
				Error:                  "Fix the errors below and try again.",
				Errors:                 verr.Fields,
				App:                    appViewFromModel(app, 0),
				ClientType:             input.ClientType,
				Environment:            input.Environment,
				RedirectURIs:           strings.Join(input.RedirectURIs, "\n"),
				PostLogoutRedirectURIs: strings.Join(input.PostLogoutRedirectURIs, "\n"),
				AllowedOrigins:         strings.Join(input.AllowedOrigins, "\n"),
			})
			return
		}
		h.logger.Error("failed to create client", "application_id", app.ID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("client created", "application_id", app.ID, "client_id", output.Client.ClientID)

	w.Header().Set("Cache-Control", "no-store")
	h.render(w, "client_registered.html", clientRegisteredPageData{
		Title:        "Client registered",
		Email:        operator.Email,
		App:          appViewFromModel(app, 0),
		Client:       clientViewFromModel(output.Client),
		ClientSecret: output.ClientSecret,
	})
}

func (h *Handler) clientDetailHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	operator := middleware.OperatorFromContext(ctx)
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return
	}

	client, err := h.clients.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		h.logger.Error("failed to load client", "client_id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	app, err := h.applications.GetByID(ctx, client.ApplicationID)
	if err != nil {
		h.logger.Error("failed to load application for client", "application_id", client.ApplicationID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.render(w, "client_detail.html", clientDetailPageData{
		Title:  client.ClientID,
		Email:  operator.Email,
		App:    appViewFromModel(app, 0),
		Client: clientViewFromModel(client),
	})
}

func buildAppDetailPageData(app db.Application, clients []db.OAuthClient) appDetailPageData {
	clientViews := make([]clientView, 0, len(clients))
	envCounts := map[string]int{"local": 0, "staging": 0, "production": 0}
	for _, c := range clients {
		envCounts[c.Environment]++
		clientViews = append(clientViews, clientViewFromModel(c))
	}

	envs := make([]envView, 0, len(envCounts))
	for _, name := range []string{"local", "staging", "production"} {
		envs = append(envs, envView{Name: name, Count: envCounts[name]})
	}

	return appDetailPageData{
		Title:   app.Name,
		App:     appViewFromModel(app, len(clientViews)),
		Clients: clientViews,
		Envs:    envs,
	}
}

func appViewFromModel(app db.Application, clientCount int) appView {
	created := ""
	if !app.CreatedAt.IsZero() {
		created = app.CreatedAt.Format(time.DateOnly)
	}
	return appView{
		ID:          app.ID,
		Name:        app.Name,
		Description: app.Description,
		FirstParty:  app.FirstParty,
		Scopes:      []string(app.AllowedScopes),
		Created:     created,
		ClientCount: clientCount,
	}
}

func clientViewFromModel(c db.OAuthClient) clientView {
	created := ""
	if !c.CreatedAt.IsZero() {
		created = c.CreatedAt.Format(time.DateOnly)
	}
	return clientView{
		ID:                     c.ID,
		ApplicationID:          c.ApplicationID,
		ClientID:               c.ClientID,
		Type:                   c.ClientType,
		AuthMethod:             c.TokenEndpointAuthMethod,
		Environment:            c.Environment,
		RedirectURIs:           []string(c.RedirectURIs),
		PostLogoutRedirectURIs: []string(c.PostLogoutRedirectURIs),
		AllowedOrigins:         []string(c.AllowedOrigins),
		Created:                created,
	}
}

func (h *Handler) renderClientNew(w http.ResponseWriter, status int, data clientNewPageData) {
	h.renderStatus(w, status, "client_new.html", data)
}

func (h *Handler) render(w http.ResponseWriter, page string, data any) {
	h.renderStatus(w, http.StatusOK, page, data)
}

func (h *Handler) renderStatus(w http.ResponseWriter, status int, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	tpl := h.templates.Get(page)
	if tpl == nil {
		h.logger.Error("template not registered", "page", page)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if err := tpl.ExecuteTemplate(w, page, data); err != nil {
		h.logger.Error("failed to render template", "page", page, "error", err)
	}
}
