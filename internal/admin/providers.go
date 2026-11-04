package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/middleware"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/service"
	"github.com/adamdlear/centrauth/internal/upstream"
)

type providerView struct {
	Provider  string
	ClientID  string
	Enabled   bool
	SecretSet bool
}

func providerViews(records []db.IdentityProvider) []providerView {
	views := make([]providerView, 0, len(records))
	for _, record := range records {
		views = append(views, providerView{
			Provider:  record.Provider,
			ClientID:  record.ClientID,
			Enabled:   record.Enabled,
			SecretSet: len(record.ClientSecretEncrypted) > 0,
		})
	}
	return views
}

type providerFormPageData struct {
	Title       string
	Email       string
	Error       string
	Errors      map[string]string
	App         appView
	Provider    string
	ClientID    string
	Enabled     bool
	IsEdit      bool
	SecretIsSet bool
	Providers   []string
}

func (h *Handler) providerNewHandler(w http.ResponseWriter, r *http.Request) {
	operator := middleware.OperatorFromContext(r.Context())
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	app, ok := h.loadApp(w, r)
	if !ok {
		return
	}

	h.renderProviderForm(w, http.StatusOK, providerFormPageData{
		Title:     "Add identity provider",
		Email:     operator.Email,
		App:       appViewFromModel(app, 0),
		Provider:  "google",
		Enabled:   true,
		Errors:    map[string]string{},
		Providers: upstream.SupportedProviders,
	})
}

func (h *Handler) providerEditHandler(w http.ResponseWriter, r *http.Request) {
	operator := middleware.OperatorFromContext(r.Context())
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	app, ok := h.loadApp(w, r)
	if !ok {
		return
	}

	provider := strings.ToLower(r.PathValue("provider"))
	records, err := h.providers.List(r.Context(), app.ID)
	if err != nil {
		h.logger.Error("failed to list providers", "application_id", app.ID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	for _, record := range records {
		if record.Provider == provider {
			h.renderProviderForm(w, http.StatusOK, providerFormPageData{
				Title:       "Edit " + provider,
				Email:       operator.Email,
				App:         appViewFromModel(app, 0),
				Provider:    record.Provider,
				ClientID:    record.ClientID,
				Enabled:     record.Enabled,
				IsEdit:      true,
				SecretIsSet: len(record.ClientSecretEncrypted) > 0,
				Errors:      map[string]string{},
				Providers:   upstream.SupportedProviders,
			})
			return
		}
	}

	http.NotFound(w, r)
}

func (h *Handler) providerSaveHandler(w http.ResponseWriter, r *http.Request) {
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

	input := service.ProviderInput{
		Provider:     r.FormValue("provider"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		Enabled:      r.FormValue("enabled") != "",
	}

	isEdit := r.FormValue("is_edit") == "true"

	if err := h.providers.Upsert(ctx, app.ID, input); err != nil {
		var verr *service.ValidationError
		if errors.As(err, &verr) {
			h.renderProviderForm(w, http.StatusBadRequest, providerFormPageData{
				Title:       providerFormTitle(input.Provider, isEdit),
				Email:       operator.Email,
				Error:       "Fix the errors below and try again.",
				Errors:      verr.Fields,
				App:         appViewFromModel(app, 0),
				Provider:    strings.ToLower(strings.TrimSpace(input.Provider)),
				ClientID:    input.ClientID,
				Enabled:     input.Enabled,
				IsEdit:      isEdit,
				SecretIsSet: input.ClientSecret == "",
				Providers:   upstream.SupportedProviders,
			})
			return
		}
		h.logger.Error("failed to save identity provider", "application_id", app.ID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("identity provider saved", "application_id", app.ID, "provider", input.Provider)
	http.Redirect(w, r, "/admin/apps/"+r.PathValue("id"), http.StatusSeeOther)
}

func (h *Handler) providerToggleHandler(w http.ResponseWriter, r *http.Request) {
	operator := middleware.OperatorFromContext(r.Context())
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	app, ok := h.loadApp(w, r)
	if !ok {
		return
	}
	provider := strings.ToLower(r.PathValue("provider"))

	records, err := h.providers.List(r.Context(), app.ID)
	if err != nil {
		h.logger.Error("failed to list providers", "application_id", app.ID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	for _, record := range records {
		if record.Provider == provider {
			if err := h.providers.SetEnabled(r.Context(), app.ID, provider, !record.Enabled); err != nil {
				h.logger.Error("failed to toggle provider", "application_id", app.ID, "provider", provider, "error", err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/apps/"+r.PathValue("id"), http.StatusSeeOther)
			return
		}
	}
	http.NotFound(w, r)
}

func (h *Handler) providerDeleteHandler(w http.ResponseWriter, r *http.Request) {
	operator := middleware.OperatorFromContext(r.Context())
	if operator == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	app, ok := h.loadApp(w, r)
	if !ok {
		return
	}
	provider := strings.ToLower(r.PathValue("provider"))

	if err := h.providers.Delete(r.Context(), app.ID, provider); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		h.logger.Error("failed to delete provider", "application_id", app.ID, "provider", provider, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("identity provider removed", "application_id", app.ID, "provider", provider)
	http.Redirect(w, r, "/admin/apps/"+r.PathValue("id"), http.StatusSeeOther)
}

func providerFormTitle(provider string, isEdit bool) string {
	provider = strings.TrimSpace(provider)
	if isEdit {
		return "Edit " + provider
	}
	return "Add identity provider"
}

func (h *Handler) renderProviderForm(w http.ResponseWriter, status int, data providerFormPageData) {
	h.renderStatus(w, status, "provider_form.html", data)
}
