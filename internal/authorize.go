package internal

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/middleware"
	"github.com/adamdlear/centrauth/internal/oauth"
	"github.com/adamdlear/centrauth/internal/repository"
)

const (
	authorizePromptCookie = "centrauth_authz"
	authorizeRequestTTL   = 10 * time.Minute
)

type authorizeErrorPageData struct {
	Title   string
	Code    string
	Message string
}

type authorizeProviderButton struct {
	Name  string
	Label string
}

type authorizePromptPageData struct {
	Title     string
	AppName   string
	ClientID  string
	Providers []authorizeProviderButton
}

func (a *App) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := oauth.ParseAuthorizeRequest(r.URL.Query())

	if req.ClientID == "" {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	if req.RedirectURI == "" {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}

	client, err := a.clients.GetByClientID(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
			return
		}
		a.logger.Error("authorize: failed to load client", "error", err)
		a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to process the authorization request")
		return
	}

	// Never redirect to an unregistered URI: it may be attacker-controlled.
	if !oauth.IsRedirectURIAllowed(client, req.RedirectURI) {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered for this client")
		return
	}

	if apErr := req.Validate(); apErr != nil {
		a.redirectAuthorizeError(w, r, req, apErr)
		return
	}

	app, err := a.applications.GetByID(ctx, client.ApplicationID)
	if err != nil {
		a.logger.Error("authorize: failed to load application", "application_id", client.ApplicationID, "error", err)
		a.redirectAuthorizeError(w, r, req, &oauth.AuthorizeError{Code: "server_error", Description: "Unable to load application"})
		return
	}

	if !oauth.ValidateRequestedScopes(app, req.Scope) {
		a.redirectAuthorizeError(w, r, req, &oauth.AuthorizeError{
			Code:        "invalid_scope",
			Description: "One or more requested scopes are not allowed for this application",
		})
		return
	}

	user := middleware.UserFromContext(ctx)
	if user == nil {
		providers, err := a.promptsForApp(ctx, app.ID)
		if err != nil {
			a.logger.Error("authorize: failed to load providers", "application_id", app.ID, "error", err)
			a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to load sign-in methods")
			return
		}

		a.storeAuthorizeRequest(w, r)
		a.renderPage(w, http.StatusOK, "authorize_prompt.html", authorizePromptPageData{
			Title:     "Continue to " + app.Name,
			AppName:   app.Name,
			ClientID:  client.ClientID,
			Providers: providers,
		})
		return
	}

	rawCode, err := oauth.GenerateAuthorizationCode()
	if err != nil {
		a.logger.Error("authorize: failed to generate code", "error", err)
		a.redirectAuthorizeError(w, r, req, &oauth.AuthorizeError{Code: "server_error", Description: "Unable to issue authorization code"})
		return
	}

	var nonce *string
	if req.Nonce != "" {
		nonce = &req.Nonce
	}

	code := &db.OAuthAuthorizationCode{
		CodeHash:            oauth.HashAuthorizationCode(rawCode),
		OAuthClientID:       client.ID,
		UserID:              user.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Nonce:               nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(oauth.AuthorizationCodeTTL),
	}
	if _, err := a.codes.Create(ctx, code); err != nil {
		a.logger.Error("authorize: failed to store code", "error", err)
		a.redirectAuthorizeError(w, r, req, &oauth.AuthorizeError{Code: "server_error", Description: "Unable to issue authorization code"})
		return
	}

	a.logger.Info("authorization code issued", "client_id", client.ClientID, "user_id", user.ID)

	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is invalid")
		return
	}
	query := redirectURL.Query()
	query.Set("code", rawCode)
	query.Set("state", req.State)
	redirectURL.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (a *App) redirectAuthorizeError(w http.ResponseWriter, r *http.Request, req oauth.AuthorizeRequest, apErr *oauth.AuthorizeError) {
	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil {
		a.renderAuthorizeError(w, http.StatusBadRequest, apErr.Code, apErr.Description)
		return
	}
	query := redirectURL.Query()
	query.Set("error", apErr.Code)
	query.Set("error_description", apErr.Description)
	if req.State != "" {
		query.Set("state", req.State)
	}
	redirectURL.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (a *App) promptsForApp(ctx context.Context, applicationID int64) ([]authorizeProviderButton, error) {
	records, err := a.providers.List(ctx, applicationID)
	if err != nil {
		return nil, err
	}

	buttons := make([]authorizeProviderButton, 0, len(records))
	for _, record := range records {
		if !record.Enabled {
			continue
		}
		buttons = append(buttons, authorizeProviderButton{
			Name:  record.Provider,
			Label: providerLabel(record.Provider),
		})
	}
	return buttons, nil
}

func providerLabel(provider string) string {
	switch provider {
	case "google":
		return "Continue with Google"
	case "github":
		return "Continue with GitHub"
	default:
		return "Continue with " + provider
	}
}

func (a *App) storeAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	encrypted, err := a.secrets.Encrypt([]byte(r.URL.RequestURI()))
	if err != nil {
		a.logger.Error("authorize: failed to protect pending request", "error", err)
		return
	}
	value := base64.RawURLEncoding.EncodeToString(encrypted)
	http.SetCookie(w, &http.Cookie{
		Name:     authorizePromptCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(a.discovery.Issuer, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(authorizeRequestTTL.Seconds()),
	})
}

func (a *App) readAuthorizeRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(authorizePromptCookie)
	if err != nil {
		return "", false
	}
	encrypted, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", false
	}
	plaintext, err := a.secrets.Decrypt(encrypted)
	if err != nil {
		return "", false
	}
	returnTo := string(plaintext)
	if !strings.HasPrefix(returnTo, "/authorize?") {
		return "", false
	}
	return returnTo, true
}

func (a *App) renderAuthorizeError(w http.ResponseWriter, status int, code, message string) {
	a.renderPage(w, status, "authorize_error.html", authorizeErrorPageData{
		Title:   "Authorization error",
		Code:    code,
		Message: message,
	})
}

func (a *App) renderPage(w http.ResponseWriter, status int, page string, data any) {
	tpl := a.templates.Get(page)
	if tpl == nil {
		a.logger.Error("template not registered", "page", page)
		http.Error(w, fmt.Sprintf("template %q not found", page), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := tpl.ExecuteTemplate(w, page, data); err != nil {
		a.logger.Error("failed to render template", "page", page, "error", err)
	}
}
