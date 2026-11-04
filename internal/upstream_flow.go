package internal

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adamdlear/centrauth/internal/oauth"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/upstream"
)

const upstreamStateCookie = "centrauth_upstream"

type upstreamState struct {
	Provider      string `json:"provider"`
	State         string `json:"state"`
	ApplicationID int64  `json:"application_id"`
	ReturnTo      string `json:"return_to"`
	Verifier      string `json:"verifier,omitempty"`
	ExpiresAt     int64  `json:"expires_at"`
}

func (a *App) upstreamStartHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providerName := strings.ToLower(r.PathValue("provider"))
	if !upstream.IsSupported(providerName) {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "Unsupported identity provider")
		return
	}

	returnTo, ok := a.readAuthorizeRequest(r)
	if !ok {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "The authorization request has expired. Start again from the application.")
		return
	}

	parsed, err := url.Parse(returnTo)
	if err != nil {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "Invalid authorization request")
		return
	}
	clientID := parsed.Query().Get("client_id")

	client, err := a.clients.GetByClientID(ctx, clientID)
	if err != nil {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
		return
	}
	app, err := a.applications.GetByID(ctx, client.ApplicationID)
	if err != nil {
		a.logger.Error("upstream start: failed to load application", "application_id", client.ApplicationID, "error", err)
		a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to load application")
		return
	}

	record, secret, err := a.providers.Get(ctx, app.ID, providerName)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "This sign-in method is not configured for the app")
			return
		}
		a.logger.Error("upstream start: failed to load provider", "application_id", app.ID, "provider", providerName, "error", err)
		a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to load sign-in method")
		return
	}
	if !record.Enabled {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "This sign-in method is disabled for the app")
		return
	}

	redirectURL := strings.TrimRight(a.discovery.Issuer, "/") + "/auth/upstream/" + providerName + "/callback"
	config, err := a.providerFactory(providerName, record.ClientID, secret, redirectURL)
	if err != nil {
		a.logger.Error("upstream start: provider config error", "provider", providerName, "error", err)
		a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to start sign-in")
		return
	}

	state, err := oauth.GenerateAuthorizationCode()
	if err != nil {
		a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to start sign-in")
		return
	}

	verifier := ""
	challenge := ""
	if config.UsePKCE {
		verifier, err = oauth.GenerateAuthorizationCode()
		if err != nil {
			a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to start sign-in")
			return
		}
		challenge = oauth.PKCEChallenge(verifier)
	}

	payload := upstreamState{
		Provider:      providerName,
		State:         state,
		ApplicationID: app.ID,
		ReturnTo:      returnTo,
		Verifier:      verifier,
		ExpiresAt:     time.Now().Add(authorizeRequestTTL).Unix(),
	}
	if err := a.setUpstreamStateCookie(w, payload); err != nil {
		a.logger.Error("upstream start: failed to protect state", "error", err)
		a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to start sign-in")
		return
	}

	http.Redirect(w, r, upstream.NewClient(config).AuthCodeURL(state, challenge), http.StatusFound)
}

func (a *App) upstreamCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providerName := strings.ToLower(r.PathValue("provider"))
	if !upstream.IsSupported(providerName) {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "Unsupported identity provider")
		return
	}

	if upstreamErr := r.URL.Query().Get("error"); upstreamErr != "" {
		description := r.URL.Query().Get("error_description")
		a.logger.Warn("upstream sign-in denied", "provider", providerName, "error", upstreamErr)
		a.renderAuthorizeError(w, http.StatusBadRequest, "access_denied", description)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "Missing code or state from the provider")
		return
	}

	payload, err := a.readUpstreamStateCookie(r)
	if err != nil {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "Sign-in state is invalid or expired. Start again from the application.")
		return
	}
	if payload.Provider != providerName ||
		subtle.ConstantTimeCompare([]byte(payload.State), []byte(state)) != 1 ||
		time.Now().Unix() > payload.ExpiresAt {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "Sign-in state is invalid or expired. Start again from the application.")
		return
	}

	record, secret, err := a.providers.Get(ctx, payload.ApplicationID, providerName)
	if err != nil || !record.Enabled {
		a.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "This sign-in method is no longer available")
		return
	}

	redirectURL := strings.TrimRight(a.discovery.Issuer, "/") + "/auth/upstream/" + providerName + "/callback"
	config, err := a.providerFactory(providerName, record.ClientID, secret, redirectURL)
	if err != nil {
		a.logger.Error("upstream callback: provider config error", "provider", providerName, "error", err)
		a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to complete sign-in")
		return
	}

	identity, err := upstream.NewClient(config).Exchange(ctx, code, payload.Verifier)
	if err != nil {
		a.logger.Warn("upstream sign-in failed", "provider", providerName, "error", err)
		a.renderAuthorizeError(w, http.StatusBadRequest, "access_denied", "The provider could not verify your identity")
		return
	}

	user, err := a.providers.ProvisionUser(ctx, *identity)
	if err != nil {
		a.logger.Error("upstream callback: failed to provision user", "provider", providerName, "error", err)
		a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to create or load the user")
		return
	}

	token, err := a.sessions.Create(ctx, user.ID)
	if err != nil {
		a.logger.Error("upstream callback: failed to create session", "error", err)
		a.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "Unable to create a session")
		return
	}
	a.sessions.SetCookie(w, token)
	a.clearUpstreamCookies(w)

	a.logger.Info("upstream sign-in succeeded", "provider", providerName, "user_id", user.ID)

	// Resume the original authorization request. The authorize handler will
	// now see the new session and issue an authorization code.
	http.Redirect(w, r, payload.ReturnTo, http.StatusSeeOther)
}

func (a *App) setUpstreamStateCookie(w http.ResponseWriter, payload upstreamState) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	encrypted, err := a.secrets.Encrypt(data)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     upstreamStateCookie,
		Value:    base64.RawURLEncoding.EncodeToString(encrypted),
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(a.discovery.Issuer, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(authorizeRequestTTL.Seconds()),
	})
	return nil
}

func (a *App) readUpstreamStateCookie(r *http.Request) (upstreamState, error) {
	cookie, err := r.Cookie(upstreamStateCookie)
	if err != nil {
		return upstreamState{}, err
	}
	encrypted, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return upstreamState{}, err
	}
	data, err := a.secrets.Decrypt(encrypted)
	if err != nil {
		return upstreamState{}, err
	}
	var payload upstreamState
	if err := json.Unmarshal(data, &payload); err != nil {
		return upstreamState{}, err
	}
	if payload.ReturnTo == "" || !strings.HasPrefix(payload.ReturnTo, "/authorize?") {
		return upstreamState{}, errors.New("invalid return target")
	}
	return payload, nil
}

func (a *App) clearUpstreamCookies(w http.ResponseWriter) {
	for _, name := range []string{upstreamStateCookie, authorizePromptCookie} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   strings.HasPrefix(a.discovery.Issuer, "https://"),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}
