package internal

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/oauth"
	"github.com/adamdlear/centrauth/internal/oidc"
	"github.com/adamdlear/centrauth/internal/repository"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token,omitempty"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (a *App) tokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		a.writeTokenError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		a.writeTokenError(w, http.StatusBadRequest, "invalid_request", "Malformed request body")
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType == "" {
		a.writeTokenError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		return
	}
	if grantType != "authorization_code" {
		a.writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Only authorization_code is supported")
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	basicClientID, basicSecret, hasBasic := r.BasicAuth()
	clientID := r.FormValue("client_id")
	if clientID == "" {
		clientID = basicClientID
	}

	switch {
	case code == "":
		a.writeTokenError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	case redirectURI == "":
		a.writeTokenError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	case codeVerifier == "":
		a.writeTokenError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required (PKCE)")
		return
	case clientID == "":
		a.writeTokenError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	client, err := a.clients.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			a.writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
			return
		}
		a.logger.Error("token: failed to load client", "error", err)
		a.writeTokenError(w, http.StatusInternalServerError, "server_error", "Unable to process the token request")
		return
	}

	if !a.authenticateTokenClient(w, r, client, clientID, basicClientID, basicSecret, hasBasic) {
		return
	}

	stored, err := a.codes.GetByCodeHash(ctx, oauth.HashAuthorizationCode(code))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			a.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code is invalid")
			return
		}
		a.logger.Error("token: failed to load authorization code", "error", err)
		a.writeTokenError(w, http.StatusInternalServerError, "server_error", "Unable to process the token request")
		return
	}

	if stored.OAuthClientID != client.ID {
		a.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code is invalid")
		return
	}
	if stored.ConsumedAt != nil {
		a.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code has already been used")
		return
	}
	if time.Now().After(stored.ExpiresAt) {
		a.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code has expired")
		return
	}

	// Consume first: a failed exchange must not leave the code reusable.
	if err := a.codes.Consume(ctx, stored.ID); err != nil {
		a.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code is invalid")
		return
	}

	if stored.RedirectURI != redirectURI {
		a.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if !oauth.VerifyPKCE(stored.CodeChallenge, codeVerifier, stored.CodeChallengeMethod) {
		a.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	accessToken, err := oauth.GenerateAccessToken()
	if err != nil {
		a.logger.Error("token: failed to generate access token", "error", err)
		a.writeTokenError(w, http.StatusInternalServerError, "server_error", "Unable to issue token")
		return
	}

	response := tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(a.idTokens.TTL().Seconds()),
	}

	if hasScope(stored.Scope, "openid") {
		user, err := a.users.GetByID(ctx, stored.UserID)
		if err != nil {
			a.logger.Error("token: failed to load user", "user_id", stored.UserID, "error", err)
			a.writeTokenError(w, http.StatusInternalServerError, "server_error", "Unable to issue ID token")
			return
		}

		authTime := stored.CreatedAt
		if authTime.IsZero() {
			authTime = time.Now()
		}

		nonce := ""
		if stored.Nonce != nil {
			nonce = *stored.Nonce
		}

		var email string
		if hasScope(stored.Scope, "email") {
			email = user.Email
		}

		idToken, err := a.idTokens.Issue(ctx, oidc.IssueParams{
			User:     &user,
			ClientID: client.ClientID,
			Nonce:    nonce,
			AuthTime: authTime,
			Email:    email,
		})
		if err != nil {
			a.logger.Error("token: failed to issue ID token", "error", err)
			a.writeTokenError(w, http.StatusInternalServerError, "server_error", "Unable to issue ID token")
			return
		}
		response.IDToken = idToken
	}

	a.logger.Info("authorization code exchanged", "client_id", client.ClientID, "user_id", stored.UserID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		a.logger.Error("token: failed to encode response", "error", err)
	}
}

func (a *App) authenticateTokenClient(w http.ResponseWriter, r *http.Request, client db.OAuthClient, clientID, basicClientID, basicSecret string, hasBasic bool) bool {
	if !oauth.IsConfidential(client) {
		return true
	}

	authenticated := false
	switch client.TokenEndpointAuthMethod {
	case "client_secret_basic":
		authenticated = hasBasic && basicClientID == client.ClientID && oauth.ValidateClientSecret(client, basicSecret)
	case "client_secret_post":
		authenticated = clientID == client.ClientID && oauth.ValidateClientSecret(client, r.FormValue("client_secret"))
	default:
		authenticated = false
	}

	if !authenticated {
		a.writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return false
	}
	return true
}

func hasScope(scopeParam, scope string) bool {
	for _, s := range strings.Fields(scopeParam) {
		if s == scope {
			return true
		}
	}
	return false
}

func (a *App) writeTokenError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(tokenErrorResponse{Error: code, ErrorDescription: description})
}
