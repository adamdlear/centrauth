package oauth

import (
	"net/url"
	"strings"
)

// AuthorizeRequest is the parsed query of a GET /authorize request.
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	State               string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func ParseAuthorizeRequest(query url.Values) AuthorizeRequest {
	return AuthorizeRequest{
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		ResponseType:        query.Get("response_type"),
		State:               query.Get("state"),
		Scope:               query.Get("scope"),
		Nonce:               query.Get("nonce"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
	}
}

// Scopes returns the requested scopes, splitting on whitespace.
func (r AuthorizeRequest) Scopes() []string {
	return strings.Fields(r.Scope)
}

func (r AuthorizeRequest) HasScope(scope string) bool {
	for _, s := range r.Scopes() {
		if s == scope {
			return true
		}
	}
	return false
}

// AuthorizeError is an OAuth error that can be returned to the client through
// the redirect URI.
type AuthorizeError struct {
	Code        string
	Description string
}

func (e *AuthorizeError) Error() string { return e.Code + ": " + e.Description }

// Validate checks the parts of the authorization request that do not require
// database lookups. Client and redirect URI validation must happen first,
// because errors may only be redirected to a trusted URI.
func (r AuthorizeRequest) Validate() *AuthorizeError {
	if r.ResponseType != "code" {
		return &AuthorizeError{
			Code:        "unsupported_response_type",
			Description: "only the authorization code flow is supported",
		}
	}
	if r.CodeChallenge == "" {
		return &AuthorizeError{Code: "invalid_request", Description: "code_challenge is required (PKCE)"}
	}
	if r.CodeChallengeMethod != "S256" {
		return &AuthorizeError{Code: "invalid_request", Description: "code_challenge_method must be S256"}
	}
	if len(r.CodeChallenge) < 43 || len(r.CodeChallenge) > 128 {
		return &AuthorizeError{Code: "invalid_request", Description: "code_challenge has an invalid length"}
	}
	if r.HasScope("openid") && r.Nonce == "" {
		return &AuthorizeError{Code: "invalid_request", Description: "nonce is required for OpenID Connect requests"}
	}
	if r.State == "" {
		return &AuthorizeError{Code: "invalid_request", Description: "state is required"}
	}
	return nil
}
