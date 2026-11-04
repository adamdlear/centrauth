// Package upstream implements the provider side of brokered sign-in. centrauth
// acts as an OAuth client to Google and GitHub.
package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	oidcclient "github.com/coreos/go-oidc/v3/oidc"
)

// SupportedProviders are the upstream providers that can be configured per app.
var SupportedProviders = []string{"google", "github"}

func IsSupported(provider string) bool {
	for _, p := range SupportedProviders {
		if p == provider {
			return true
		}
	}
	return false
}

// Config describes one upstream provider registration.
type Config struct {
	Name         string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	EmailsURL    string
	Issuer       string
	Scopes       []string
	UsePKCE      bool
	OIDC         bool
}

// ConfigFor returns the endpoint configuration for a supported provider.
func ConfigFor(name, clientID, clientSecret, redirectURL string) (Config, error) {
	switch name {
	case "google":
		return Config{
			Name:         name,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			Issuer:       "https://accounts.google.com",
			Scopes:       []string{"openid", "email", "profile"},
			UsePKCE:      true,
			OIDC:         true,
		}, nil
	case "github":
		return Config{
			Name:         name,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			AuthURL:      "https://github.com/login/oauth/authorize",
			TokenURL:     "https://github.com/login/oauth/access_token",
			UserInfoURL:  "https://api.github.com/user",
			EmailsURL:    "https://api.github.com/user/emails",
			Scopes:       []string{"read:user", "user:email"},
			UsePKCE:      false,
			OIDC:         false,
		}, nil
	default:
		return Config{}, fmt.Errorf("unsupported identity provider %q", name)
	}
}

// Identity is the normalized provider identity returned after a successful
// upstream sign-in.
type Identity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

type Client struct {
	config Config
	http   *http.Client
}

func NewClient(config Config) *Client {
	return &Client{
		config: config,
		http:   &http.Client{Timeout: 15 * time.Second},
	}
}

// AuthCodeURL builds the upstream authorization URL.
func (c *Client) AuthCodeURL(state, codeChallenge string) string {
	query := url.Values{
		"client_id":     {c.config.ClientID},
		"redirect_uri":  {c.config.RedirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(c.config.Scopes, " ")},
		"state":         {state},
	}
	if c.config.UsePKCE && codeChallenge != "" {
		query.Set("code_challenge", codeChallenge)
		query.Set("code_challenge_method", "S256")
	}
	return c.config.AuthURL + "?" + query.Encode()
}

// Exchange swaps the upstream authorization code for an identity.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier string) (*Identity, error) {
	if c.config.OIDC {
		return c.exchangeOIDC(ctx, code, codeVerifier)
	}
	return c.exchangeGitHub(ctx, code, codeVerifier)
}

func (c *Client) exchangeOIDC(ctx context.Context, code, codeVerifier string) (*Identity, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {c.config.ClientID},
		"client_secret": {c.config.ClientSecret},
		"redirect_uri":  {c.config.RedirectURL},
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := c.postForm(ctx, c.config.TokenURL, form, &tokenResponse); err != nil {
		return nil, fmt.Errorf("exchange upstream code: %w", err)
	}
	if tokenResponse.IDToken == "" {
		return nil, errors.New("upstream token response did not include an id_token")
	}

	provider, err := oidcclient.NewProvider(ctx, c.config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover upstream OIDC provider: %w", err)
	}
	idToken, err := provider.Verifier(&oidcclient.Config{ClientID: c.config.ClientID}).Verify(ctx, tokenResponse.IDToken)
	if err != nil {
		return nil, fmt.Errorf("verify upstream id_token: %w", err)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode upstream claims: %w", err)
	}

	return &Identity{
		Provider:      c.config.Name,
		Subject:       idToken.Subject,
		Email:         strings.TrimSpace(claims.Email),
		EmailVerified: claims.EmailVerified,
		Name:          strings.TrimSpace(claims.Name),
	}, nil
}

func (c *Client) exchangeGitHub(ctx context.Context, code, codeVerifier string) (*Identity, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {c.config.ClientID},
		"client_secret": {c.config.ClientSecret},
		"redirect_uri":  {c.config.RedirectURL},
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.postForm(ctx, c.config.TokenURL, form, &tokenResponse); err != nil {
		return nil, fmt.Errorf("exchange upstream code: %w", err)
	}
	if tokenResponse.AccessToken == "" {
		return nil, errors.New("upstream token response did not include an access_token")
	}

	var profile struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := c.getJSON(ctx, c.config.UserInfoURL, tokenResponse.AccessToken, &profile); err != nil {
		return nil, fmt.Errorf("fetch upstream profile: %w", err)
	}
	if profile.ID == 0 {
		return nil, errors.New("upstream profile did not include an id")
	}

	email := strings.TrimSpace(profile.Email)
	verified := false
	if c.config.EmailsURL != "" {
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := c.getJSON(ctx, c.config.EmailsURL, tokenResponse.AccessToken, &emails); err == nil {
			for _, candidate := range emails {
				if candidate.Verified && (candidate.Primary || email == "") {
					email = candidate.Email
					verified = true
					if candidate.Primary {
						break
					}
				}
			}
		}
	}

	name := strings.TrimSpace(profile.Name)
	if name == "" {
		name = profile.Login
	}

	return &Identity{
		Provider:      c.config.Name,
		Subject:       strconv.FormatInt(profile.ID, 10),
		Email:         email,
		EmailVerified: verified,
		Name:          name,
	}, nil
}

func (c *Client) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "centrauth")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upstream token endpoint returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) getJSON(ctx context.Context, endpoint, accessToken string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "centrauth")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upstream endpoint returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
