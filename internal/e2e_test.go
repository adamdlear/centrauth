package internal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/oauth"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/service"
	"github.com/adamdlear/centrauth/internal/session"
	"github.com/adamdlear/centrauth/internal/signing"
	"github.com/adamdlear/centrauth/internal/upstream"
	oidcclient "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http/cookiejar"
)

const e2eVerifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG-e2e"

type e2eEnv struct {
	t            *testing.T
	server       *httptest.Server
	app          *App
	database     *db.DB
	provider     *oidcclient.Provider
	appModel     db.Application
	client       db.OAuthClient
	clientSecret string
	user         db.User
	sessionToken string
	redirectURI  string
}

func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()

	if os.Getenv("DB_HOST") == "" || os.Getenv("DB_DATABASE") == "" {
		t.Skip("DB_HOST/DB_DATABASE not set; skipping end-to-end tests")
	}

	port := 5432
	if p := os.Getenv("DB_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}

	database, err := db.New(db.DBConfig{
		Host:     os.Getenv("DB_HOST"),
		User:     os.Getenv("DB_USERNAME"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   os.Getenv("DB_DATABASE"),
		Port:     port,
	})
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	issuer := "http://" + listener.Addr().String()

	cfg := AppConfig{
		ServerConfig: ServerConfig{
			Addr:                  listener.Addr().String(),
			IssuerURL:             issuer,
			SigningKeyPath:        t.TempDir() + "/signing-key.pem",
			ProviderSecretKeyPath: t.TempDir() + "/provider-secret.key",
			IDTokenTTL:            10 * time.Minute,
		},
		DBConfig: db.DBConfig{
			Host:     os.Getenv("DB_HOST"),
			User:     os.Getenv("DB_USERNAME"),
			Password: os.Getenv("DB_PASSWORD"),
			DBName:   os.Getenv("DB_DATABASE"),
			Port:     port,
		},
		SessionConfig:         session.Config{CookieName: "centrauth_session", TTL: time.Hour},
		OperatorSessionConfig: session.Config{CookieName: "centrauth_operator", TTL: time.Hour},
	}

	app, err := NewApp(cfg, database)
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	server := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: app.routes()},
	}
	server.Start()
	t.Cleanup(server.Close)

	ctx := context.Background()
	provider, err := oidcclient.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("oidc discovery against test server: %v", err)
	}

	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)

	user := db.User{Subject: "e2e-subject-" + suffix, Email: "e2e-" + suffix + "@example.com"}
	if err := database.Client.Create(&user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	appService := service.NewAppService(
		repository.NewGormApplicationRepo(database.Client),
		repository.NewGormClientRepo(database.Client),
	)
	registered, err := appService.RegisterApp(ctx, service.RegisterAppInput{
		Name:          "E2E App " + suffix,
		FirstParty:    true,
		AllowedScopes: []string{"openid", "profile", "email"},
		Client: service.ClientInput{
			ClientType:   "confidential",
			RedirectURIs: []string{"https://app.example.com/callback"},
			Environment:  "production",
		},
	})
	if err != nil {
		t.Fatalf("register test app: %v", err)
	}

	token := randomToken(t)
	sum := sha256.Sum256([]byte(token))
	record := db.Session{TokenHash: sum[:], UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}
	if err := database.Client.Create(&record).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	t.Cleanup(func() {
		database.Client.Exec("DELETE FROM oauth_authorization_codes WHERE oauth_client_id = ?", registered.Client.ID)
		database.Client.Exec("DELETE FROM sessions WHERE user_id = ?", user.ID)
		database.Client.Exec("DELETE FROM applications WHERE id = ?", registered.App.ID)
		database.Client.Exec("DELETE FROM users WHERE id = ?", user.ID)
	})

	return &e2eEnv{
		t:            t,
		server:       server,
		app:          app,
		database:     database,
		provider:     provider,
		appModel:     registered.App,
		client:       registered.Client,
		clientSecret: registered.ClientSecret,
		user:         user,
		sessionToken: token,
		redirectURI:  "https://app.example.com/callback",
	}
}

func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type authorizeParams struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scope        string
	State        string
	Nonce        string
	Challenge    string
	Method       string
	WithSession  bool
}

func defaultAuthorizeParams(env *e2eEnv) authorizeParams {
	return authorizeParams{
		ClientID:     env.client.ClientID,
		RedirectURI:  env.redirectURI,
		ResponseType: "code",
		Scope:        "openid profile",
		State:        "state-e2e",
		Nonce:        "nonce-e2e",
		Challenge:    oauth.PKCEChallenge(e2eVerifier),
		Method:       "S256",
		WithSession:  true,
	}
}

func (env *e2eEnv) authorize(params authorizeParams) *http.Response {
	env.t.Helper()

	q := url.Values{
		"client_id":             {params.ClientID},
		"redirect_uri":          {params.RedirectURI},
		"response_type":         {params.ResponseType},
		"scope":                 {params.Scope},
		"state":                 {params.State},
		"nonce":                 {params.Nonce},
		"code_challenge":        {params.Challenge},
		"code_challenge_method": {params.Method},
	}
	req, err := http.NewRequest(http.MethodGet, env.server.URL+"/authorize?"+q.Encode(), nil)
	if err != nil {
		env.t.Fatalf("build authorize request: %v", err)
	}
	if params.WithSession {
		req.AddCookie(&http.Cookie{Name: "centrauth_session", Value: env.sessionToken})
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		env.t.Fatalf("authorize request: %v", err)
	}
	return resp
}

func (env *e2eEnv) authorizeWith(t *testing.T, client *http.Client, params authorizeParams) *http.Response {
	t.Helper()
	q := url.Values{
		"client_id":             {params.ClientID},
		"redirect_uri":          {params.RedirectURI},
		"response_type":         {params.ResponseType},
		"scope":                 {params.Scope},
		"state":                 {params.State},
		"nonce":                 {params.Nonce},
		"code_challenge":        {params.Challenge},
		"code_challenge_method": {params.Method},
	}
	resp, err := client.Get(env.server.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	return resp
}

func (env *e2eEnv) oauthConfig(secret string) *oauth2.Config {
	endpoint := env.provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	return &oauth2.Config{
		ClientID:     env.client.ClientID,
		ClientSecret: secret,
		Endpoint:     endpoint,
		RedirectURL:  env.redirectURI,
	}
}

func (env *e2eEnv) issueCode(t *testing.T, params authorizeParams) string {
	t.Helper()
	resp := env.authorize(params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d, want 302; body: %s", resp.StatusCode, body)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := location.Query().Get("state"); got != params.State {
		t.Errorf("state = %q, want %q", got, params.State)
	}
	if errCode := location.Query().Get("error"); errCode != "" {
		t.Fatalf("authorize returned error %q: %s", errCode, location.Query().Get("error_description"))
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("authorize redirect missing code")
	}
	return code
}

func TestCompleteOIDCFlow(t *testing.T) {
	env := newE2EEnv(t)

	resp := env.authorize(defaultAuthorizeParams(env))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d, want 302; body: %s", resp.StatusCode, body)
	}

	location, _ := url.Parse(resp.Header.Get("Location"))
	code := location.Query().Get("code")
	state := location.Query().Get("state")
	if code == "" || state != "state-e2e" {
		t.Fatalf("redirect code/state = %q/%q", code, state)
	}

	token, err := env.oauthConfig(env.clientSecret).Exchange(
		context.Background(),
		code,
		oauth2.SetAuthURLParam("code_verifier", e2eVerifier),
	)
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatal("token response missing id_token")
	}

	verifier := env.provider.Verifier(&oidcclient.Config{ClientID: env.client.ClientID})
	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		t.Fatalf("verify ID token with discovery + JWKS: %v", err)
	}

	if idToken.Subject != env.user.Subject {
		t.Errorf("sub = %q, want %q", idToken.Subject, env.user.Subject)
	}
	if idToken.Audience[0] != env.client.ClientID {
		t.Errorf("aud = %v, want %q", idToken.Audience, env.client.ClientID)
	}
	if idToken.Issuer != env.server.URL {
		t.Errorf("iss = %q, want %q", idToken.Issuer, env.server.URL)
	}
	if got := idToken.Nonce; got != "nonce-e2e" {
		t.Errorf("nonce = %q", got)
	}
	if time.Until(idToken.Expiry) <= 0 {
		t.Error("ID token is already expired")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	if _, ok := claims["auth_time"]; !ok {
		t.Error("ID token missing auth_time claim")
	}

	// The code is single use.
	_, err = env.oauthConfig(env.clientSecret).Exchange(
		context.Background(),
		code,
		oauth2.SetAuthURLParam("code_verifier", e2eVerifier),
	)
	if err == nil {
		t.Fatal("replaying the authorization code succeeded")
	}
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		var body map[string]string
		_ = json.Unmarshal(retrieveErr.Body, &body)
		if body["error"] != "invalid_grant" {
			t.Errorf("replay error = %q, want invalid_grant", body["error"])
		}
	}
}

func TestE2EUnknownClient(t *testing.T) {
	env := newE2EEnv(t)
	params := defaultAuthorizeParams(env)
	params.ClientID = "no-such-client"

	resp := env.authorize(params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestE2EUnregisteredRedirectURI(t *testing.T) {
	env := newE2EEnv(t)
	params := defaultAuthorizeParams(env)
	params.RedirectURI = "https://evil.example.com/callback"

	resp := env.authorize(params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("Location = %q, want no redirect", loc)
	}
}

func TestE2EAuthorizeErrorsRedirect(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*authorizeParams)
		wantError string
	}{
		{"missing pkce", func(p *authorizeParams) { p.Challenge = "" }, "invalid_request"},
		{"plain pkce", func(p *authorizeParams) { p.Method = "plain" }, "invalid_request"},
		{"missing nonce", func(p *authorizeParams) { p.Nonce = "" }, "invalid_request"},
		{"unsupported response type", func(p *authorizeParams) { p.ResponseType = "token" }, "unsupported_response_type"},
		{"invalid scope", func(p *authorizeParams) { p.Scope = "admin:all" }, "invalid_scope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newE2EEnv(t)
			params := defaultAuthorizeParams(env)
			tt.mutate(&params)

			resp := env.authorize(params)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("got status %d, want 302", resp.StatusCode)
			}
			location, _ := url.Parse(resp.Header.Get("Location"))
			if got := location.Query().Get("error"); got != tt.wantError {
				t.Errorf("error = %q, want %q", got, tt.wantError)
			}
		})
	}
}

func TestE2ENoSessionShowsPrompt(t *testing.T) {
	env := newE2EEnv(t)
	params := defaultAuthorizeParams(env)
	params.WithSession = false

	resp := env.authorize(params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "No sign-in method is configured") {
		t.Error("prompt missing placeholder message")
	}
}

func TestE2EInvalidPKCEVerifier(t *testing.T) {
	env := newE2EEnv(t)
	code := env.issueCode(t, defaultAuthorizeParams(env))

	_, err := env.oauthConfig(env.clientSecret).Exchange(
		context.Background(),
		code,
		oauth2.SetAuthURLParam("code_verifier", strings.Repeat("z", len(e2eVerifier))),
	)
	if err == nil {
		t.Fatal("exchange with a wrong verifier succeeded")
	}
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		var body map[string]string
		_ = json.Unmarshal(retrieveErr.Body, &body)
		if body["error"] != "invalid_grant" {
			t.Errorf("error = %q, want invalid_grant", body["error"])
		}
	}
}

func TestE2EExpiredCode(t *testing.T) {
	env := newE2EEnv(t)
	code := env.issueCode(t, defaultAuthorizeParams(env))

	hash := oauth.HashAuthorizationCode(code)
	if err := env.database.Client.Exec(
		"UPDATE oauth_authorization_codes SET expires_at = ? WHERE code_hash = ?",
		time.Now().Add(-time.Minute), hash,
	).Error; err != nil {
		t.Fatalf("expire code: %v", err)
	}

	_, err := env.oauthConfig(env.clientSecret).Exchange(
		context.Background(),
		code,
		oauth2.SetAuthURLParam("code_verifier", e2eVerifier),
	)
	if err == nil {
		t.Fatal("exchange with an expired code succeeded")
	}
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		var body map[string]string
		_ = json.Unmarshal(retrieveErr.Body, &body)
		if body["error"] != "invalid_grant" {
			t.Errorf("error = %q, want invalid_grant", body["error"])
		}
	}
}

func TestE2EWrongClientSecret(t *testing.T) {
	env := newE2EEnv(t)
	code := env.issueCode(t, defaultAuthorizeParams(env))

	_, err := env.oauthConfig("wrong-secret").Exchange(
		context.Background(),
		code,
		oauth2.SetAuthURLParam("code_verifier", e2eVerifier),
	)
	if err == nil {
		t.Fatal("exchange with a wrong client secret succeeded")
	}
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) {
		t.Fatalf("error type = %T, want *oauth2.RetrieveError", err)
	}
	if retrieveErr.Response.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", retrieveErr.Response.StatusCode)
	}
	if retrieveErr.ErrorCode != "invalid_client" {
		t.Errorf("error = %q, want invalid_client", retrieveErr.ErrorCode)
	}
}

func TestE2EPublicClientFlow(t *testing.T) {
	env := newE2EEnv(t)

	appService := service.NewAppService(
		repository.NewGormApplicationRepo(env.database.Client),
		repository.NewGormClientRepo(env.database.Client),
	)
	registered, err := appService.RegisterApp(context.Background(), service.RegisterAppInput{
		Name:          "E2E Public App " + env.user.Subject,
		AllowedScopes: []string{"openid"},
		Client: service.ClientInput{
			ClientType:   "public",
			RedirectURIs: []string{"https://public.example.com/callback"},
			Environment:  "production",
		},
	})
	if err != nil {
		t.Fatalf("register public app: %v", err)
	}
	t.Cleanup(func() {
		env.database.Client.Exec("DELETE FROM applications WHERE id = ?", registered.App.ID)
	})

	params := defaultAuthorizeParams(env)
	params.ClientID = registered.Client.ClientID
	params.RedirectURI = "https://public.example.com/callback"
	params.Scope = "openid"
	code := env.issueCode(t, params)

	cfg := &oauth2.Config{
		ClientID:    registered.Client.ClientID,
		Endpoint:    env.provider.Endpoint(),
		RedirectURL: params.RedirectURI,
	}
	token, err := cfg.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", e2eVerifier))
	if err != nil {
		t.Fatalf("public client exchange: %v", err)
	}
	if _, ok := token.Extra("id_token").(string); !ok {
		t.Error("public client response missing id_token")
	}
}

func TestE2EDiscoveryMatchesIssuer(t *testing.T) {
	env := newE2EEnv(t)

	resp, err := http.Get(env.server.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery request: %v", err)
	}
	defer resp.Body.Close()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if doc["issuer"] != env.server.URL {
		t.Errorf("issuer = %v, want %q", doc["issuer"], env.server.URL)
	}
	if doc["jwks_uri"] != env.server.URL+"/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v", doc["jwks_uri"])
	}
}

func TestE2EUnknownCode(t *testing.T) {
	env := newE2EEnv(t)

	_, err := env.oauthConfig(env.clientSecret).Exchange(
		context.Background(),
		"no-such-code",
		oauth2.SetAuthURLParam("code_verifier", e2eVerifier),
	)
	if err == nil {
		t.Fatal("exchange with an unknown code succeeded")
	}
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) && retrieveErr.ErrorCode != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", retrieveErr.ErrorCode)
	}
}

func TestE2EBrokeredGoogleSignIn(t *testing.T) {
	env := newE2EEnv(t)

	// A fake Google: discovery, JWKS, and a token endpoint that returns a
	// signed ID token for a fixed upstream identity.
	upstreamKey, err := signing.NewKeyManager(t.TempDir() + "/upstream-key.pem")
	if err != nil {
		t.Fatalf("upstream key: %v", err)
	}

	var fakeURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                fakeURL,
			"authorization_endpoint":                fakeURL + "/auth",
			"token_endpoint":                        fakeURL + "/token",
			"jwks_uri":                              fakeURL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(upstreamKey.JWKS())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("code") != "good-code" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		now := time.Now()
		claims := map[string]any{
			"iss": fakeURL, "sub": "broker-subject", "aud": "fake-google-client",
			"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
			"email": "broker@example.com", "email_verified": true, "name": "Broker User",
		}
		payload, _ := json.Marshal(claims)
		signer, _ := upstreamKey.Signer()
		object, _ := signer.Sign(payload)
		idToken, _ := object.CompactSerialize()
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "upstream-token",
			"id_token":     idToken,
		})
	})
	fakeServer := httptest.NewServer(mux)
	defer fakeServer.Close()
	fakeURL = fakeServer.URL

	env.app.providerFactory = func(name, clientID, clientSecret, redirectURL string) (upstream.Config, error) {
		return upstream.Config{
			Name:         name,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			AuthURL:      fakeURL + "/auth",
			TokenURL:     fakeURL + "/token",
			Issuer:       fakeURL,
			Scopes:       []string{"openid", "email", "profile"},
			UsePKCE:      true,
			OIDC:         true,
		}, nil
	}

	if err := env.app.providers.Upsert(context.Background(), env.appModel.ID, service.ProviderInput{
		Provider:     "google",
		ClientID:     "fake-google-client",
		ClientSecret: "fake-google-secret",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("configure provider: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	browser := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	params := defaultAuthorizeParams(env)
	params.Scope = "openid profile email"
	params.WithSession = false

	// 1. The unsigned-in prompt offers the configured provider.
	authResp := env.authorizeWith(t, browser, params)
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("prompt status = %d, want 200", authResp.StatusCode)
	}
	body, _ := io.ReadAll(authResp.Body)
	authResp.Body.Close()
	if !strings.Contains(string(body), "Continue with Google") {
		t.Fatalf("prompt missing provider button: %s", body)
	}

	// 2. Starting sign-in redirects to the upstream provider with state + PKCE.
	startResp, err := browser.Get(env.server.URL + "/auth/upstream/google/start")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("start status = %d, want 302: %s", startResp.StatusCode, body)
	}
	upstreamAuthURL, err := url.Parse(startResp.Header.Get("Location"))
	if err != nil || upstreamAuthURL.Host != strings.TrimPrefix(fakeURL, "http://") {
		t.Fatalf("upstream redirect = %q, err = %v", startResp.Header.Get("Location"), err)
	}
	if upstreamAuthURL.Query().Get("code_challenge") == "" {
		t.Error("upstream authorization request missing PKCE challenge")
	}
	state := upstreamAuthURL.Query().Get("state")
	if state == "" {
		t.Fatal("upstream authorization request missing state")
	}

	// 3. The provider calls back with an authorization code.
	callbackResp, err := browser.Get(env.server.URL + "/auth/upstream/google/callback?code=good-code&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("callback status = %d, want 303: %s", callbackResp.StatusCode, body)
	}
	returnTo := callbackResp.Header.Get("Location")
	if !strings.HasPrefix(returnTo, "/authorize?") {
		t.Fatalf("callback return target = %q", returnTo)
	}

	// 4. The original authorization request resumes with the new session.
	resumeResp, err := browser.Get(env.server.URL + returnTo)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	defer resumeResp.Body.Close()
	if resumeResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resumeResp.Body)
		t.Fatalf("resume status = %d, want 302: %s", resumeResp.StatusCode, body)
	}
	appRedirect, _ := url.Parse(resumeResp.Header.Get("Location"))
	code := appRedirect.Query().Get("code")
	if code == "" {
		t.Fatal("resumed authorization request did not issue a code")
	}

	// 5. Exchange the code and verify the provisioned identity.
	token, err := env.oauthConfig(env.clientSecret).Exchange(
		context.Background(), code, oauth2.SetAuthURLParam("code_verifier", e2eVerifier),
	)
	if err != nil {
		t.Fatalf("token exchange after brokered sign-in: %v", err)
	}
	rawIDToken := token.Extra("id_token").(string)
	verifier := env.provider.Verifier(&oidcclient.Config{ClientID: env.client.ClientID})
	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		t.Fatalf("verify brokered ID token: %v", err)
	}
	firstSubject := idToken.Subject
	if firstSubject == "" {
		t.Fatal("brokered ID token has an empty subject")
	}
	var claims map[string]any
	_ = idToken.Claims(&claims)
	if claims["email"] != "broker@example.com" {
		t.Errorf("email claim = %v, want broker@example.com", claims["email"])
	}

	// 6. A second sign-in reuses the same user rather than creating another.
	resp2 := env.authorizeWith(t, browser, defaultAuthorizeParams(env))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("second authorize status = %d, want 302 (session should persist)", resp2.StatusCode)
	}
	secondRedirect, _ := url.Parse(resp2.Header.Get("Location"))
	secondCode := secondRedirect.Query().Get("code")
	if secondCode == "" {
		t.Fatal("second authorization missing code")
	}
	token2, err := env.oauthConfig(env.clientSecret).Exchange(
		context.Background(), secondCode, oauth2.SetAuthURLParam("code_verifier", e2eVerifier),
	)
	if err != nil {
		t.Fatalf("second token exchange: %v", err)
	}
	idToken2, err := verifier.Verify(context.Background(), token2.Extra("id_token").(string))
	if err != nil {
		t.Fatalf("verify second ID token: %v", err)
	}
	if idToken2.Subject != firstSubject {
		t.Errorf("second sign-in subject = %q, want %q", idToken2.Subject, firstSubject)
	}

	var users int64
	env.database.Client.Raw("SELECT count(*) FROM users WHERE email = ?", "broker@example.com").Scan(&users)
	if users != 1 {
		t.Errorf("users with brokered email = %d, want 1", users)
	}
}

func TestE2EConcurrentCodeExchange(t *testing.T) {
	env := newE2EEnv(t)
	code := env.issueCode(t, defaultAuthorizeParams(env))

	type result struct {
		err error
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := env.oauthConfig(env.clientSecret).Exchange(
				context.Background(),
				code,
				oauth2.SetAuthURLParam("code_verifier", e2eVerifier),
			)
			results <- result{err: err}
		}()
	}

	successes := 0
	failures := 0
	for i := 0; i < 2; i++ {
		if r := <-results; r.err == nil {
			successes++
		} else {
			failures++
		}
	}
	if successes != 1 || failures != 1 {
		t.Errorf("concurrent exchange successes/failures = %d/%d, want 1/1", successes, failures)
	}
}
