package oidc

import (
	"slices"
	"strings"
	"testing"
)

func TestNewDiscoveryConfig(t *testing.T) {
	const issuer = "https://auth.example.com"
	cfg := NewDiscoveryConfig(issuer)

	if cfg.Issuer != issuer {
		t.Errorf("Issuer = %q, want %q", cfg.Issuer, issuer)
	}

	for name, got := range map[string]string{
		"AuthorizationEndpoint": cfg.AuthorizationEndpoint,
		"TokenEndpoint":         cfg.TokenEndpoint,
		"JWKSURI":               cfg.JWKSURI,
	} {
		if !strings.HasPrefix(got, issuer+"/") {
			t.Errorf("%s = %q, want an absolute URL under the issuer", name, got)
		}
	}
	if cfg.AuthorizationEndpoint != issuer+"/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", cfg.AuthorizationEndpoint)
	}
	if cfg.TokenEndpoint != issuer+"/token" {
		t.Errorf("TokenEndpoint = %q", cfg.TokenEndpoint)
	}
	if cfg.JWKSURI != issuer+"/.well-known/jwks.json" {
		t.Errorf("JWKSURI = %q", cfg.JWKSURI)
	}

	if !slices.Equal(cfg.ResponseTypesSupported, []string{"code"}) {
		t.Errorf("ResponseTypesSupported = %v, want [code]", cfg.ResponseTypesSupported)
	}
	if !slices.Equal(cfg.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Errorf("CodeChallengeMethodsSupported = %v, want [S256]", cfg.CodeChallengeMethodsSupported)
	}
	if !slices.Contains(cfg.IDTokenSigningAlgValuesSupported, "RS256") {
		t.Errorf("IDTokenSigningAlgValuesSupported = %v, want RS256", cfg.IDTokenSigningAlgValuesSupported)
	}
	if !slices.Contains(cfg.SubjectTypesSupported, "public") {
		t.Errorf("SubjectTypesSupported = %v, want public", cfg.SubjectTypesSupported)
	}
}

func TestNewDiscoveryConfig_NormalizesTrailingSlash(t *testing.T) {
	cfg := NewDiscoveryConfig("http://localhost:8080/")

	if cfg.Issuer != "http://localhost:8080" {
		t.Errorf("Issuer = %q, want no trailing slash", cfg.Issuer)
	}
	if cfg.JWKSURI != "http://localhost:8080/.well-known/jwks.json" {
		t.Errorf("JWKSURI = %q", cfg.JWKSURI)
	}
}
