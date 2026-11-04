package oauth

import "testing"

const testVerifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

func TestVerifyPKCE(t *testing.T) {
	challenge := PKCEChallenge(testVerifier)

	tests := []struct {
		name      string
		challenge string
		verifier  string
		method    string
		want      bool
	}{
		{"matching S256", challenge, testVerifier, "S256", true},
		{"wrong verifier", challenge, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFH", "S256", false},
		{"wrong method", challenge, testVerifier, "plain", false},
		{"empty challenge", "", testVerifier, "S256", false},
		{"short verifier", challenge, "short", "S256", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyPKCE(tt.challenge, tt.verifier, tt.method); got != tt.want {
				t.Errorf("VerifyPKCE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizeRequestValidate(t *testing.T) {
	valid := AuthorizeRequest{
		ResponseType:        "code",
		State:               "state",
		CodeChallenge:       PKCEChallenge(testVerifier),
		CodeChallengeMethod: "S256",
	}

	tests := []struct {
		name      string
		mutate    func(*AuthorizeRequest)
		wantCode  string
		wantError bool
	}{
		{"valid without openid", func(r *AuthorizeRequest) {}, "", false},
		{"valid openid with nonce", func(r *AuthorizeRequest) { r.Scope = "openid profile"; r.Nonce = "n" }, "", false},
		{"non-code response type", func(r *AuthorizeRequest) { r.ResponseType = "token" }, "unsupported_response_type", true},
		{"missing challenge", func(r *AuthorizeRequest) { r.CodeChallenge = "" }, "invalid_request", true},
		{"plain method", func(r *AuthorizeRequest) { r.CodeChallengeMethod = "plain" }, "invalid_request", true},
		{"short challenge", func(r *AuthorizeRequest) { r.CodeChallenge = "short" }, "invalid_request", true},
		{"openid without nonce", func(r *AuthorizeRequest) { r.Scope = "openid" }, "invalid_request", true},
		{"missing state", func(r *AuthorizeRequest) { r.State = "" }, "invalid_request", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := valid
			tt.mutate(&req)
			err := req.Validate()
			if tt.wantError {
				if err == nil {
					t.Fatal("Validate() error = nil, want error")
				}
				if err.Code != tt.wantCode {
					t.Errorf("error code = %q, want %q", err.Code, tt.wantCode)
				}
			} else if err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
		})
	}
}
