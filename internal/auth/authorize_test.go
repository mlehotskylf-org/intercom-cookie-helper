package auth

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildAuthorizeURL(t *testing.T) {
	tests := []struct {
		name        string
		params      AuthorizeParams
		wantErr     bool
		errContains string
		validate    func(t *testing.T, gotURL string)
	}{
		{
			name: "minimal valid OAuth2 params",
			params: AuthorizeParams{
				Domain:      "auth.example.com",
				ClientID:    "client123",
				RedirectURI: "https://app.example.com/callback",
				Scope:       "read write",
				State:       "random-state",
			},
			wantErr: false,
			validate: func(t *testing.T, gotURL string) {
				u, err := url.Parse(gotURL)
				if err != nil {
					t.Fatalf("failed to parse URL: %v", err)
				}

				// Check scheme and host
				if u.Scheme != "https" {
					t.Errorf("scheme = %s, want https", u.Scheme)
				}
				if u.Host != "auth.example.com" {
					t.Errorf("host = %s, want auth.example.com", u.Host)
				}
				if u.Path != "/authorize" {
					t.Errorf("path = %s, want /authorize", u.Path)
				}

				// Check required params
				q := u.Query()
				if q.Get("response_type") != "code" {
					t.Errorf("response_type = %s, want code", q.Get("response_type"))
				}
				if q.Get("client_id") != "client123" {
					t.Errorf("client_id = %s, want client123", q.Get("client_id"))
				}
				if q.Get("redirect_uri") != "https://app.example.com/callback" {
					t.Errorf("redirect_uri = %s, want https://app.example.com/callback", q.Get("redirect_uri"))
				}
				if q.Get("scope") != "read write" {
					t.Errorf("scope = %s, want 'read write'", q.Get("scope"))
				}
				if q.Get("state") != "random-state" {
					t.Errorf("state = %s, want random-state", q.Get("state"))
				}

				// Nonce should not be present for non-OIDC flows
				if q.Get("nonce") != "" {
					t.Errorf("nonce should not be present for non-OIDC flows")
				}
			},
		},
		{
			name: "full OIDC params with PKCE",
			params: AuthorizeParams{
				Domain:              "auth.example.com",
				ClientID:            "client123",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "openid profile email",
				State:               "random-state",
				Nonce:               "random-nonce",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
				Prompt:              "login consent",
				Audience:            "https://api.example.com",
			},
			wantErr: false,
			validate: func(t *testing.T, gotURL string) {
				u, err := url.Parse(gotURL)
				if err != nil {
					t.Fatalf("failed to parse URL: %v", err)
				}

				q := u.Query()
				if q.Get("scope") != "openid profile email" {
					t.Errorf("scope = %s, want 'openid profile email'", q.Get("scope"))
				}
				if q.Get("nonce") != "random-nonce" {
					t.Errorf("nonce = %s, want random-nonce", q.Get("nonce"))
				}
				if q.Get("code_challenge") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
					t.Errorf("code_challenge = %s", q.Get("code_challenge"))
				}
				if q.Get("code_challenge_method") != "S256" {
					t.Errorf("code_challenge_method = %s, want S256", q.Get("code_challenge_method"))
				}
				if q.Get("prompt") != "login consent" {
					t.Errorf("prompt = %s, want 'login consent'", q.Get("prompt"))
				}
				if q.Get("audience") != "https://api.example.com" {
					t.Errorf("audience = %s, want https://api.example.com", q.Get("audience"))
				}
			},
		},
		{
			name: "URL encoding of special characters",
			params: AuthorizeParams{
				Domain:      "auth.example.com",
				ClientID:    "client/123",
				RedirectURI: "https://app.example.com/callback?foo=bar&baz=qux",
				Scope:       "openid profile email",
				State:       "state+with+spaces",
				Nonce:       "nonce=with=equals",
			},
			wantErr: false,
			validate: func(t *testing.T, gotURL string) {
				// The URL should be properly encoded
				if !strings.Contains(gotURL, "client_id=client%2F123") {
					t.Error("client_id should be URL encoded")
				}
				if !strings.Contains(gotURL, "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback%3Ffoo%3Dbar%26baz%3Dqux") {
					t.Error("redirect_uri should be URL encoded")
				}
				if !strings.Contains(gotURL, "state=state%2Bwith%2Bspaces") {
					t.Error("state should be URL encoded")
				}
				if !strings.Contains(gotURL, "nonce=nonce%3Dwith%3Dequals") {
					t.Error("nonce should be URL encoded")
				}
			},
		},
		{
			name: "missing domain",
			params: AuthorizeParams{
				ClientID:    "client123",
				RedirectURI: "https://app.example.com/callback",
				Scope:       "read",
				State:       "state",
			},
			wantErr:     true,
			errContains: "domain is required",
		},
		{
			name: "missing client_id",
			params: AuthorizeParams{
				Domain:      "auth.example.com",
				RedirectURI: "https://app.example.com/callback",
				Scope:       "read",
				State:       "state",
			},
			wantErr:     true,
			errContains: "client_id is required",
		},
		{
			name: "missing redirect_uri",
			params: AuthorizeParams{
				Domain:   "auth.example.com",
				ClientID: "client123",
				Scope:    "read",
				State:    "state",
			},
			wantErr:     true,
			errContains: "redirect_uri is required",
		},
		{
			name: "missing scope",
			params: AuthorizeParams{
				Domain:      "auth.example.com",
				ClientID:    "client123",
				RedirectURI: "https://app.example.com/callback",
				State:       "state",
			},
			wantErr:     true,
			errContains: "scope is required",
		},
		{
			name: "missing state",
			params: AuthorizeParams{
				Domain:      "auth.example.com",
				ClientID:    "client123",
				RedirectURI: "https://app.example.com/callback",
				Scope:       "read",
			},
			wantErr:     true,
			errContains: "state is required for CSRF protection",
		},
		{
			name: "OIDC flow missing nonce",
			params: AuthorizeParams{
				Domain:      "auth.example.com",
				ClientID:    "client123",
				RedirectURI: "https://app.example.com/callback",
				Scope:       "openid profile",
				State:       "state",
			},
			wantErr:     true,
			errContains: "nonce is required for OpenID Connect flows",
		},
		{
			name: "PKCE with challenge but no method",
			params: AuthorizeParams{
				Domain:        "auth.example.com",
				ClientID:      "client123",
				RedirectURI:   "https://app.example.com/callback",
				Scope:         "read",
				State:         "state",
				CodeChallenge: "challenge",
			},
			wantErr:     true,
			errContains: "code_challenge_method is required when using PKCE",
		},
		{
			name: "PKCE with method but no challenge",
			params: AuthorizeParams{
				Domain:              "auth.example.com",
				ClientID:            "client123",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "read",
				State:               "state",
				CodeChallengeMethod: "S256",
			},
			wantErr:     true,
			errContains: "code_challenge is required when code_challenge_method is set",
		},
		{
			name: "invalid code_challenge_method",
			params: AuthorizeParams{
				Domain:              "auth.example.com",
				ClientID:            "client123",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "read",
				State:               "state",
				CodeChallenge:       "challenge",
				CodeChallengeMethod: "MD5",
			},
			wantErr:     true,
			errContains: "invalid code_challenge_method",
		},
		{
			name: "domain with protocol",
			params: AuthorizeParams{
				Domain:      "https://auth.example.com",
				ClientID:    "client123",
				RedirectURI: "https://app.example.com/callback",
				Scope:       "read",
				State:       "state",
			},
			wantErr:     true,
			errContains: "domain must not contain protocol",
		},
		{
			name: "domain with path",
			params: AuthorizeParams{
				Domain:      "auth.example.com/authorize",
				ClientID:    "client123",
				RedirectURI: "https://app.example.com/callback",
				Scope:       "read",
				State:       "state",
			},
			wantErr:     true,
			errContains: "domain must not contain path",
		},
		{
			name: "PKCE with plain method",
			params: AuthorizeParams{
				Domain:              "auth.example.com",
				ClientID:            "client123",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "read",
				State:               "state",
				CodeChallenge:       "verifier",
				CodeChallengeMethod: "plain",
			},
			wantErr: false,
			validate: func(t *testing.T, gotURL string) {
				u, err := url.Parse(gotURL)
				if err != nil {
					t.Fatalf("failed to parse URL: %v", err)
				}
				q := u.Query()
				if q.Get("code_challenge_method") != "plain" {
					t.Errorf("code_challenge_method = %s, want plain", q.Get("code_challenge_method"))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildAuthorizeURL(tt.params)

			if tt.wantErr {
				if err == nil {
					t.Errorf("BuildAuthorizeURL() error = nil, want error containing %q", tt.errContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("BuildAuthorizeURL() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("BuildAuthorizeURL() unexpected error: %v", err)
				return
			}

			if tt.validate != nil {
				tt.validate(t, got)
			}
		})
	}
}

func TestBuildAuthorizeURL_Integration(t *testing.T) {
	// Test with real-world Auth0 parameters
	params := AuthorizeParams{
		Domain:              "tenant.auth0.com",
		ClientID:            "abc123def456",
		RedirectURI:         "https://myapp.com/callback",
		Scope:               "openid profile email offline_access",
		State:               "xyzabc123",
		Nonce:               "nonce456",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Audience:            "https://api.myapp.com",
	}

	url, err := BuildAuthorizeURL(params)
	if err != nil {
		t.Fatalf("BuildAuthorizeURL() error = %v", err)
	}

	// Verify the URL structure
	if !strings.HasPrefix(url, "https://tenant.auth0.com/authorize?") {
		t.Errorf("URL should start with https://tenant.auth0.com/authorize?, got %s", url)
	}

	// Verify all parameters are present
	requiredParams := []string{
		"response_type=code",
		"client_id=abc123def456",
		"redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback",
		"scope=openid+profile+email+offline_access",
		"state=xyzabc123",
		"nonce=nonce456",
		"code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method=S256",
		"audience=https%3A%2F%2Fapi.myapp.com",
	}

	for _, param := range requiredParams {
		if !strings.Contains(url, param) {
			t.Errorf("URL missing parameter %s", param)
		}
	}
}

func TestBuildAuthorizeURL_ParameterOrder(t *testing.T) {
	// While parameter order doesn't matter functionally, test that we produce consistent URLs
	params := AuthorizeParams{
		Domain:      "auth.example.com",
		ClientID:    "client123",
		RedirectURI: "https://app.example.com/callback",
		Scope:       "openid profile",
		State:       "state",
		Nonce:       "nonce",
	}

	url1, _ := BuildAuthorizeURL(params)
	url2, _ := BuildAuthorizeURL(params)

	if url1 != url2 {
		t.Error("BuildAuthorizeURL should produce consistent URLs for the same input")
	}
}
