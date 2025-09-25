package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExchangeCode(t *testing.T) {
	tests := []struct {
		name             string
		serverResponse   interface{}
		serverStatus     int
		clientSecret     string
		expectedError    string
		validateRequest  func(t *testing.T, r *http.Request)
	}{
		{
			name: "successful token exchange with client secret",
			serverResponse: TokenResponse{
				AccessToken: "test-access-token",
				IDToken:     "test-id-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				Scope:       "openid profile email",
			},
			serverStatus: http.StatusOK,
			clientSecret: "test-secret",
			validateRequest: func(t *testing.T, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST request, got %s", r.Method)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
					t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %s", ct)
				}

				err := r.ParseForm()
				if err != nil {
					t.Fatalf("failed to parse form: %v", err)
				}

				// Validate required parameters
				expectedParams := map[string]string{
					"grant_type":    "authorization_code",
					"client_id":     "test-client-id",
					"code":          "test-code",
					"code_verifier": "test-verifier",
					"redirect_uri":  "https://example.com/callback",
					"client_secret": "test-secret",
				}

				for key, expected := range expectedParams {
					if actual := r.FormValue(key); actual != expected {
						t.Errorf("expected %s=%s, got %s", key, expected, actual)
					}
				}
			},
		},
		{
			name: "successful token exchange without client secret (public client)",
			serverResponse: TokenResponse{
				AccessToken: "test-access-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			},
			serverStatus: http.StatusOK,
			clientSecret: "", // No client secret for public clients
			validateRequest: func(t *testing.T, r *http.Request) {
				err := r.ParseForm()
				if err != nil {
					t.Fatalf("failed to parse form: %v", err)
				}

				// Ensure client_secret is NOT included
				if r.FormValue("client_secret") != "" {
					t.Error("client_secret should not be included for public clients")
				}

				// Still validate other required parameters
				expectedParams := map[string]string{
					"grant_type":    "authorization_code",
					"client_id":     "test-client-id",
					"code":          "test-code",
					"code_verifier": "test-verifier",
					"redirect_uri":  "https://example.com/callback",
				}

				for key, expected := range expectedParams {
					if actual := r.FormValue(key); actual != expected {
						t.Errorf("expected %s=%s, got %s", key, expected, actual)
					}
				}
			},
		},
		{
			name: "invalid grant error",
			serverResponse: TokenError{
				Error:            "invalid_grant",
				ErrorDescription: "Invalid authorization code",
			},
			serverStatus:  http.StatusBadRequest,
			clientSecret:  "test-secret",
			expectedError: "authorization code is invalid or expired",
		},
		{
			name: "invalid client error",
			serverResponse: TokenError{
				Error: "invalid_client",
			},
			serverStatus:  http.StatusUnauthorized,
			clientSecret:  "test-secret",
			expectedError: "client authentication failed",
		},
		{
			name:           "server error without json response",
			serverResponse: "Internal Server Error",
			serverStatus:   http.StatusInternalServerError,
			clientSecret:   "test-secret",
			expectedError:  "token exchange failed with status 500",
		},
		{
			name: "missing access token in response",
			serverResponse: map[string]interface{}{
				"token_type": "Bearer",
				"expires_in": 3600,
			},
			serverStatus:  http.StatusOK,
			clientSecret:  "test-secret",
			expectedError: "invalid token response: missing access_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Validate request if validator provided
				if tt.validateRequest != nil {
					tt.validateRequest(t, r)
				}

				// Set response status
				w.WriteHeader(tt.serverStatus)

				// Write response based on type
				switch v := tt.serverResponse.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			// Use the full test server URL (includes protocol)
			// Call ExchangeCode
			resp, err := ExchangeCode(
				context.Background(),
				server.URL,
				"test-client-id",
				tt.clientSecret,
				"https://example.com/callback",
				"test-code",
				"test-verifier",
			)

			// Check error expectations
			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.expectedError)
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %q", tt.expectedError, err.Error())
				}
				return
			}

			// Check success expectations
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if resp == nil {
				t.Error("expected non-nil response")
				return
			}

			if resp.AccessToken == "" {
				t.Error("expected non-empty access token")
			}
		})
	}
}

func TestExchangeCode_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler will never complete before context cancellation
		<-r.Context().Done()
	}))
	defer server.Close()

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Call ExchangeCode with cancelled context
	_, err := ExchangeCode(
		ctx,
		server.URL,
		"test-client-id",
		"test-secret",
		"https://example.com/callback",
		"test-code",
		"test-verifier",
	)

	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}

	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context cancelled error, got: %v", err)
	}
}