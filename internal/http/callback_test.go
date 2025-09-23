package httpx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/auth"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

// Helper function to add config to context for tests
func withTestConfig(ctx context.Context, cfg config.Config) context.Context {
	return context.WithValue(ctx, ConfigContextKey, cfg)
}

// Helper function to create a test transaction cookie
func createTestTxnCookie(t *testing.T, state, cv, nonce string, expiry time.Time, signingKey []byte, domain string) *http.Cookie {
	t.Helper()

	// Create the payload
	payload := auth.TxnPayloadV1{
		V:     auth.TxnV1,
		State: state,
		CV:    cv,
		Nonce: nonce,
		Iat:   time.Now().Unix(),
		Exp:   expiry.Unix(),
	}

	// Encode the payload
	encoded, err := auth.EncodeTxnV1(payload, signingKey)
	if err != nil {
		t.Fatalf("Failed to encode transaction: %v", err)
	}

	// Create the cookie
	return &http.Cookie{
		Name:     auth.TxnCookieName,
		Value:    encoded,
		Domain:   domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// Helper to create valid base64url strings for OIDC parameters
func makeBase64URL(data string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(data))
}

// Helper to create a valid PKCE code verifier (43-128 characters)
func makeValidCodeVerifier() string {
	// Create a 64-byte random string, which when base64url encoded will be ~86 characters
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestHandleCallback(t *testing.T) {
	// Common test configuration
	cfg := config.Config{
		CookieSigningKey:          []byte("test-signing-key-32-bytes-long!!"),
		SecondaryCookieSigningKey: []byte("secondary-key-32-bytes-long!!!!"),
		TxnSkew:                   5 * time.Minute,
		TxnTTL:                    10 * time.Minute,
		CookieDomain:              ".example.com",
		IntercomAppID:            "test-app-id",
		Env:                       "dev",
		AppHostname:               "example.com",
		Auth0RedirectPath:         "/callback", // Must start with /
		Auth0Domain:              "test.auth0.com",
		Auth0ClientID:            "test-client-id",
		Auth0ClientSecret:        "test-client-secret",
	}

	// Valid OIDC parameters (base64url encoded)
	validState := makeBase64URL("test-state")
	validCV := makeValidCodeVerifier() // Must be 43-128 characters for PKCE
	validNonce := makeBase64URL("test-nonce")

	tests := []struct {
		name           string
		queryParams    string
		setupCookie    func(t *testing.T, r *http.Request)
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "missing code parameter",
			queryParams:    "?state=" + validState,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name:           "missing state parameter",
			queryParams:    "?code=test-code",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name:           "missing both code and state",
			queryParams:    "",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name:           "oauth error response",
			queryParams:    "?error=access_denied&error_description=User+denied+access",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "access_denied",
		},
		{
			name:        "missing transaction cookie",
			queryParams: "?code=test-code&state=" + validState,
			setupCookie: func(t *testing.T, r *http.Request) {
				// No cookie set
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name:        "expired transaction cookie",
			queryParams: "?code=test-code&state=" + validState,
			setupCookie: func(t *testing.T, r *http.Request) {
				// Set an expired transaction cookie
				// For expired cookie, we need to set Iat to be before Exp
				expiredTime := time.Now().Add(-10 * time.Minute)
				payload := auth.TxnPayloadV1{
					V:     auth.TxnV1,
					State: validState,
					CV:    validCV,
					Nonce: validNonce,
					Iat:   expiredTime.Add(-5 * time.Minute).Unix(), // 15 minutes ago
					Exp:   expiredTime.Unix(),                       // 10 minutes ago (expired)
				}
				encoded, err := auth.EncodeTxnV1(payload, cfg.CookieSigningKey)
				if err != nil {
					t.Fatalf("Failed to encode transaction: %v", err)
				}
				cookie := &http.Cookie{
					Name:     auth.TxnCookieName,
					Value:    encoded,
					Domain:   cfg.CookieDomain,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				}
				r.AddCookie(cookie)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name:        "state mismatch",
			queryParams: "?code=test-code&state=" + makeBase64URL("wrong-state"),
			setupCookie: func(t *testing.T, r *http.Request) {
				// Set a valid transaction cookie with different state
				cookie := createTestTxnCookie(
					t,
					validState, // Different from query param
					validCV,
					validNonce,
					time.Now().Add(10*time.Minute),
					cfg.CookieSigningKey,
					cfg.CookieDomain,
				)
				r.AddCookie(cookie)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name:        "valid callback with transaction",
			queryParams: "?code=test-code&state=" + validState,
			setupCookie: func(t *testing.T, r *http.Request) {
				// Set a valid transaction cookie with matching state
				cookie := createTestTxnCookie(
					t,
					validState,
					validCV,
					validNonce,
					time.Now().Add(10*time.Minute),
					cfg.CookieSigningKey,
					cfg.CookieDomain,
				)
				r.AddCookie(cookie)
			},
			expectedStatus: http.StatusBadRequest, // Will fail because we're not mocking Auth0
			expectedError:  "invalid_grant",
		},
		{
			name:        "tampered transaction cookie",
			queryParams: "?code=test-code&state=" + validState,
			setupCookie: func(t *testing.T, r *http.Request) {
				// Set a valid transaction cookie then tamper with it
				cookie := createTestTxnCookie(
					t,
					validState,
					validCV,
					validNonce,
					time.Now().Add(10*time.Minute),
					cfg.CookieSigningKey,
					cfg.CookieDomain,
				)
				// Tamper with the cookie value
				cookie.Value = cookie.Value + "tampered"
				r.AddCookie(cookie)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name:        "transaction cookie signed with wrong key",
			queryParams: "?code=test-code&state=" + validState,
			setupCookie: func(t *testing.T, r *http.Request) {
				// Set a transaction cookie signed with wrong key
				wrongKey := []byte("wrong-signing-key-32-bytes-long!")
				cookie := createTestTxnCookie(
					t,
					validState,
					validCV,
					validNonce,
					time.Now().Add(10*time.Minute),
					wrongKey,
					cfg.CookieDomain,
				)
				r.AddCookie(cookie)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name:        "transaction cookie with secondary key",
			queryParams: "?code=test-code&state=" + validState,
			setupCookie: func(t *testing.T, r *http.Request) {
				// Set a transaction cookie signed with secondary key
				cookie := createTestTxnCookie(
					t,
					validState,
					validCV,
					validNonce,
					time.Now().Add(10*time.Minute),
					cfg.SecondaryCookieSigningKey,
					cfg.CookieDomain,
				)
				r.AddCookie(cookie)
			},
			expectedStatus: http.StatusBadRequest, // Will fail because we're not mocking Auth0
			expectedError:  "invalid_grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest("GET", "/callback"+tt.queryParams, nil)

			// Add config to context
			req = req.WithContext(withTestConfig(req.Context(), cfg))

			// Setup cookie if needed
			if tt.setupCookie != nil {
				tt.setupCookie(t, req)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			handleCallback(rr, req)

			// Check status
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Parse response
			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}

			// Check error field
			if errorField, ok := response["error"].(string); ok {
				if errorField != tt.expectedError {
					t.Errorf("Expected error %q, got %q", tt.expectedError, errorField)
				}
			} else if tt.expectedError != "" {
				t.Errorf("Expected error %q, but no error field in response", tt.expectedError)
			}
		})
	}
}

func TestHandleCallback_NoConfig(t *testing.T) {
	// Test without config in context
	req := httptest.NewRequest("GET", "/callback?code=test&state=test", nil)
	rr := httptest.NewRecorder()

	handleCallback(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if errorField, ok := response["error"].(string); !ok || errorField != "internal_error" {
		t.Errorf("Expected error 'internal_error', got %v", response["error"])
	}
}

func TestHandleCallback_MisconfiguredRedirectPath(t *testing.T) {
	// Test with Auth0RedirectPath not starting with /
	cfg := config.Config{
		CookieSigningKey:  []byte("test-signing-key-32-bytes-long!!"),
		TxnSkew:           5 * time.Minute,
		TxnTTL:            10 * time.Minute,
		CookieDomain:      ".example.com",
		IntercomAppID:     "test-app-id",
		Env:               "dev",
		AppHostname:       "example.com",
		Auth0RedirectPath: "callback", // Missing leading slash
		Auth0Domain:       "test.auth0.com",
		Auth0ClientID:     "test-client-id",
		Auth0ClientSecret: "test-client-secret",
	}

	// Valid OIDC parameters
	validState := makeBase64URL("test-state")
	validCV := makeValidCodeVerifier()
	validNonce := makeBase64URL("test-nonce")

	// Create request with valid code and state
	req := httptest.NewRequest("GET", "/callback?code=test-code&state="+validState, nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Set a valid transaction cookie
	cookie := createTestTxnCookie(
		t,
		validState,
		validCV,
		validNonce,
		time.Now().Add(10*time.Minute),
		cfg.CookieSigningKey,
		cfg.CookieDomain,
	)
	req.AddCookie(cookie)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	handleCallback(rr, req)

	// Should return 500 Internal Server Error for misconfiguration
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if errorField, ok := response["error"].(string); !ok || errorField != "internal_error" {
		t.Errorf("Expected error 'internal_error', got %v", response["error"])
	}
}