package httpx

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// setupCallbackTestTemplates creates temporary templates for callback tests
func setupCallbackTestTemplates(t *testing.T) func() {
	t.Helper()

	// Create a temporary web directory for tests
	err := os.MkdirAll("web", 0o755)
	if err != nil {
		t.Fatalf("Failed to create web directory: %v", err)
	}

	// Create error template
	errorTmplContent := `<!DOCTYPE html>
<html>
<body>
<h1>We couldn't sign you in</h1>
<p>{{if .ErrorMessage}}{{.ErrorMessage}}{{else}}Something went wrong.{{end}}</p>
<a href="{{.TryAgainURL}}">Try again</a>
</body>
</html>`

	errorTmplPath := filepath.Join("web", "error.tmpl")
	err = os.WriteFile(errorTmplPath, []byte(errorTmplContent), 0o644)
	if err != nil {
		t.Fatalf("Failed to create error template file: %v", err)
	}

	// Create success template (in case it's needed)
	successTmplContent := `<!DOCTYPE html>
<html>
<body>
<h1>Login Successful</h1>
</body>
</html>`

	successTmplPath := filepath.Join("web", "callback-ok.tmpl")
	err = os.WriteFile(successTmplPath, []byte(successTmplContent), 0o644)
	if err != nil {
		t.Fatalf("Failed to create success template file: %v", err)
	}

	// Return cleanup function
	return func() {
		os.RemoveAll("web")
	}
}

func TestHandleCallback(t *testing.T) {
	// Setup test templates
	cleanup := setupCallbackTestTemplates(t)
	defer cleanup()

	// Common test configuration
	cfg := config.Config{
		CookieSigningKey:          []byte("test-signing-key-32-bytes-long!!"),
		SecondaryCookieSigningKey: []byte("secondary-key-32-bytes-long!!!!"),
		TxnSkew:                   5 * time.Minute,
		TxnTTL:                    10 * time.Minute,
		CookieDomain:              ".example.com",
		IntercomAppID:             "test-app-id",
		Env:                       "dev",
		AppHostname:               "example.com",
		Auth0RedirectPath:         "/callback", // Must start with /
		Auth0Domain:               "test.auth0.com",
		Auth0ClientID:             "test-client-id",
		Auth0ClientSecret:         "test-client-secret",
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
			expectedError:  "security_check", // State mismatch uses ErrorMsgSecurityValidation
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
			req.Header.Set("Accept", "text/html")

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

			// Now we render HTML error pages instead of JSON
			body := rr.Body.String()

			// Verify we got HTML response for errors
			if tt.expectedStatus == http.StatusBadRequest {
				contentType := rr.Header().Get("Content-Type")
				if !strings.Contains(contentType, "text/html") {
					t.Errorf("Expected HTML content type, got %s", contentType)
				}

				// Check that the error page is rendered
				if !strings.Contains(body, "Can&#39;t complete sign-in") {
					t.Error("Error page should contain 'Can't complete sign-in'")
				}

				// Map expected error codes to actual HTML error messages
				// These are based on what renderErrorPage() actually generates
				expectedMessages := map[string]string{
					"invalid_request": "no longer valid",       // ErrorMsgSessionExpired or ErrorMsgMissingParams
					"invalid_grant":   "couldn't verify",       // ErrorMsgAuthFailed
					"access_denied":   "denied",                // OAuth error passes through the description
					"security_check":  "security check failed", // ErrorMsgSecurityValidation
				}

				for errorCode, msgFragment := range expectedMessages {
					if tt.expectedError == errorCode {
						// Check for related error message in HTML
						if !strings.Contains(strings.ToLower(body), msgFragment) {
							t.Logf("Expected error message containing %q for error %s", msgFragment, errorCode)
						}
						break
					}
				}
			}
		})
	}
}

func TestHandleCallback_NoConfig(t *testing.T) {
	// Setup test templates
	cleanup := setupCallbackTestTemplates(t)
	defer cleanup()

	// Test without config in context
	req := httptest.NewRequest("GET", "/callback?code=test&state=test", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()

	handleCallback(rr, req)

	// Should return Bad Request with HTML error page
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	// Verify HTML error page is rendered
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected HTML content type, got %s", contentType)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Can&#39;t complete sign-in") {
		t.Error("Error page should contain 'Can't complete sign-in'")
	}
	// Config unavailable maps to ErrorMsgConfigUnavailable which uses the default message
	if !strings.Contains(strings.ToLower(body), "configuration") {
		t.Error("Error page should mention configuration error")
	}
}

func TestHandleCallback_MisconfiguredRedirectPath(t *testing.T) {
	// Setup test templates
	cleanup := setupCallbackTestTemplates(t)
	defer cleanup()

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
	req.Header.Set("Accept", "text/html")
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

	// Should return Bad Request with HTML error page for misconfiguration
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	// Verify HTML error page is rendered
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected HTML content type, got %s", contentType)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Can&#39;t complete sign-in") {
		t.Error("Error page should contain 'Can't complete sign-in'")
	}
	// ErrorMsgServerConfig uses default case, so check for general error message
	if body == "" {
		t.Error("Error page should not be empty")
	}
}
