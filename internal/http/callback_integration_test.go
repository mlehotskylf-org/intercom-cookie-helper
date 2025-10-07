package httpx

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/auth"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// MockAuth0Server creates a test server that mocks Auth0 endpoints
type MockAuth0Server struct {
	*httptest.Server
	TokenResponse *auth.TokenResponse
	TokenError    *auth.TokenError
	Nonce         string // Store nonce for ID token generation
}

// NewMockAuth0Server creates a new mock Auth0 server
func NewMockAuth0Server() *MockAuth0Server {
	mock := &MockAuth0Server{}

	// Create the test server
	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			mock.handleTokenExchange(w, r)
		default:
			http.NotFound(w, r)
		}
	}))

	return mock
}

func (m *MockAuth0Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check content type
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/x-www-form-urlencoded") {
		http.Error(w, "Invalid content type", http.StatusBadRequest)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Check grant type
	if r.Form.Get("grant_type") != "authorization_code" {
		http.Error(w, "Invalid grant type", http.StatusBadRequest)
		return
	}

	// If TokenError is set, return error response
	if m.TokenError != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(m.TokenError)
		return
	}

	// Return success response
	if m.TokenResponse == nil {
		// Default successful response - use the nonce if set
		nonce := m.Nonce
		if nonce == "" {
			nonce = "test-nonce"
		}
		m.TokenResponse = &auth.TokenResponse{
			AccessToken: "test-access-token",
			IDToken:     createMockIDToken(nonce),
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "openid profile email",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m.TokenResponse)
}

// createMockIDToken creates a fake ID token for testing with the given nonce.
// Includes a mock Intercom JWT in the custom claim to simulate Auth0 Action behavior.
func createMockIDToken(nonce string) string {
	// Create a mock Intercom JWT (simulating what Auth0 Action would generate)
	mockIntercomJWT, _ := auth.MintIntercomJWT([]byte("test-intercom-secret"), auth.IntercomClaims{
		UserID: "auth0|123456",
		Email:  "test@example.com",
		Name:   "Test User",
		Iat:    time.Now().Unix(),
		Exp:    time.Now().Add(10 * time.Minute).Unix(),
	})

	// Create a simple JWT-like structure (header.payload.signature)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"email":"test@example.com",
		"name":"Test User",
		"iss":"https://test.auth0.com/",
		"aud":"test-client-id",
		"exp":` + fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()) + `,
		"iat":` + fmt.Sprintf("%d", time.Now().Unix()) + `,
		"nonce":"` + nonce + `",
		"http://lfx.dev/claims/intercom":"` + mockIntercomJWT + `"
	}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

// Helper to create a valid redirect cookie for integration tests
func createIntegrationRedirectCookie(returnTo string, signingKey []byte, domain string) *http.Cookie {
	// Create a test response writer to capture the cookie
	rr := httptest.NewRecorder()

	// Use SetSignedRedirectCookie to create the cookie
	opts := security.CookieOpts{
		Domain:   domain,
		TTL:      30 * time.Minute,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	_, err := security.SetSignedRedirectCookie(rr, returnTo, "example.com", signingKey, opts, time.Now())
	if err != nil {
		return nil
	}

	// Extract the cookie that was set
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == security.RedirectCookieName {
			return cookie
		}
	}

	return nil
}

// Test the full callback integration with mocked Auth0
func TestCallbackIntegration(t *testing.T) {
	// Setup test templates
	cleanup := setupCallbackTestTemplates(t)
	defer cleanup()

	// Create mock Auth0 server
	mockAuth0 := NewMockAuth0Server()
	defer mockAuth0.Close()

	// Base configuration - use the mock server URL directly (includes http://)
	baseCfg := config.Config{
		CookieSigningKey:          []byte("test-signing-key-32-bytes-long!!"),
		SecondaryCookieSigningKey: []byte("secondary-key-32-bytes-long!!!!"),
		TxnSkew:                   5 * time.Minute,
		TxnTTL:                    10 * time.Minute,
		CookieDomain:              ".example.com",
		IntercomAppID:             "test-app-id",
		Env:                       "test",
		AppHostname:               "example.com",
		Auth0RedirectPath:         "/callback",
		Auth0Domain:               mockAuth0.URL, // Use full URL with http:// prefix
		Auth0ClientID:             "test-client-id",
		Auth0ClientSecret:         "test-client-secret",
		RedirectTTL:               30 * time.Minute,
		RedirectSkew:              1 * time.Minute,
		AllowedReturnHosts:        []string{"app.intercom.io"},
	}

	tests := []struct {
		name           string
		setupMock      func()
		setupRequest   func() *http.Request
		expectedStatus int
		checkResponse  func(t *testing.T, rr *httptest.ResponseRecorder)
	}{
		{
			name: "happy path - successful authentication with redirect cookie",
			setupMock: func() {
				mockAuth0.TokenResponse = nil // Use default success
				mockAuth0.TokenError = nil
			},
			setupRequest: func() *http.Request {
				// Generate valid PKCE values
				codeVerifier := makeValidCodeVerifier()
				state := makeBase64URL("test-state")
				nonce := makeBase64URL("test-nonce")

				// Set nonce in mock server for ID token
				mockAuth0.Nonce = nonce

				// Create request
				req := httptest.NewRequest("GET", "/callback?code=valid-code&state="+state, nil)

				// Add transaction cookie
				txnCookie := createTestTxnCookie(
					t,
					state,
					codeVerifier,
					nonce,
					time.Now().Add(10*time.Minute),
					baseCfg.CookieSigningKey,
					baseCfg.CookieDomain,
				)
				req.AddCookie(txnCookie)

				// Add redirect cookie
				redirectCookie := createIntegrationRedirectCookie(
					"https://app.intercom.io/admin/inbox",
					baseCfg.CookieSigningKey,
					baseCfg.CookieDomain,
				)
				req.AddCookie(redirectCookie)

				// Add config to context
				req = req.WithContext(withTestConfig(req.Context(), baseCfg))

				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
				// Should render Intercom identify page
				body := rr.Body.String()
				if !strings.Contains(body, "intercom_user_jwt") {
					t.Error("Should include intercom_user_jwt in page")
				}
				if !strings.Contains(body, "Signing you in to chat") {
					t.Error("Should render Intercom identify page")
				}

				// Check that transaction cookie is cleared
				cookies := rr.Result().Cookies()
				for _, cookie := range cookies {
					if cookie.Name == auth.TxnCookieName && cookie.MaxAge != -1 {
						t.Error("Transaction cookie should be cleared")
					}
				}
			},
		},
		{
			name: "happy path - no redirect cookie still succeeds",
			setupMock: func() {
				mockAuth0.TokenResponse = nil // Use default success
				mockAuth0.TokenError = nil
			},
			setupRequest: func() *http.Request {
				// Generate valid PKCE values
				codeVerifier := makeValidCodeVerifier()
				state := makeBase64URL("test-state")
				nonce := makeBase64URL("test-nonce")

				// Set nonce in mock server for ID token
				mockAuth0.Nonce = nonce

				// Create request
				req := httptest.NewRequest("GET", "/callback?code=valid-code&state="+state, nil)

				// Add transaction cookie only (no redirect cookie)
				txnCookie := createTestTxnCookie(
					t,
					state,
					codeVerifier,
					nonce,
					time.Now().Add(10*time.Minute),
					baseCfg.CookieSigningKey,
					baseCfg.CookieDomain,
				)
				req.AddCookie(txnCookie)

				// Add config to context
				req = req.WithContext(withTestConfig(req.Context(), baseCfg))

				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
				// Should render Intercom identify page
				body := rr.Body.String()
				if !strings.Contains(body, "intercom_user_jwt") {
					t.Error("Should include intercom_user_jwt in page")
				}
				if !strings.Contains(body, "Signing you in to chat") {
					t.Error("Should render Intercom identify page")
				}
			},
		},
		{
			name: "bad state - mismatch between cookie and query",
			setupMock: func() {
				// Mock setup doesn't matter, should fail before Auth0 call
			},
			setupRequest: func() *http.Request {
				// Generate valid PKCE values
				codeVerifier := makeValidCodeVerifier()
				cookieState := makeBase64URL("cookie-state")
				queryState := makeBase64URL("different-state")
				nonce := makeBase64URL("test-nonce")

				// Create request with different state
				req := httptest.NewRequest("GET", "/callback?code=valid-code&state="+queryState, nil)
				req.Header.Set("Accept", "text/html")

				// Add transaction cookie with different state
				txnCookie := createTestTxnCookie(
					t,
					cookieState, // Different from query
					codeVerifier,
					nonce,
					time.Now().Add(10*time.Minute),
					baseCfg.CookieSigningKey,
					baseCfg.CookieDomain,
				)
				req.AddCookie(txnCookie)

				// Add config to context
				req = req.WithContext(withTestConfig(req.Context(), baseCfg))

				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
				// Should render error template
				body := rr.Body.String()
				if !strings.Contains(body, "Can&#39;t complete sign-in") {
					t.Error("Should render error template")
				}
				if !strings.Contains(strings.ToLower(body), "security check failed") {
					t.Error("Should mention security validation error")
				}
			},
		},
		{
			name: "token exchange failure - Auth0 returns error",
			setupMock: func() {
				mockAuth0.TokenError = &auth.TokenError{
					Error:            "invalid_grant",
					ErrorDescription: "Authorization code is invalid or expired",
				}
				mockAuth0.TokenResponse = nil
			},
			setupRequest: func() *http.Request {
				// Generate valid PKCE values
				codeVerifier := makeValidCodeVerifier()
				state := makeBase64URL("test-state")
				nonce := makeBase64URL("test-nonce")

				// Set nonce in mock server for ID token
				mockAuth0.Nonce = nonce

				// Create request
				req := httptest.NewRequest("GET", "/callback?code=invalid-code&state="+state, nil)
				req.Header.Set("Accept", "text/html")

				// Add valid transaction cookie
				txnCookie := createTestTxnCookie(
					t,
					state,
					codeVerifier,
					nonce,
					time.Now().Add(10*time.Minute),
					baseCfg.CookieSigningKey,
					baseCfg.CookieDomain,
				)
				req.AddCookie(txnCookie)

				// Add config to context
				req = req.WithContext(withTestConfig(req.Context(), baseCfg))

				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
				// Should render error template
				body := rr.Body.String()
				if !strings.Contains(body, "Can&#39;t complete sign-in") {
					t.Error("Should render error template")
				}
				// The apostrophe in "couldn't" is escaped as &#39; in HTML
				if !strings.Contains(strings.ToLower(body), "couldn&#39;t verify") {
					t.Error("Should mention authentication error")
				}
			},
		},
		{
			name: "missing transaction cookie",
			setupMock: func() {
				// Mock setup doesn't matter, should fail before Auth0 call
			},
			setupRequest: func() *http.Request {
				state := makeBase64URL("test-state")

				// Create request without transaction cookie
				req := httptest.NewRequest("GET", "/callback?code=valid-code&state="+state, nil)
				req.Header.Set("Accept", "text/html")

				// Add config to context but no cookies
				req = req.WithContext(withTestConfig(req.Context(), baseCfg))

				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
				// Should render error template
				body := rr.Body.String()
				if !strings.Contains(body, "Can&#39;t complete sign-in") {
					t.Error("Should render error template")
				}
				if !strings.Contains(strings.ToLower(body), "no longer valid") {
					t.Error("Should mention link is no longer valid")
				}
			},
		},
		{
			name: "expired transaction cookie",
			setupMock: func() {
				// Mock setup doesn't matter, should fail before Auth0 call
			},
			setupRequest: func() *http.Request {
				// Generate valid PKCE values
				codeVerifier := makeValidCodeVerifier()
				state := makeBase64URL("test-state")
				nonce := makeBase64URL("test-nonce")

				// Set nonce in mock server for ID token
				mockAuth0.Nonce = nonce

				// Create request
				req := httptest.NewRequest("GET", "/callback?code=valid-code&state="+state, nil)
				req.Header.Set("Accept", "text/html")

				// Add expired transaction cookie
				expiredTime := time.Now().Add(-10 * time.Minute)
				payload := auth.TxnPayloadV1{
					V:     auth.TxnV1,
					State: state,
					CV:    codeVerifier,
					Nonce: nonce,
					Iat:   expiredTime.Add(-5 * time.Minute).Unix(),
					Exp:   expiredTime.Unix(), // Already expired
				}
				encoded, _ := auth.EncodeTxnV1(payload, baseCfg.CookieSigningKey)
				txnCookie := &http.Cookie{
					Name:     auth.TxnCookieName,
					Value:    encoded,
					Domain:   baseCfg.CookieDomain,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				}
				req.AddCookie(txnCookie)

				// Add config to context
				req = req.WithContext(withTestConfig(req.Context(), baseCfg))

				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
				// Should render error template
				body := rr.Body.String()
				if !strings.Contains(body, "Can&#39;t complete sign-in") {
					t.Error("Should render error template")
				}
				if !strings.Contains(strings.ToLower(body), "no longer valid") {
					t.Error("Should mention link is no longer valid")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock behavior
			tt.setupMock()

			// Create request
			req := tt.setupRequest()

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			handleCallback(rr, req)

			// Check status
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check response
			tt.checkResponse(t, rr)
		})
	}
}

// Test OAuth error handling
func TestCallbackIntegration_OAuthErrors(t *testing.T) {
	// Setup test templates
	cleanup := setupCallbackTestTemplates(t)
	defer cleanup()

	cfg := config.Config{
		CookieSigningKey: []byte("test-signing-key-32-bytes-long!!"),
		CookieDomain:     ".example.com",
		IntercomAppID:    "test-app-id",
		AppHostname:      "example.com",
	}

	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
		checkResponse  func(t *testing.T, rr *httptest.ResponseRecorder)
	}{
		{
			name:           "user cancelled authorization",
			queryParams:    "?error=access_denied&error_description=User+cancelled+authorization",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
				body := rr.Body.String()
				if !strings.Contains(body, "Can&#39;t complete sign-in") {
					t.Error("Should render error template")
				}
				if !strings.Contains(strings.ToLower(body), "cancelled") {
					t.Error("Should mention cancellation")
				}
			},
		},
		{
			name:           "invalid request error",
			queryParams:    "?error=invalid_request&error_description=Invalid+redirect_uri",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
				body := rr.Body.String()
				if !strings.Contains(body, "Can&#39;t complete sign-in") {
					t.Error("Should render error template")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest("GET", "/callback"+tt.queryParams, nil)
			req.Header.Set("Accept", "text/html")
			req = req.WithContext(withTestConfig(req.Context(), cfg))

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			handleCallback(rr, req)

			// Check status
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check response
			tt.checkResponse(t, rr)
		})
	}
}
