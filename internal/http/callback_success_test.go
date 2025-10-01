package httpx

import (
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

func setupTestTemplate(t *testing.T) func() {
	// No-op function for backward compatibility
	// Templates are now embedded, so no setup needed
	return func() {}
}

// TestHandleCallbackSuccess_TransactionCookieCleared verifies that the transaction cookie
// is properly cleared after successful authentication flow
func TestHandleCallbackSuccess_TransactionCookieCleared(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	// Setup test Auth0 server to mock successful responses
	mockAuth0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			// Mock successful token exchange response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-access-token",
				"id_token":     createTestIDToken(t, makeBase64URL("test-nonce")),
				"token_type":   "Bearer",
				"expires_in":   3600,
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockAuth0.Close()

	// Use the full mock server URL (keep http:// prefix for test server)
	// The auth package will detect and use the protocol from the domain
	mockHost := mockAuth0.URL

	// Setup test configuration
	cfg := config.Config{
		CookieSigningKey:          []byte("test-signing-key-32-bytes-long!!"),
		SecondaryCookieSigningKey: []byte("secondary-key-32-bytes-long!!!!"),
		TxnSkew:                   5 * time.Minute,
		TxnTTL:                    10 * time.Minute,
		RedirectSkew:              5 * time.Minute,
		IntercomAppID:             "test-app-id",
		CookieDomain:              ".example.com",
		Env:                       "dev",
		AppHostname:               "example.com",
		Auth0RedirectPath:         "/callback",
		Auth0Domain:               mockHost,
		Auth0ClientID:             "test-client-id",
		Auth0ClientSecret:         "test-client-secret",
	}

	// Create test OIDC parameters
	validState := makeBase64URL("test-state")
	validCV := makeValidCodeVerifier()
	validNonce := makeBase64URL("test-nonce")

	// Create request with valid callback parameters
	req := httptest.NewRequest("GET", "/callback?code=test-code&state="+validState, nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Set valid transaction cookie that should be cleared
	txnCookie := createTestTxnCookie(
		t,
		validState,
		validCV,
		validNonce,
		time.Now().Add(10*time.Minute),
		cfg.CookieSigningKey,
		cfg.CookieDomain,
	)
	req.AddCookie(txnCookie)

	// Set valid redirect cookie
	redirectCookie := createTestRedirectCookie(t, cfg, "https://example.com/original")
	req.AddCookie(redirectCookie)

	// Create response recorder to capture the response
	rr := httptest.NewRecorder()

	// Call the callback handler
	handleCallback(rr, req)

	// Verify successful response (200 OK)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
		t.Logf("Response body: %s", rr.Body.String())
	}

	// Verify we got HTML response
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected HTML content type, got %s", contentType)
	}

	// Check the HTML response contains Intercom identify page
	body := rr.Body.String()
	t.Logf("Response body (first 500 chars): %.500s", body)
	if !strings.Contains(body, "intercom_user_jwt") {
		t.Error("Response should contain 'intercom_user_jwt'")
	}
	if !strings.Contains(body, "Signing you in to chat") {
		t.Error("Response should contain Intercom identify page title")
	}
	// The user data is embedded in the JWT, not displayed as plain text
	// Just check that we have the Intercom setup script
	if !strings.Contains(body, "window.intercomSettings") {
		t.Error("Response should contain Intercom initialization script")
	}
	if !strings.Contains(body, "test-app-id") {
		t.Error("Response should contain the Intercom app ID")
	}
	// Check redirect is set up
	if !strings.Contains(body, "location.replace") {
		t.Error("Response should contain redirect logic")
	}

	// CRITICAL: Verify transaction cookie is cleared
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == auth.TxnCookieName {
			// Check if cookie is being cleared (MaxAge = -1 or expired time)
			if cookie.MaxAge != -1 && !cookie.Expires.Before(time.Now()) {
				t.Error("Transaction cookie was not cleared after successful authentication")
				t.Logf("Cookie details: MaxAge=%d, Expires=%v", cookie.MaxAge, cookie.Expires)
			}
		}
		// Also verify redirect cookie is cleared
		if cookie.Name == security.RedirectCookieName {
			if cookie.MaxAge != -1 && !cookie.Expires.Before(time.Now()) {
				t.Error("Redirect cookie was not cleared after successful authentication")
				t.Logf("Cookie details: MaxAge=%d, Expires=%v", cookie.MaxAge, cookie.Expires)
			}
		}
	}
}

// Helper to create a test redirect cookie
func createTestRedirectCookie(t *testing.T, cfg config.Config, returnURL string) *http.Cookie {
	t.Helper()

	// Create a test response writer to capture the cookie
	rr := httptest.NewRecorder()

	// Use SetSignedRedirectCookie to create the cookie
	opts := security.CookieOpts{
		Domain:   cfg.CookieDomain,
		TTL:      30 * time.Minute,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	_, err := security.SetSignedRedirectCookie(rr, returnURL, "example.com", cfg.CookieSigningKey, opts, time.Now())
	if err != nil {
		t.Fatalf("Failed to create redirect cookie: %v", err)
	}

	// Extract the cookie that was set
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == security.RedirectCookieName {
			return cookie
		}
	}

	t.Fatal("Redirect cookie was not set")
	return nil
}

// Helper to create a test ID token with nonce and Intercom JWT
func createTestIDToken(t *testing.T, nonce string) string {
	t.Helper()

	// Generate mock Intercom JWT (simulating Auth0 Action)
	mockIntercomJWT, err := auth.MintIntercomJWT([]byte("test-secret"), auth.IntercomClaims{
		UserID: "auth0|user123",
		Email:  "",
		Name:   "",
		Iat:    time.Now().Unix(),
		Exp:    time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("failed to mint mock Intercom JWT: %v", err)
	}

	// Create a simple JWT-like structure (header.payload.signature)
	// This is a simplified version for testing - real JWT would need proper signing
	header := makeBase64URL(`{"alg":"RS256","typ":"JWT"}`)
	expTime := time.Now().Add(time.Hour).Unix()
	payloadJSON := fmt.Sprintf(`{"nonce":"%s","sub":"auth0|user123","aud":"test-client-id","exp":%d,"http://lfx.dev/claims/intercom":"%s"}`, nonce, expTime, mockIntercomJWT)
	payload := makeBase64URL(payloadJSON)
	signature := makeBase64URL("test-signature")

	return header + "." + payload + "." + signature
}

// TestHandleCallbackSuccess_WithoutRedirectCookie verifies fallback behavior
// when redirect cookie is missing or invalid
func TestHandleCallbackSuccess_WithoutRedirectCookie(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	// Setup test Auth0 server
	mockAuth0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-access-token",
				"id_token":     createTestIDToken(t, makeBase64URL("test-nonce")),
				"token_type":   "Bearer",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockAuth0.Close()

	// Use the full mock server URL (keep http:// prefix for test server)
	mockHost := mockAuth0.URL

	cfg := config.Config{
		CookieSigningKey:  []byte("test-signing-key-32-bytes-long!!"),
		TxnSkew:           5 * time.Minute,
		TxnTTL:            10 * time.Minute,
		RedirectSkew:      5 * time.Minute,
		CookieDomain:      ".example.com",
		IntercomAppID:     "test-app-id",
		AppHostname:       "example.com",
		Auth0RedirectPath: "/callback",
		Auth0Domain:       mockHost,
		Auth0ClientID:     "test-client-id",
		Auth0ClientSecret: "test-client-secret",
		Env:               "dev",
	}

	validState := makeBase64URL("test-state")
	validCV := makeValidCodeVerifier()
	validNonce := makeBase64URL("test-nonce")

	req := httptest.NewRequest("GET", "/callback?code=test-code&state="+validState, nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Set transaction cookie but NO redirect cookie
	txnCookie := createTestTxnCookie(t, validState, validCV, validNonce,
		time.Now().Add(10*time.Minute), cfg.CookieSigningKey, cfg.CookieDomain)
	req.AddCookie(txnCookie)

	rr := httptest.NewRecorder()
	handleCallback(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Verify HTML response contains Intercom identify page
	body := rr.Body.String()
	if !strings.Contains(body, "intercom_user_jwt") {
		t.Error("Response should contain 'intercom_user_jwt'")
	}
	if !strings.Contains(body, "Signing you in to chat") {
		t.Error("Response should contain Intercom identify page title")
	}
	// The fallback URL is in the redirect logic
	if !strings.Contains(body, "location.replace") {
		t.Error("Response should contain redirect logic")
	}

	// Verify transaction cookie is still cleared
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == auth.TxnCookieName {
			if cookie.MaxAge != -1 && !cookie.Expires.Before(time.Now()) {
				t.Error("Transaction cookie was not cleared even without redirect cookie")
			}
		}
	}
}
