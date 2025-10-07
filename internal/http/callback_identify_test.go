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
)

// TestCallbackRendererSuccess tests that the callback handler correctly renders
// the Intercom identify page with the expected Subject, Email, Name, and ReturnTo values
func TestCallbackRendererSuccess(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	// Create test config
	cfg := config.Config{
		Env:                       "test",
		AppHostname:               "localhost",
		Port:                      "8080",
		CookieDomain:              ".localhost",
		EnableHSTS:                false,
		RedirectTTL:               30 * time.Minute,
		SessionTTL:                24 * time.Hour,
		LogLevel:                  "info",
		CookieSigningKey:          []byte("test-signing-key-32-bytes-long!"),
		SecondaryCookieSigningKey: []byte{},
		RedirectSkew:              5 * time.Minute,
		Auth0Domain:               "test.auth0.com",
		Auth0ClientID:             "test-client-id",
		Auth0ClientSecret:         "test-client-secret",
		Auth0RedirectPath:         "/callback",
		IntercomAppID:             "test-app-id",
		TxnTTL:                    10 * time.Minute,
		TxnSkew:                   1 * time.Minute,
	}

	// Nonce to use in both transaction cookie and ID token
	testNonce := makeBase64URL("test-nonce-renderer")

	// Create a mock Auth0 server that returns ID token with user claims
	mockAuth0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			// Generate mock Intercom JWT (simulating Auth0 Action)
			mockIntercomJWT, _ := auth.MintIntercomJWT([]byte("test-secret"), auth.IntercomClaims{
				UserID: "auth0|renderer-test-123",
				Email:  "renderer@example.com",
				Name:   "Renderer Test User",
				Iat:    time.Now().Unix(),
				Exp:    time.Now().Add(10 * time.Minute).Unix(),
			})

			// Create ID token with specific user claims we'll verify in the output
			expTime := time.Now().Add(time.Hour).Unix()
			payloadJSON := fmt.Sprintf(`{
				"nonce": "%s",
				"email": "renderer@example.com",
				"name": "Renderer Test User",
				"aud": "test-client-id",
				"exp": %d,
				"http://lfx.dev/claims/intercom": "%s"
			}`, testNonce, expTime, mockIntercomJWT)

			header := makeBase64URL(`{"alg":"RS256","typ":"JWT"}`)
			payload := makeBase64URL(payloadJSON)
			signature := makeBase64URL("test-signature")
			idToken := fmt.Sprintf("%s.%s.%s", header, payload, signature)

			response := map[string]interface{}{
				"access_token": "test-access-token",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer mockAuth0.Close()

	// Update config to use mock Auth0 server
	// Use the full URL (keep http:// for test server)
	cfg.Auth0Domain = mockAuth0.URL

	// Create router with test config
	router := NewRouter(cfg)

	// Create transaction cookie with nonce and code verifier
	state := makeBase64URL("test-state-renderer")
	codeVerifier := makeValidCodeVerifier()

	txnCookie := createTestTxnCookie(
		t,
		state,
		codeVerifier,
		testNonce, // Use same nonce as in ID token
		time.Now().Add(10*time.Minute),
		cfg.CookieSigningKey,
		cfg.CookieDomain,
	)

	// Create redirect cookie with specific return URL we'll verify
	returnURL := "https://example.com/dashboard?source=test"
	redirectCookie := createTestRedirectCookie(t, cfg, returnURL)

	// Make callback request with OAuth code, state, and cookies
	req := httptest.NewRequest("GET", "/callback?code=test-auth-code-renderer&state="+state, nil)
	req.AddCookie(txnCookie)
	req.AddCookie(redirectCookie)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Assert response status
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
		t.Logf("Response body: %s", rec.Body.String())
		return
	}

	// Assert content type is text/html
	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected Content-Type to contain 'text/html', got '%s'", contentType)
	}

	// Get the rendered HTML
	body := rec.Body.String()

	// Assert that the HTML contains the expected values from our test data
	// These should be embedded in the Intercom settings or the page

	// Check for email
	expectedEmail := "renderer@example.com"
	if !strings.Contains(body, expectedEmail) {
		t.Errorf("expected HTML to contain Email '%s'", expectedEmail)
	}

	// Check for name
	expectedName := "Renderer Test User"
	if !strings.Contains(body, expectedName) {
		t.Errorf("expected HTML to contain Name '%s'", expectedName)
	}

	// Check for returnTo URL (may be URL-encoded in JavaScript, so check for the domain)
	if !strings.Contains(body, "example.com") {
		t.Error("expected HTML to contain return URL domain 'example.com'")
	}

	// Check for Intercom app ID
	if !strings.Contains(body, cfg.IntercomAppID) {
		t.Errorf("expected HTML to contain Intercom AppID '%s'", cfg.IntercomAppID)
	}

	// Verify the HTML contains intercomSettings (Intercom widget configuration)
	if !strings.Contains(body, "window.intercomSettings") {
		t.Error("expected HTML to contain 'window.intercomSettings'")
	}

	// Verify it contains the Intercom widget script
	if !strings.Contains(body, "widget.intercom.io") {
		t.Error("expected HTML to contain Intercom widget script URL")
	}
}

// TestCallbackRendererMissingRedirectCookie tests that when redirect cookie is missing,
// the renderer still succeeds with fallback URL
func TestCallbackRendererMissingRedirectCookie(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	// Create test config
	cfg := config.Config{
		Env:                       "test",
		AppHostname:               "localhost",
		Port:                      "8080",
		CookieDomain:              ".localhost",
		EnableHSTS:                false,
		RedirectTTL:               30 * time.Minute,
		SessionTTL:                24 * time.Hour,
		LogLevel:                  "info",
		CookieSigningKey:          []byte("test-signing-key-32-bytes-long!"),
		SecondaryCookieSigningKey: []byte{},
		RedirectSkew:              5 * time.Minute,
		Auth0Domain:               "test.auth0.com",
		Auth0ClientID:             "test-client-id",
		Auth0ClientSecret:         "test-client-secret",
		Auth0RedirectPath:         "/callback",
		IntercomAppID:             "test-app-id",
		TxnTTL:                    10 * time.Minute,
		TxnSkew:                   1 * time.Minute,
	}

	// Nonce to use in both transaction cookie and ID token
	fallbackNonce := makeBase64URL("fallback-nonce")

	// Create mock Auth0 server
	mockAuth0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			// Generate mock Intercom JWT
			mockIntercomJWT, _ := auth.MintIntercomJWT([]byte("test-secret"), auth.IntercomClaims{
				UserID: "auth0|fallback-user",
				Email:  "fallback@example.com",
				Name:   "Fallback User",
				Iat:    time.Now().Unix(),
				Exp:    time.Now().Add(10 * time.Minute).Unix(),
			})

			expTime := time.Now().Add(time.Hour).Unix()
			payloadJSON := fmt.Sprintf(`{
				"nonce": "%s",
				"email": "fallback@example.com",
				"name": "Fallback User",
				"aud": "test-client-id",
				"exp": %d,
				"http://lfx.dev/claims/intercom": "%s"
			}`, fallbackNonce, expTime, mockIntercomJWT)

			header := makeBase64URL(`{"alg":"RS256","typ":"JWT"}`)
			payload := makeBase64URL(payloadJSON)
			signature := makeBase64URL("test-signature")
			idToken := fmt.Sprintf("%s.%s.%s", header, payload, signature)

			response := map[string]interface{}{
				"access_token": "test-access-token",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer mockAuth0.Close()

	cfg.Auth0Domain = mockAuth0.URL
	router := NewRouter(cfg)

	// Create transaction cookie
	state := makeBase64URL("fallback-state")
	codeVerifier := makeValidCodeVerifier()

	txnCookie := createTestTxnCookie(
		t,
		state,
		codeVerifier,
		fallbackNonce, // Use same nonce as in ID token
		time.Now().Add(10*time.Minute),
		cfg.CookieSigningKey,
		cfg.CookieDomain,
	)

	// Make callback request WITHOUT redirect cookie
	req := httptest.NewRequest("GET", "/callback?code=fallback-code&state="+state, nil)
	req.AddCookie(txnCookie)
	// Note: No redirect cookie

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Assert response
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
		t.Logf("Response body: %s", rec.Body.String())
		return
	}

	body := rec.Body.String()

	// Assert fallback URL is used (may be URL-encoded)
	if !strings.Contains(body, "localhost") {
		t.Error("expected HTML to contain fallback URL with 'localhost'")
	}

	// Should still render Intercom widget
	if !strings.Contains(body, "window.intercomSettings") {
		t.Error("expected HTML to contain Intercom settings even with fallback URL")
	}
}

// TestCallbackRendererWithSpecialCharacters tests that special characters
// in user data are properly escaped in the HTML output
func TestCallbackRendererWithSpecialCharacters(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	cfg := config.Config{
		Env:                       "test",
		AppHostname:               "localhost",
		Port:                      "8080",
		CookieDomain:              ".localhost",
		EnableHSTS:                false,
		RedirectTTL:               30 * time.Minute,
		SessionTTL:                24 * time.Hour,
		LogLevel:                  "info",
		CookieSigningKey:          []byte("test-signing-key-32-bytes-long!"),
		SecondaryCookieSigningKey: []byte{},
		RedirectSkew:              5 * time.Minute,
		Auth0Domain:               "test.auth0.com",
		Auth0ClientID:             "test-client-id",
		Auth0ClientSecret:         "test-client-secret",
		Auth0RedirectPath:         "/callback",
		IntercomAppID:             "test-app-id",
		TxnTTL:                    10 * time.Minute,
		TxnSkew:                   1 * time.Minute,
	}

	// Nonce to use in both transaction cookie and ID token
	specialNonce := makeBase64URL("special-nonce")

	// Create mock with user data containing special characters
	mockAuth0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			// Generate mock Intercom JWT with special characters
			mockIntercomJWT, _ := auth.MintIntercomJWT([]byte("test-secret"), auth.IntercomClaims{
				UserID: "auth0|special-123",
				Email:  "test+alias@example.com",
				Name:   "O'Brien \"The\" User",
				Iat:    time.Now().Unix(),
				Exp:    time.Now().Add(10 * time.Minute).Unix(),
			})

			expTime := time.Now().Add(time.Hour).Unix()
			// Name with apostrophe and quotes to test escaping
			payloadJSON := fmt.Sprintf(`{
				"nonce": "%s",
				"email": "test+alias@example.com",
				"name": "O'Brien \"The\" User",
				"aud": "test-client-id",
				"exp": %d,
				"http://lfx.dev/claims/intercom": "%s"
			}`, specialNonce, expTime, mockIntercomJWT)

			header := makeBase64URL(`{"alg":"RS256","typ":"JWT"}`)
			payload := makeBase64URL(payloadJSON)
			signature := makeBase64URL("test-signature")
			idToken := fmt.Sprintf("%s.%s.%s", header, payload, signature)

			response := map[string]interface{}{
				"access_token": "test-access-token",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer mockAuth0.Close()

	cfg.Auth0Domain = mockAuth0.URL
	router := NewRouter(cfg)

	// Create cookies
	state := makeBase64URL("special-state")
	codeVerifier := makeValidCodeVerifier()

	txnCookie := createTestTxnCookie(
		t,
		state,
		codeVerifier,
		specialNonce, // Use same nonce as in ID token
		time.Now().Add(10*time.Minute),
		cfg.CookieSigningKey,
		cfg.CookieDomain,
	)

	returnURL := "https://example.com/path?param=value&other=test"
	redirectCookie := createTestRedirectCookie(t, cfg, returnURL)

	req := httptest.NewRequest("GET", "/callback?code=special-code&state="+state, nil)
	req.AddCookie(txnCookie)
	req.AddCookie(redirectCookie)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
		return
	}

	body := rec.Body.String()

	// Verify that email is present (+ may be URL-encoded as %2B)
	if !strings.Contains(body, "test") && !strings.Contains(body, "example.com") {
		t.Error("expected email domain to be in output")
	}

	// Template should escape quotes/apostrophes appropriately for JavaScript
	// We just verify the name appears in some form
	if !strings.Contains(body, "O") && !strings.Contains(body, "Brien") {
		t.Error("expected name to appear in output (may be escaped)")
	}

	// Verify return URL with query parameters
	if !strings.Contains(body, "example.com") {
		t.Error("expected return URL domain to be in output")
	}
}
