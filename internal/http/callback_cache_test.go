package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

func TestCallbackCacheHeaders(t *testing.T) {
	// Test that callback handler sets proper cache headers
	// Setup mock Auth0 server
	mockAuth0 := NewMockAuth0Server()
	defer mockAuth0.Close()

	// Create valid ID token with nonce
	nonce := "test-nonce-12345"
	mockAuth0.Nonce = nonce

	// Set up mock to return success with default response (includes ID token)
	mockAuth0.TokenResponse = nil
	mockAuth0.TokenError = nil

	// Create test config
	cfg := config.Config{
		Auth0Domain:           strings.TrimPrefix(mockAuth0.URL, "http://"),
		Auth0ClientID:         "test-client-id",
		Auth0ClientSecret:     "test-client-secret",
		CookieSigningKey:      []byte("test-signing-key-32-bytes-long!!"),
		CookieDomain:          "localhost",
		AppHostname:           "localhost",
		Port:                  "8080",
		Env:                   "dev",
		AllowedReturnHosts:    []string{"example.com"},
		AllowedQueryParams:    []string{"utm_campaign"},
		IntercomAppID:         "test-app-id",
		IntercomJWTSecret:     []byte("test-jwt-secret"),
		IntercomJWTTTL:        10 * time.Minute,
		TxnTTL:                10 * time.Minute,
		TxnSkew:               5 * time.Minute,
		RedirectTTL:           30 * time.Minute,
		RedirectSkew:          1 * time.Minute,
	}

	// Create valid transaction cookie using helper
	state := makeBase64URL("test-state-12345")
	codeVerifier := makeValidCodeVerifier()
	txnCookie := createTestTxnCookie(
		t,
		state,
		codeVerifier,
		nonce,
		time.Now().Add(10*time.Minute),
		cfg.CookieSigningKey,
		cfg.CookieDomain,
	)

	// Create request with valid params
	req := httptest.NewRequest("GET", "/callback?code=test-code&state="+state, nil)
	req.AddCookie(txnCookie)
	req.Header.Set("Accept", "text/html")
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	handleCallback(rr, req)

	// Verify Cache-Control header
	cacheControl := rr.Header().Get("Cache-Control")
	if cacheControl != "no-store, max-age=0" {
		t.Errorf("Expected Cache-Control: no-store, max-age=0, got %s", cacheControl)
	}

	// Verify Pragma header
	pragma := rr.Header().Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("Expected Pragma: no-cache, got %s", pragma)
	}
}
