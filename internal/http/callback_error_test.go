package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

// TestHandleCallback_ErrorPage_InvalidState verifies that an invalid state parameter
// triggers the error page with appropriate message
func TestHandleCallback_ErrorPage_InvalidState(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	// Setup test configuration
	cfg := config.Config{
		CookieSigningKey: []byte("test-signing-key-32-bytes-long!!"),
		TxnSkew:          5 * time.Minute,
		TxnTTL:           10 * time.Minute,
		CookieDomain:     ".example.com",
		AppHostname:      "example.com",
		Auth0RedirectPath: "/callback",
		Env:              "prod",
		Port:             "8080",
	}

	// Create request with invalid state (no transaction cookie)
	req := httptest.NewRequest("GET", "/callback?code=test-code&state=invalid-state", nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call the callback handler
	handleCallback(rr, req)

	// Verify we got a 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	// Verify we got HTML error page
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected HTML content type, got %s", contentType)
	}

	// Check error page content
	body := rr.Body.String()
	if !strings.Contains(body, "We couldn't sign you in") {
		t.Error("Error page should contain 'We couldn't sign you in'")
	}
	if !strings.Contains(body, "Your session has expired") {
		t.Error("Error page should contain 'Your session has expired' for missing transaction cookie")
	}
	if !strings.Contains(body, "Try again") {
		t.Error("Error page should contain 'Try again' button")
	}
	if !strings.Contains(body, "/login?return_to=") {
		t.Error("Error page should contain link to login page")
	}
}

// TestHandleCallback_ErrorPage_StateMismatch verifies that state mismatch
// triggers the error page with security validation message
func TestHandleCallback_ErrorPage_StateMismatch(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	// Setup test configuration
	cfg := config.Config{
		CookieSigningKey: []byte("test-signing-key-32-bytes-long!!"),
		TxnSkew:          5 * time.Minute,
		TxnTTL:           10 * time.Minute,
		CookieDomain:     ".example.com",
		AppHostname:      "example.com",
		Auth0RedirectPath: "/callback",
		Env:              "prod",
		Port:             "8080",
	}

	// Create valid transaction cookie with different state
	validState := makeBase64URL("expected-state")
	validCV := makeValidCodeVerifier()
	validNonce := makeBase64URL("test-nonce")

	// Create request with mismatched state
	req := httptest.NewRequest("GET", "/callback?code=test-code&state=wrong-state", nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Add transaction cookie with different state
	txnCookie := createTestTxnCookie(
		t,
		validState, // Cookie has different state
		validCV,
		validNonce,
		time.Now().Add(10*time.Minute),
		cfg.CookieSigningKey,
		cfg.CookieDomain,
	)
	req.AddCookie(txnCookie)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call the callback handler
	handleCallback(rr, req)

	// Verify we got a 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	// Check error page content
	body := rr.Body.String()
	if !strings.Contains(body, "We couldn't sign you in") {
		t.Error("Error page should contain 'We couldn't sign you in'")
	}
	if !strings.Contains(body, "Security validation failed") {
		t.Error("Error page should contain 'Security validation failed' for state mismatch")
	}
}

// TestHandleCallback_ErrorPage_MissingCode verifies that missing code parameter
// triggers the error page with appropriate message
func TestHandleCallback_ErrorPage_MissingCode(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	// Setup test configuration
	cfg := config.Config{
		CookieSigningKey: []byte("test-signing-key-32-bytes-long!!"),
		AppHostname:      "example.com",
		Auth0RedirectPath: "/callback",
		Env:              "prod",
		Port:             "8080",
	}

	// Create request without code parameter
	req := httptest.NewRequest("GET", "/callback?state=some-state", nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call the callback handler
	handleCallback(rr, req)

	// Verify we got a 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	// Check error page content
	body := rr.Body.String()
	if !strings.Contains(body, "We couldn't sign you in") {
		t.Error("Error page should contain 'We couldn't sign you in'")
	}
	if !strings.Contains(body, "Missing required authentication parameters") {
		t.Error("Error page should contain message about missing parameters")
	}
}

// TestHandleCallback_ErrorPage_Auth0Error verifies that Auth0 error parameter
// triggers the error page with the error description
func TestHandleCallback_ErrorPage_Auth0Error(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	// Setup test configuration
	cfg := config.Config{
		CookieSigningKey: []byte("test-signing-key-32-bytes-long!!"),
		AppHostname:      "example.com",
		Auth0RedirectPath: "/callback",
		Env:              "prod",
		Port:             "8080",
	}

	// Create request with Auth0 error
	req := httptest.NewRequest("GET", "/callback?error=access_denied&error_description=User+cancelled+login", nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call the callback handler
	handleCallback(rr, req)

	// Verify we got a 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	// Check error page content
	body := rr.Body.String()
	if !strings.Contains(body, "We couldn't sign you in") {
		t.Error("Error page should contain 'We couldn't sign you in'")
	}
	if !strings.Contains(body, "User cancelled login") {
		t.Error("Error page should contain the Auth0 error description")
	}
}

// TestHandleCallback_ErrorPage_LocalhostConfig verifies error page works
// correctly with localhost configuration for development
func TestHandleCallback_ErrorPage_LocalhostConfig(t *testing.T) {
	// Setup test template
	cleanup := setupTestTemplate(t)
	defer cleanup()

	// Setup localhost configuration
	cfg := config.Config{
		CookieSigningKey: []byte("test-signing-key-32-bytes-long!!"),
		AppHostname:      "localhost",
		Auth0RedirectPath: "/callback",
		Env:              "dev",
		Port:             "8080",
	}

	// Create request with invalid state
	req := httptest.NewRequest("GET", "/callback?code=test&state=invalid", nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call the callback handler
	handleCallback(rr, req)

	// Verify we got a 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	// Check that Try Again URL uses HTTP for localhost
	body := rr.Body.String()
	if !strings.Contains(body, "/login?return_to=http%3A%2F%2Flocalhost%3A8080%2F") {
		t.Error("Error page should use HTTP scheme for localhost in dev mode")
	}
}