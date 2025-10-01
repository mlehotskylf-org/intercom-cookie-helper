package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/auth"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

func TestLogoutHandler_NoAcceptHeader(t *testing.T) {
	// Setup config
	cfg := config.Config{
		CookieDomain:  "localhost",
		AppHostname:   "localhost",
		Port:          "8080",
		Env:           "dev",
		EnableLogout: true,
	}

	// Create request without Accept header
	req := httptest.NewRequest("GET", "/logout", nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	logoutHandler(rr, req)

	// Should return 204 No Content
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}

	// Check Cache-Control header
	cacheControl := rr.Header().Get("Cache-Control")
	if cacheControl != "no-store, max-age=0" {
		t.Errorf("Expected Cache-Control: no-store, max-age=0, got %s", cacheControl)
	}

	// Check Pragma header
	pragma := rr.Header().Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("Expected Pragma: no-cache, got %s", pragma)
	}

	// Check that both cookies are cleared
	cookies := rr.Result().Cookies()
	foundTxnCookie := false
	foundRedirectCookie := false

	for _, cookie := range cookies {
		if cookie.Name == auth.TxnCookieName {
			foundTxnCookie = true
			if cookie.MaxAge != -1 && cookie.Value != "" {
				t.Error("Transaction cookie should be cleared (MaxAge=-1 or empty value)")
			}
		}
		if cookie.Name == security.RedirectCookieName {
			foundRedirectCookie = true
			if cookie.MaxAge != -1 && cookie.Value != "" {
				t.Error("Redirect cookie should be cleared (MaxAge=-1 or empty value)")
			}
		}
	}

	if !foundTxnCookie {
		t.Error("Transaction cookie should be set (to clear it)")
	}
	if !foundRedirectCookie {
		t.Error("Redirect cookie should be set (to clear it)")
	}

	// Body should be empty for 204
	if rr.Body.Len() != 0 {
		t.Errorf("Expected empty body for 204, got %d bytes", rr.Body.Len())
	}
}

func TestLogoutHandler_HTMLAccept(t *testing.T) {
	// Setup config without Auth0 logout enabled
	cfg := config.Config{
		CookieDomain:      "localhost",
		AppHostname:       "localhost",
		Port:              "8080",
		Env:               "dev",
		Auth0Domain:       "test.auth0.com",
		Auth0ClientID:     "test-client-id",
		EnableLogout:      true,
		EnableAuth0Logout: false,
	}

	// Create request with Accept: text/html
	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Accept", "text/html")
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	logoutHandler(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Check Content-Type
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected text/html content type, got %s", contentType)
	}

	// Check Cache-Control header
	cacheControl := rr.Header().Get("Cache-Control")
	if cacheControl != "no-store, max-age=0" {
		t.Errorf("Expected Cache-Control: no-store, max-age=0, got %s", cacheControl)
	}

	// Check Pragma header
	pragma := rr.Header().Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("Expected Pragma: no-cache, got %s", pragma)
	}

	// Check that both cookies are cleared
	cookies := rr.Result().Cookies()
	foundTxnCookie := false
	foundRedirectCookie := false

	for _, cookie := range cookies {
		if cookie.Name == auth.TxnCookieName {
			foundTxnCookie = true
		}
		if cookie.Name == security.RedirectCookieName {
			foundRedirectCookie = true
		}
	}

	if !foundTxnCookie {
		t.Error("Transaction cookie should be set (to clear it)")
	}
	if !foundRedirectCookie {
		t.Error("Redirect cookie should be set (to clear it)")
	}

	// Check HTML body content
	body := rr.Body.String()
	expectedStrings := []string{
		"<!DOCTYPE html>",
		"<title>Signed Out</title>",
		"<h1>Signed out</h1>",
		"You have been signed out.",
		"Return",
		`<meta name="robots" content="noindex">`,
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected HTML to contain %q, but it didn't", expected)
		}
	}

	// Check that return URL is present and uses HTTP for localhost dev
	if !strings.Contains(body, "http://localhost:8080/") {
		t.Error("Expected return URL to be http://localhost:8080/ for dev environment")
	}

	// Auth0 logout link should NOT be present when disabled
	if strings.Contains(body, "Sign out of your account") {
		t.Error("Auth0 logout link should not be present when EnableAuth0Logout is false")
	}
	if strings.Contains(body, "/v2/logout") {
		t.Error("Auth0 logout URL should not be present when EnableAuth0Logout is false")
	}
}

func TestLogoutHandler_HTMLAcceptWithAuth0Enabled(t *testing.T) {
	// Setup config WITH Auth0 logout enabled
	cfg := config.Config{
		CookieDomain:      "localhost",
		AppHostname:       "localhost",
		Port:              "8080",
		Env:               "dev",
		Auth0Domain:       "test.auth0.com",
		Auth0ClientID:     "test-client-id",
		EnableLogout:      true,
		EnableAuth0Logout: true,
	}

	// Create request with Accept: text/html
	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Accept", "text/html")
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	logoutHandler(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Check HTML body content
	body := rr.Body.String()

	// Auth0 logout link SHOULD be present when enabled
	if !strings.Contains(body, "Sign out of your account") {
		t.Error("Auth0 logout link should be present when EnableAuth0Logout is true")
	}
	if !strings.Contains(body, "/v2/logout") {
		t.Error("Auth0 logout URL should be present when EnableAuth0Logout is true")
	}

	// Verify the full Auth0 URL is properly formatted
	if !strings.Contains(body, "https://test.auth0.com/v2/logout?client_id=test-client-id") {
		t.Error("Auth0 logout URL should be properly formatted with domain and client_id")
	}
}

func TestLogoutHandler_ProductionHTTPS(t *testing.T) {
	// Setup production config
	cfg := config.Config{
		CookieDomain:      ".example.com",
		AppHostname:       "example.com",
		Port:              "8080",
		Env:               "prod",
		Auth0Domain:       "example.auth0.com",
		Auth0ClientID:     "prod-client-id",
		EnableLogout:      true,
		EnableAuth0Logout: false,
	}

	// Create request with Accept: text/html
	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Accept", "text/html")
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	logoutHandler(rr, req)

	// Check that return URL uses HTTPS for production
	body := rr.Body.String()
	if !strings.Contains(body, "https://example.com/") {
		t.Error("Expected return URL to be https://example.com/ for production environment")
	}
	if strings.Contains(body, "http://example.com/") {
		t.Error("Should not use HTTP for production environment")
	}
}

func TestLogoutHandler_NoConfig(t *testing.T) {
	// Create request without config in context
	req := httptest.NewRequest("GET", "/logout", nil)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	logoutHandler(rr, req)

	// Should return 500 Internal Server Error
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", rr.Code)
	}
}

func TestLogoutHandler_JSONAccept(t *testing.T) {
	// Setup config
	cfg := config.Config{
		CookieDomain:  "localhost",
		AppHostname:   "localhost",
		Port:          "8080",
		Env:           "dev",
		EnableLogout: true,
	}

	// Create request with Accept: application/json (API client)
	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Accept", "application/json")
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	logoutHandler(rr, req)

	// Should return 204 No Content (not HTML)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204 for JSON accept, got %d", rr.Code)
	}

	// Body should be empty
	if rr.Body.Len() != 0 {
		t.Errorf("Expected empty body for JSON accept, got %d bytes", rr.Body.Len())
	}
}

func TestLogoutHandler_WithReferer(t *testing.T) {
	// Setup config with allowed hosts
	cfg := config.Config{
		CookieDomain:       ".example.com",
		AppHostname:        "example.com",
		Port:               "8080",
		Env:                "prod",
		EnableLogout:       true,
		AllowedReturnHosts: []string{"example.com"},
		AllowedReturnHostsPreprocessed: []config.ProcessedHost{
			{Original: "example.com", Canonical: "example.com", IsWildcard: false},
		},
		AllowedQueryParams: []string{"utm_campaign", "utm_source"},
	}

	// Create request with valid HTTPS Referer header
	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "https://example.com/some-page")
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	logoutHandler(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Check that return URL uses the Referer (sanitizer returns HTTPS URLs)
	body := rr.Body.String()
	if !strings.Contains(body, "https://example.com/some-page") {
		t.Error("Expected return URL to use Referer header")
	}
}

func TestLogoutHandler_Disabled(t *testing.T) {
	// Setup config with logout DISABLED
	cfg := config.Config{
		CookieDomain:  "localhost",
		AppHostname:   "localhost",
		Port:          "8080",
		Env:           "dev",
		EnableLogout: false,
	}

	// Create request
	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Accept", "text/html")
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	logoutHandler(rr, req)

	// Should return 404 Not Found when disabled
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 when logout disabled, got %d", rr.Code)
	}
}

func TestLogoutHandler_WithInvalidReferer(t *testing.T) {
	// Setup config with allowed hosts
	cfg := config.Config{
		CookieDomain:       "localhost",
		AppHostname:        "localhost",
		Port:               "8080",
		Env:                "dev",
		EnableLogout:       true,
		AllowedReturnHosts: []string{"localhost"},
		AllowedReturnHostsPreprocessed: []config.ProcessedHost{
			{Original: "localhost", Canonical: "localhost", IsWildcard: false},
		},
		AllowedQueryParams: []string{"utm_campaign", "utm_source"},
	}

	// Create request with disallowed Referer
	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "http://evil.com/phishing")
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	logoutHandler(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Check that return URL falls back to safe default (not evil.com)
	body := rr.Body.String()
	if strings.Contains(body, "evil.com") {
		t.Error("Should not use disallowed Referer URL")
	}
	if !strings.Contains(body, "http://localhost:8080/") {
		t.Error("Should fall back to safe default URL")
	}
}
