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
		CookieDomain: "localhost",
		AppHostname:  "localhost",
		Port:         "8080",
		Env:          "dev",
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
	if cacheControl != "no-store" {
		t.Errorf("Expected Cache-Control: no-store, got %s", cacheControl)
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
	// Setup config
	cfg := config.Config{
		CookieDomain:      "localhost",
		AppHostname:       "localhost",
		Port:              "8080",
		Env:               "dev",
		Auth0Domain:       "test.auth0.com",
		Auth0ClientID:     "test-client-id",
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
	if cacheControl != "no-store" {
		t.Errorf("Expected Cache-Control: no-store, got %s", cacheControl)
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
		"You have been signed out from this helper",
		"Return",
		`<meta name="robots" content="noindex">`,
		"Sign out of your account", // Auth0 logout link
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

	// Check that Auth0 logout URL is present
	if !strings.Contains(body, "/v2/logout") {
		t.Error("Expected Auth0 logout URL to be present")
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
		CookieDomain: "localhost",
		AppHostname:  "localhost",
		Port:         "8080",
		Env:          "dev",
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
