package httpx

import (
	"net/http/httptest"
	"testing"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

func TestLoginCacheHeaders(t *testing.T) {
	// Test that login handler sets proper cache headers
	cfg := config.Config{
		Auth0Domain:        "test.auth0.com",
		Auth0ClientID:      "test-client-id",
		Auth0ClientSecret:  "test-client-secret",
		CookieSigningKey:   []byte("test-signing-key-32-bytes-long!"),
		CookieDomain:       "localhost",
		AppHostname:        "localhost",
		Port:               "8080",
		Env:                "dev",
		AllowedReturnHosts: []string{"example.com"},
		AllowedQueryParams: []string{"utm_campaign"},
	}

	// Create host allowlist and sanitizer
	allowlist, err := security.NewHostAllowlist(cfg.AllowedReturnHosts)
	if err != nil {
		t.Fatalf("Failed to create allowlist: %v", err)
	}
	sanitizer := security.NewSanitizer(allowlist, cfg.AllowedQueryParams)

	// Create request with valid return_to
	req := httptest.NewRequest("GET", "/login?return_to=https://example.com/dashboard", nil)
	req = req.WithContext(withTestConfig(req.Context(), cfg))

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler directly
	handler := loginHandler(sanitizer)
	handler(rr, req)

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
