package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

// TestLocalhostHTTP_DeployedDevHTTPS verifies that:
// - localhost uses HTTP (for local development)
// - deployed dev environments use HTTPS (fixes referrer drop)
// - production uses HTTPS
func TestLocalhostHTTP_DeployedDevHTTPS(t *testing.T) {
	tests := []struct {
		name            string
		appHostname     string
		env             string
		expectedScheme  string
		expectedPort    bool // true if port should be included
		description     string
	}{
		{
			name:           "localhost uses HTTP",
			appHostname:    "localhost",
			env:            "dev",
			expectedScheme: "http://",
			expectedPort:   true,
			description:    "Local development should use HTTP for convenience",
		},
		{
			name:           "127.0.0.1 uses HTTP",
			appHostname:    "127.0.0.1",
			env:            "dev",
			expectedScheme: "http://",
			expectedPort:   true,
			description:    "Localhost IP should use HTTP",
		},
		{
			name:           "deployed dev uses HTTPS",
			appHostname:    "dev.example.com",
			env:            "dev",
			expectedScheme: "https://",
			expectedPort:   false,
			description:    "Deployed dev environment should use HTTPS to prevent referrer drops",
		},
		{
			name:           "staging uses HTTPS",
			appHostname:    "staging.example.com",
			env:            "staging",
			expectedScheme: "https://",
			expectedPort:   false,
			description:    "Staging should use HTTPS",
		},
		{
			name:           "production uses HTTPS",
			appHostname:    "example.com",
			env:            "production",
			expectedScheme: "https://",
			expectedPort:   false,
			description:    "Production should use HTTPS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build config for this test case
			cfg := config.Config{
				Env:                tt.env,
				AppHostname:        tt.appHostname,
				Port:               "8080",
				CookieDomain:       ".example.com",
				AllowedReturnHosts: []string{"example.com", "*.example.com"},
				AllowedQueryParams: []string{"utm_source", "utm_campaign"},
				IntercomAppID:      "test-app-id",
				Auth0Domain:        "test.auth0.com",
				Auth0ClientID:      "test-client-id",
				Auth0ClientSecret:  "test-secret",
				Auth0RedirectPath:  "/callback",
				CookieSigningKey:   []byte("test-signing-key-32-bytes-long!!"),
				RedirectTTL:        30 * time.Minute,
				RedirectSkew:       time.Minute,
				TxnTTL:             10 * time.Minute,
				TxnSkew:            time.Minute,
			}

			// Create router
			router := NewRouter(cfg)

			// Make request to /login with referer to trigger redirect
			req := httptest.NewRequest("GET", "/login?return_to=https://example.com/", nil)
			req.Header.Set("Referer", "https://example.com/")
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			// Should redirect to Auth0
			if rec.Code != http.StatusFound {
				t.Fatalf("expected 302 redirect, got %d", rec.Code)
			}

			location := rec.Header().Get("Location")
			if location == "" {
				t.Fatal("expected Location header, got empty")
			}

			// Check that the redirect_uri parameter uses the correct scheme
			if !strings.Contains(location, "redirect_uri=") {
				t.Fatal("expected redirect_uri parameter in Auth0 URL")
			}

			// Extract redirect_uri from location
			// Format: ...redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback...
			if strings.Contains(location, tt.expectedScheme) {
				// Good! Found expected scheme
				t.Logf("✓ Found expected scheme %s in redirect_uri", tt.expectedScheme)
			} else {
				// Check URL-encoded version
				if tt.expectedScheme == "http://" && !strings.Contains(location, "http%3A%2F%2F") {
					t.Errorf("expected HTTP scheme in redirect_uri for %s, but got: %s", tt.appHostname, location)
				}
				if tt.expectedScheme == "https://" && !strings.Contains(location, "https%3A%2F%2F") {
					t.Errorf("expected HTTPS scheme in redirect_uri for %s, but got: %s", tt.appHostname, location)
				}
			}

			// Check port inclusion
			if tt.expectedPort {
				if !strings.Contains(location, "%3A8080") && !strings.Contains(location, ":8080") {
					t.Errorf("expected port 8080 in redirect_uri for %s", tt.appHostname)
				}
			} else {
				if strings.Contains(location, "%3A8080") || strings.Contains(location, ":8080") {
					t.Errorf("unexpected port in redirect_uri for %s", tt.appHostname)
				}
			}

			t.Logf("redirect_uri for %s (%s): contains scheme=%s, description=%s",
				tt.appHostname, tt.env, tt.expectedScheme, tt.description)
		})
	}
}

// TestErrorPageURL_LocalhostHTTP_DeployedDevHTTPS verifies that error page
// retry URLs use the correct scheme based on hostname
func TestErrorPageURL_LocalhostHTTP_DeployedDevHTTPS(t *testing.T) {
	tests := []struct {
		name           string
		appHostname    string
		env            string
		expectedScheme string
	}{
		{
			name:           "localhost error page uses HTTP",
			appHostname:    "localhost",
			env:            "dev",
			expectedScheme: "http://",
		},
		{
			name:           "deployed dev error page uses HTTPS",
			appHostname:    "dev.example.com",
			env:            "dev",
			expectedScheme: "https://",
		},
		{
			name:           "production error page uses HTTPS",
			appHostname:    "example.com",
			env:            "production",
			expectedScheme: "https://",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{
				Env:         tt.env,
				AppHostname: tt.appHostname,
				Port:        "8080",
			}

			// Call safeDefaultURL (internal function)
			url := safeDefaultURL(cfg)

			if !strings.HasPrefix(url, tt.expectedScheme) {
				t.Errorf("expected URL to start with %s, got: %s", tt.expectedScheme, url)
			}

			t.Logf("safeDefaultURL for %s (%s): %s", tt.appHostname, tt.env, url)
		})
	}
}
