package httpx

import (
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

// newTestConfig creates a valid test configuration with all required fields
func newTestConfig() config.Config {
	return config.Config{
		Env:                "test",
		AppHostname:        "localhost",
		Port:               "8080",
		CookieDomain:       ".localhost",
		AllowedReturnHosts: []string{"example.com", "*.example.com"},
		AllowedQueryParams: []string{"utm_source", "utm_campaign"},

		// Auth0 configuration (required for login handler)
		Auth0Domain:       "test.auth0.com",
		Auth0ClientID:     "test-client-id",
		Auth0ClientSecret: "test-client-secret",
		Auth0RedirectPath: "/callback",

		// Intercom configuration
		IntercomAppID:     "test-app-id",
		IntercomJWTSecret: "test-jwt-secret",

		// Cookie configuration
		CookieSigningKey: []byte("test-signing-key-32-bytes-long!!"),
		RedirectTTL:      30 * time.Minute,
		RedirectSkew:     1 * time.Minute,
		SessionTTL:       24 * time.Hour,
		TxnTTL:           10 * time.Minute,
		TxnSkew:          1 * time.Minute,

		// Other settings
		LogLevel:   "info",
		EnableHSTS: false,
	}
}
