package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// Config holds all application configuration
type Config struct {
	// Environment: dev, staging, or prod (default: dev)
	Env string

	// Application hostname (e.g., intercom-auth.riscv.org)
	AppHostname string

	// Server port (default: 8080)
	Port string

	// Cookie domain - eTLD+1 like .riscv.org
	CookieDomain string

	// Allowed return hosts - list of hosts that can be redirect targets
	AllowedReturnHosts []string

	// Preprocessed allowed hosts for fast wildcard matching
	AllowedReturnHostsPreprocessed []ProcessedHost

	// Allowed query params to preserve (default: ["utm_campaign", "utm_source"])
	AllowedQueryParams []string

	// Intercom application ID
	IntercomAppID string

	// Intercom JWT secret - dev only, prod uses secret manager
	IntercomJWTSecret string

	// Auth0 configuration
	Auth0Domain       string
	Auth0ClientID     string
	Auth0ClientSecret string // dev only, disallowed in prod

	// Auth0 redirect path (default: "/callback")
	Auth0RedirectPath string

	// Cookie signing key - decoded from hex or base64
	CookieSigningKey []byte

	// Secondary cookie signing key for key rotation (optional; empty in dev)
	SecondaryCookieSigningKey []byte

	// Redirect TTL - how long redirect URLs are valid (default: 30m)
	RedirectTTL time.Duration

	// Redirect skew - clock skew allowance for redirect cookies (default: 1m)
	RedirectSkew time.Duration

	// Session TTL - OIDC transaction cookie lifetime (default: 24h)
	SessionTTL time.Duration

	// Log level: info, debug, warn, error (default: info)
	LogLevel string

	// Enable HSTS - default false in dev, true in prod
	EnableHSTS bool
}

// ProcessedHost represents a processed host pattern for fast matching
type ProcessedHost struct {
	// Original pattern as provided by user (e.g., "*.example.com")
	Original string
	// Canonical pattern for fast matching (e.g., "example.com" for "*.example.com")
	Canonical string
	// IsWildcard indicates if this is a wildcard pattern
	IsWildcard bool
}

// FromEnv reads configuration from environment variables
func FromEnv() (Config, error) {
	cfg := Config{}

	// Environment
	cfg.Env = getEnv("ENV", "dev")

	// Basic settings with normalization
	appHostname := getEnv("APP_HOSTNAME", "")
	if appHostname != "" {
		normalized, err := normalizeHostname(appHostname)
		if err != nil {
			return cfg, fmt.Errorf("invalid APP_HOSTNAME: %w", err)
		}
		cfg.AppHostname = normalized
	}
	cfg.Port = getEnv("PORT", "8080")
	cfg.CookieDomain = getEnv("COOKIE_DOMAIN", "")

	// Parse allowed hosts from CSV with normalization
	allowedHosts := parseCSV("ALLOWED_RETURN_HOSTS")
	cfg.AllowedReturnHosts, cfg.AllowedReturnHostsPreprocessed = normalizeAllowedHosts(allowedHosts)

	// Parse allowed query params with defaults
	if params := parseCSV("ALLOWED_QUERY_PARAMS"); len(params) > 0 {
		cfg.AllowedQueryParams = params
	} else {
		cfg.AllowedQueryParams = []string{"utm_campaign", "utm_source"}
	}

	// Intercom settings
	cfg.IntercomAppID = getEnv("INTERCOM_APP_ID", "")
	cfg.IntercomJWTSecret = getEnv("INTERCOM_JWT_SECRET", "")

	// Auth0 settings
	cfg.Auth0Domain = getEnv("AUTH0_DOMAIN", "")
	cfg.Auth0ClientID = getEnv("AUTH0_CLIENT_ID", "")
	cfg.Auth0ClientSecret = getEnv("AUTH0_CLIENT_SECRET", "")
	cfg.Auth0RedirectPath = getEnv("AUTH0_REDIRECT_PATH", "/callback")

	// Parse cookie signing key from hex or base64
	if key := getEnv("COOKIE_SIGNING_KEY", ""); key != "" {
		var err error
		cfg.CookieSigningKey, err = decodeKey(key)
		if err != nil {
			return cfg, err
		}
	}

	// Parse secondary cookie signing key (optional)
	if key := getEnv("SECONDARY_COOKIE_SIGNING_KEY", ""); key != "" {
		var err error
		cfg.SecondaryCookieSigningKey, err = decodeKey(key)
		if err != nil {
			return cfg, fmt.Errorf("invalid SECONDARY_COOKIE_SIGNING_KEY: %w", err)
		}
	}

	// Parse durations with defaults
	var err error
	cfg.RedirectTTL, err = parseDuration("REDIRECT_TTL", "30m")
	if err != nil {
		return cfg, err
	}

	cfg.SessionTTL, err = parseDuration("SESSION_TTL", "24h")
	if err != nil {
		return cfg, err
	}

	cfg.RedirectSkew, err = parseDuration("REDIRECT_SKEW", "1m")
	if err != nil {
		return cfg, err
	}

	// Log level
	cfg.LogLevel = strings.ToLower(getEnv("LOG_LEVEL", "info"))

	// HSTS - default based on environment
	cfg.EnableHSTS = parseBool("ENABLE_HSTS", cfg.Env == "prod")

	return cfg, nil
}

// Validate checks that required fields are set and enforces prod constraints
func (c *Config) Validate() error {
	// Check required fields
	if c.AppHostname == "" {
		return fmt.Errorf("APP_HOSTNAME is required (set to your domain, e.g., intercom-auth.example.com)")
	}

	// Validate PORT format and range
	if c.Port == "" {
		return fmt.Errorf("PORT is required (set to a port number 1-65535, e.g., 8080)")
	}
	if port, err := strconv.Atoi(c.Port); err != nil {
		return fmt.Errorf("PORT must be a valid number 1-65535 (got %q)", c.Port)
	} else if port < 1 || port > 65535 {
		return fmt.Errorf("PORT must be 1-65535 (got %q)", c.Port)
	}

	// Validate COOKIE_DOMAIN format
	if c.CookieDomain == "" {
		return fmt.Errorf("COOKIE_DOMAIN is required (set to your domain with leading dot, e.g., .example.com)")
	}
	if !strings.HasPrefix(c.CookieDomain, ".") {
		return fmt.Errorf("COOKIE_DOMAIN must start with '.' for subdomain sharing (got %q, use %q)", c.CookieDomain, "."+c.CookieDomain)
	}
	if !strings.Contains(c.CookieDomain[1:], ".") {
		return fmt.Errorf("COOKIE_DOMAIN must contain a dot after the leading dot (got %q, expected format like '.example.com')", c.CookieDomain)
	}

	if c.IntercomAppID == "" {
		return fmt.Errorf("INTERCOM_APP_ID is required (get from your Intercom app settings)")
	}

	if c.Auth0Domain == "" {
		return fmt.Errorf("AUTH0_DOMAIN is required (set to your Auth0 tenant domain, e.g., your-tenant.auth0.com)")
	}

	if c.Auth0ClientID == "" {
		return fmt.Errorf("AUTH0_CLIENT_ID is required (get from your Auth0 application settings)")
	}

	if len(c.CookieSigningKey) == 0 {
		return fmt.Errorf("COOKIE_SIGNING_KEY is required (generate a 32+ byte hex string for cookie security)")
	}
	if len(c.CookieSigningKey) < 32 {
		return fmt.Errorf("COOKIE_SIGNING_KEY must be at least 32 bytes for security (got %d bytes, need 32+)", len(c.CookieSigningKey))
	}

	// Validate secondary cookie signing key (optional, but if provided must be valid)
	if len(c.SecondaryCookieSigningKey) > 0 && len(c.SecondaryCookieSigningKey) < 32 {
		return fmt.Errorf("SECONDARY_COOKIE_SIGNING_KEY must be at least 32 bytes for security (got %d bytes, need 32+)", len(c.SecondaryCookieSigningKey))
	}

	// Validate redirect skew (0-2m range)
	if c.RedirectSkew < 0 {
		return fmt.Errorf("REDIRECT_SKEW must be non-negative (got %v)", c.RedirectSkew)
	}
	if c.RedirectSkew > 2*time.Minute {
		return fmt.Errorf("REDIRECT_SKEW must not exceed 2 minutes for security (got %v, max 2m)", c.RedirectSkew)
	}

	// Validate environment value
	switch c.Env {
	case "dev", "staging", "prod":
		// valid
	default:
		return fmt.Errorf("ENV must be 'dev', 'staging', or 'prod' (got %q)", c.Env)
	}

	// Validate log level
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("LOG_LEVEL must be 'debug', 'info', 'warn', or 'error' (got %q)", c.LogLevel)
	}

	// Production-only constraints
	if c.Env == "prod" {
		if c.IntercomJWTSecret != "" {
			return fmt.Errorf("in prod, INTERCOM_JWT_SECRET must be unset (use secret manager instead)")
		}
		if c.Auth0ClientSecret != "" {
			return fmt.Errorf("in prod, AUTH0_CLIENT_SECRET must be unset (use secret manager instead)")
		}
	} else {
		// In dev/staging, these are required
		if c.IntercomJWTSecret == "" {
			return fmt.Errorf("INTERCOM_JWT_SECRET is required in %s environment (set a test secret or get from Intercom)", c.Env)
		}
		if c.Auth0ClientSecret == "" {
			return fmt.Errorf("AUTH0_CLIENT_SECRET is required in %s environment (get from Auth0 application settings)", c.Env)
		}
	}

	return nil
}

// Helper functions

// getEnv returns the value of an environment variable or a default value
func getEnv(key, def string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return def
}

// parseCSV splits a CSV environment variable into a slice
// It trims spaces, converts to lowercase, deduplicates, and drops empty values
func parseCSV(key string) []string {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, p := range parts {
		trimmed := strings.TrimSpace(strings.ToLower(p))
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
	}
	return result
}

// parseDuration parses a duration environment variable with a default
func parseDuration(key, def string) (time.Duration, error) {
	value := getEnv(key, def)
	dur, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s: %w", key, err)
	}
	return dur, nil
}

// parseBool parses a boolean environment variable with a default
func parseBool(key string, def bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return def
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return def
	}
	return parsed
}

// decodeKey decodes a key from hex or base64 encoding
func decodeKey(key string) ([]byte, error) {
	if key == "" {
		return nil, fmt.Errorf("COOKIE_SIGNING_KEY is empty")
	}

	// Try hex first (most common for keys)
	if decoded, err := hex.DecodeString(key); err == nil {
		return decoded, nil
	}

	// Try standard base64
	if decoded, err := base64.StdEncoding.DecodeString(key); err == nil {
		return decoded, nil
	}

	// Try base64 URL encoding (no padding)
	if decoded, err := base64.RawURLEncoding.DecodeString(key); err == nil {
		return decoded, nil
	}

	return nil, fmt.Errorf("COOKIE_SIGNING_KEY must be valid hex or base64 encoding")
}

// normalizeHostname ensures hostname is host-only (no scheme/port)
func normalizeHostname(hostname string) (string, error) {
	// Check if it contains a scheme
	if strings.Contains(hostname, "://") {
		return "", fmt.Errorf("hostname must not contain scheme (found ://): %s", hostname)
	}

	// Check if it contains a port
	if strings.Contains(hostname, ":") {
		return "", fmt.Errorf("hostname must not contain port (found :): %s", hostname)
	}

	// Normalize to lowercase
	return strings.ToLower(strings.TrimSpace(hostname)), nil
}

// normalizeAllowedHosts processes the allowed hosts list
func normalizeAllowedHosts(hosts []string) ([]string, []ProcessedHost) {
	normalized := make([]string, len(hosts))
	processed := make([]ProcessedHost, len(hosts))

	for i, host := range hosts {
		// Normalize to lowercase and trim
		normalizedHost := strings.ToLower(strings.TrimSpace(host))
		normalized[i] = normalizedHost

		// Process for fast matching
		if strings.HasPrefix(normalizedHost, "*.") {
			// Wildcard pattern - strip the "*." prefix for canonical form
			canonical := normalizedHost[2:] // Remove "*."
			processed[i] = ProcessedHost{
				Original:   normalizedHost,
				Canonical:  canonical,
				IsWildcard: true,
			}
		} else {
			// Exact host match
			processed[i] = ProcessedHost{
				Original:   normalizedHost,
				Canonical:  normalizedHost,
				IsWildcard: false,
			}
		}
	}

	return normalized, processed
}

// BuildSanitizer creates a URL sanitizer from the configuration
func (c Config) BuildSanitizer() (*security.Sanitizer, error) {
	allow, err := security.NewHostAllowlist(c.AllowedReturnHosts)
	if err != nil {
		return nil, err
	}

	list := c.AllowedQueryParams
	if len(list) == 0 {
		list = []string{"utm_campaign", "utm_source"}
	}

	return security.NewSanitizer(allow, list), nil
}

// RedirectCookieOpts returns the cookie options for redirect cookies
func (c Config) RedirectCookieOpts() security.CookieOpts {
	return security.CookieOpts{
		Domain:   c.CookieDomain,
		Secure:   c.Env == "prod",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		TTL:      c.RedirectTTL,
		Skew:     c.RedirectSkew,
	}
}
