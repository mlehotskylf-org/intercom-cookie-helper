package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
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

	// Redirect TTL - how long redirect URLs are valid (default: 30m)
	RedirectTTL time.Duration

	// Session TTL - OIDC transaction cookie lifetime (default: 24h)
	SessionTTL time.Duration

	// Log level: info, debug, warn, error (default: info)
	LogLevel string

	// Enable HSTS - default false in dev, true in prod
	EnableHSTS bool
}

// FromEnv reads configuration from environment variables
func FromEnv() (Config, error) {
	cfg := Config{}

	// Environment
	cfg.Env = getEnv("ENV", "dev")

	// Basic settings
	cfg.AppHostname = getEnv("APP_HOSTNAME", "")
	cfg.Port = getEnv("PORT", "8080")
	cfg.CookieDomain = getEnv("COOKIE_DOMAIN", "")

	// Parse allowed hosts from CSV
	cfg.AllowedReturnHosts = parseCSV("ALLOWED_RETURN_HOSTS")

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
		return fmt.Errorf("APP_HOSTNAME is required")
	}

	if c.CookieDomain == "" {
		return fmt.Errorf("COOKIE_DOMAIN is required")
	}

	if c.IntercomAppID == "" {
		return fmt.Errorf("INTERCOM_APP_ID is required")
	}

	if c.Auth0Domain == "" {
		return fmt.Errorf("AUTH0_DOMAIN is required")
	}

	if c.Auth0ClientID == "" {
		return fmt.Errorf("AUTH0_CLIENT_ID is required")
	}

	if len(c.CookieSigningKey) == 0 {
		return fmt.Errorf("COOKIE_SIGNING_KEY is required")
	}

	// Validate environment value
	switch c.Env {
	case "dev", "staging", "prod":
		// valid
	default:
		return fmt.Errorf("ENV must be dev, staging, or prod")
	}

	// Validate log level
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("LOG_LEVEL must be debug, info, warn, or error")
	}

	// Production-only constraints
	if c.Env == "prod" {
		if c.IntercomJWTSecret != "" {
			return fmt.Errorf("INTERCOM_JWT_SECRET should not be set in prod (use secret manager)")
		}
		if c.Auth0ClientSecret != "" {
			return fmt.Errorf("AUTH0_CLIENT_SECRET should not be set in prod (use secret manager)")
		}
	} else {
		// In dev/staging, these are required
		if c.IntercomJWTSecret == "" {
			return fmt.Errorf("INTERCOM_JWT_SECRET is required in %s", c.Env)
		}
		if c.Auth0ClientSecret == "" {
			return fmt.Errorf("AUTH0_CLIENT_SECRET is required in %s", c.Env)
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
