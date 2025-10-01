package httpx

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

// HealthStatus represents the overall health status of the service.
type HealthStatus struct {
	Status string            `json:"status"`         // "ok" or "degraded"
	Checks map[string]string `json:"checks,omitempty"` // Only included in deep health checks
}

// healthzHandler handles basic health check requests.
// Returns 200 OK with {"status": "ok"} for basic liveness checks.
// Supports ?check=deep for dependency validation (Auth0 reachability, config validity).
func healthzHandler(w http.ResponseWriter, r *http.Request) {
	// Check if deep health check is requested
	if r.URL.Query().Get("check") == "deep" {
		deepHealthCheck(w, r)
		return
	}

	// Basic health check - just return OK
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// deepHealthCheck performs comprehensive validation of external dependencies and configuration.
// Returns 200 if all checks pass, 503 if any critical check fails.
func deepHealthCheck(w http.ResponseWriter, r *http.Request) {
	cfg, ok := GetConfigFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, HealthStatus{
			Status: "degraded",
			Checks: map[string]string{
				"config": "unavailable",
			},
		})
		return
	}

	checks := make(map[string]string)
	allHealthy := true

	// Check 1: Validate configuration is complete
	if err := validateConfig(cfg); err != nil {
		checks["config"] = fmt.Sprintf("invalid: %v", err)
		allHealthy = false
		log.Printf("Health check failed - config validation: %v", err)
	} else {
		checks["config"] = "ok"
	}

	// Check 2: Verify Auth0 domain is reachable
	if err := checkAuth0Reachability(cfg.Auth0Domain); err != nil {
		checks["auth0"] = fmt.Sprintf("unreachable: %v", err)
		allHealthy = false
		log.Printf("Health check failed - Auth0 reachability: %v", err)
	} else {
		checks["auth0"] = "ok"
	}

	// Check 3: Verify cookie signing key is valid
	if len(cfg.CookieSigningKey) < 32 {
		checks["cookie_key"] = "invalid: key too short"
		allHealthy = false
		log.Printf("Health check failed - cookie signing key too short: %d bytes", len(cfg.CookieSigningKey))
	} else {
		checks["cookie_key"] = "ok"
	}

	// Determine overall status
	status := HealthStatus{
		Status: "ok",
		Checks: checks,
	}

	if !allHealthy {
		status.Status = "degraded"
		writeJSON(w, http.StatusServiceUnavailable, status)
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// validateConfig checks that critical configuration fields are set.
func validateConfig(cfg config.Config) error {
	if cfg.Auth0Domain == "" {
		return fmt.Errorf("AUTH0_DOMAIN not configured")
	}
	if cfg.Auth0ClientID == "" {
		return fmt.Errorf("AUTH0_CLIENT_ID not configured")
	}
	if cfg.IntercomAppID == "" {
		return fmt.Errorf("INTERCOM_APP_ID not configured")
	}
	if len(cfg.IntercomJWTSecret) == 0 {
		return fmt.Errorf("INTERCOM_JWT_SECRET not configured")
	}
	if cfg.AppHostname == "" {
		return fmt.Errorf("APP_HOSTNAME not configured")
	}
	if cfg.CookieDomain == "" {
		return fmt.Errorf("COOKIE_DOMAIN not configured")
	}
	return nil
}

// checkAuth0Reachability verifies that Auth0 domain is reachable via HTTPS.
// Makes a HEAD request to the OIDC well-known configuration endpoint.
func checkAuth0Reachability(domain string) error {
	// Build well-known OIDC configuration URL
	url := fmt.Sprintf("https://%s/.well-known/openid-configuration", domain)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Accept 200 OK or 405 Method Not Allowed (some servers don't support HEAD)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMethodNotAllowed {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}
