package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

func TestHealthzHandler_Basic(t *testing.T) {
	// Create a minimal valid config
	cfg := config.Config{
		Env:         "dev",
		AppHostname: "localhost",
		Port:        "8080",
	}

	// Create router with config
	router := NewRouter(cfg)

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	// Execute request
	router.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Check status field
	if response["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", response["status"])
	}

	// Ensure no checks field in basic health check
	if _, hasChecks := response["checks"]; hasChecks {
		t.Error("Basic health check should not include checks field")
	}
}

func TestHealthzHandler_Deep_Success(t *testing.T) {
	// Create a complete valid config
	cfg := config.Config{
		Env:               "dev",
		AppHostname:       "localhost",
		Port:              "8080",
		Auth0Domain:       "dev-test.us.auth0.com",
		Auth0ClientID:     "test-client-id",
		Auth0ClientSecret: "test-secret",
		IntercomAppID:     "test-app-id",
		IntercomJWTSecret: []byte("test-jwt-secret-with-sufficient-length"),
		CookieDomain:      ".example.com",
		CookieSigningKey:  []byte("0123456789abcdef0123456789abcdef"), // 32 bytes
	}

	// Create router with config
	router := NewRouter(cfg)

	// Create request with ?check=deep
	req := httptest.NewRequest(http.MethodGet, "/healthz?check=deep", nil)
	w := httptest.NewRecorder()

	// Execute request
	router.ServeHTTP(w, req)

	// Note: Auth0 reachability check may fail in test environment
	// We accept either 200 or 503 as long as response structure is correct
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 200 or 503, got %d", w.Code)
	}

	// Parse response
	var response HealthStatus
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response structure
	if response.Status != "ok" && response.Status != "degraded" {
		t.Errorf("Expected status 'ok' or 'degraded', got '%s'", response.Status)
	}

	// Verify checks field exists
	if response.Checks == nil {
		t.Fatal("Expected checks field in deep health check response")
	}

	// Verify config check passes (since we provided valid config)
	if configStatus, ok := response.Checks["config"]; !ok {
		t.Error("Expected 'config' check in response")
	} else if configStatus != "ok" {
		t.Errorf("Expected config check to be 'ok', got '%s'", configStatus)
	}

	// Verify cookie_key check passes (we provided 32 byte key)
	if keyStatus, ok := response.Checks["cookie_key"]; !ok {
		t.Error("Expected 'cookie_key' check in response")
	} else if keyStatus != "ok" {
		t.Errorf("Expected cookie_key check to be 'ok', got '%s'", keyStatus)
	}

	// Auth0 check may pass or fail depending on network
	if _, ok := response.Checks["auth0"]; !ok {
		t.Error("Expected 'auth0' check in response")
	}
}

func TestHealthzHandler_Deep_MissingConfig(t *testing.T) {
	// Create incomplete config (missing Auth0Domain)
	cfg := config.Config{
		Env:              "dev",
		AppHostname:      "localhost",
		Port:             "8080",
		IntercomAppID:    "test-app-id",
		CookieSigningKey: []byte("0123456789abcdef0123456789abcdef"),
	}

	// Create router with config
	router := NewRouter(cfg)

	// Create request with ?check=deep
	req := httptest.NewRequest(http.MethodGet, "/healthz?check=deep", nil)
	w := httptest.NewRecorder()

	// Execute request
	router.ServeHTTP(w, req)

	// Should return 503 Service Unavailable
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	// Parse response
	var response HealthStatus
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify degraded status
	if response.Status != "degraded" {
		t.Errorf("Expected status 'degraded', got '%s'", response.Status)
	}

	// Verify config check fails
	if configStatus, ok := response.Checks["config"]; !ok {
		t.Error("Expected 'config' check in response")
	} else if configStatus == "ok" {
		t.Error("Expected config check to fail with missing configuration")
	}
}

func TestHealthzHandler_Deep_ShortCookieKey(t *testing.T) {
	// Create config with short cookie key
	cfg := config.Config{
		Env:               "dev",
		AppHostname:       "localhost",
		Port:              "8080",
		Auth0Domain:       "dev-test.us.auth0.com",
		Auth0ClientID:     "test-client-id",
		IntercomAppID:     "test-app-id",
		IntercomJWTSecret: []byte("test-secret"),
		CookieDomain:      ".example.com",
		CookieSigningKey:  []byte("tooshort"), // Only 8 bytes
	}

	// Create router with config
	router := NewRouter(cfg)

	// Create request with ?check=deep
	req := httptest.NewRequest(http.MethodGet, "/healthz?check=deep", nil)
	w := httptest.NewRecorder()

	// Execute request
	router.ServeHTTP(w, req)

	// Should return 503 Service Unavailable
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	// Parse response
	var response HealthStatus
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify degraded status
	if response.Status != "degraded" {
		t.Errorf("Expected status 'degraded', got '%s'", response.Status)
	}

	// Verify cookie_key check fails
	if keyStatus, ok := response.Checks["cookie_key"]; !ok {
		t.Error("Expected 'cookie_key' check in response")
	} else if keyStatus == "ok" {
		t.Error("Expected cookie_key check to fail with short key")
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		cfg       config.Config
		expectErr bool
	}{
		{
			name: "valid config",
			cfg: config.Config{
				Auth0Domain:       "test.auth0.com",
				Auth0ClientID:     "client-id",
				IntercomAppID:     "app-id",
				IntercomJWTSecret: []byte("secret"),
				AppHostname:       "localhost",
				CookieDomain:      ".example.com",
			},
			expectErr: false,
		},
		{
			name: "missing Auth0 domain",
			cfg: config.Config{
				Auth0ClientID:     "client-id",
				IntercomAppID:     "app-id",
				IntercomJWTSecret: []byte("secret"),
				AppHostname:       "localhost",
				CookieDomain:      ".example.com",
			},
			expectErr: true,
		},
		{
			name: "missing Auth0 client ID",
			cfg: config.Config{
				Auth0Domain:       "test.auth0.com",
				IntercomAppID:     "app-id",
				IntercomJWTSecret: []byte("secret"),
				AppHostname:       "localhost",
				CookieDomain:      ".example.com",
			},
			expectErr: true,
		},
		{
			name: "missing Intercom app ID",
			cfg: config.Config{
				Auth0Domain:       "test.auth0.com",
				Auth0ClientID:     "client-id",
				IntercomJWTSecret: []byte("secret"),
				AppHostname:       "localhost",
				CookieDomain:      ".example.com",
			},
			expectErr: true,
		},
		{
			name: "missing Intercom JWT secret",
			cfg: config.Config{
				Auth0Domain:   "test.auth0.com",
				Auth0ClientID: "client-id",
				IntercomAppID: "app-id",
				AppHostname:   "localhost",
				CookieDomain:  ".example.com",
			},
			expectErr: true,
		},
		{
			name: "missing app hostname",
			cfg: config.Config{
				Auth0Domain:       "test.auth0.com",
				Auth0ClientID:     "client-id",
				IntercomAppID:     "app-id",
				IntercomJWTSecret: []byte("secret"),
				CookieDomain:      ".example.com",
			},
			expectErr: true,
		},
		{
			name: "missing cookie domain",
			cfg: config.Config{
				Auth0Domain:       "test.auth0.com",
				Auth0ClientID:     "client-id",
				IntercomAppID:     "app-id",
				IntercomJWTSecret: []byte("secret"),
				AppHostname:       "localhost",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if tt.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}
