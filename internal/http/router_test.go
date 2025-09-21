package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

func TestHealthEndpoint(t *testing.T) {
	// Create a minimal test config
	cfg := config.Config{
		Env:         "test",
		AppHostname: "localhost",
		Port:        "8080",
		EnableHSTS:  false,
		RedirectTTL: 30 * time.Minute,
		SessionTTL:  24 * time.Hour,
		LogLevel:    "info",
	}
	router := NewRouter(cfg)

	req, err := http.NewRequest("GET", "/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%s'", response["status"])
	}
}

func TestHSTSHeader(t *testing.T) {
	tests := []struct {
		name       string
		enableHSTS bool
		expectHSTS bool
	}{
		{
			name:       "HSTS enabled",
			enableHSTS: true,
			expectHSTS: true,
		},
		{
			name:       "HSTS disabled",
			enableHSTS: false,
			expectHSTS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{
				Env:         "test",
				AppHostname: "localhost",
				Port:        "8080",
				EnableHSTS:  tt.enableHSTS,
				RedirectTTL: 30 * time.Minute,
				SessionTTL:  24 * time.Hour,
				LogLevel:    "info",
			}
			router := NewRouter(cfg)

			req, err := http.NewRequest("GET", "/healthz", nil)
			if err != nil {
				t.Fatal(err)
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			hstsHeader := rec.Header().Get("Strict-Transport-Security")
			if tt.expectHSTS {
				expected := "max-age=31536000; includeSubDomains"
				if hstsHeader != expected {
					t.Errorf("expected HSTS header '%s', got '%s'", expected, hstsHeader)
				}
			} else {
				if hstsHeader != "" {
					t.Errorf("expected no HSTS header, got '%s'", hstsHeader)
				}
			}
		})
	}
}

func TestConfigInContext(t *testing.T) {
	cfg := config.Config{
		Env:          "test",
		AppHostname:  "example.com",
		Port:         "8080",
		CookieDomain: ".example.com",
		EnableHSTS:   false,
		RedirectTTL:  30 * time.Minute,
		SessionTTL:   24 * time.Hour,
		LogLevel:     "info",
	}

	// Create a test handler that checks for config in context
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxCfg, ok := GetConfigFromContext(r.Context())
		if !ok {
			t.Error("config not found in context")
			return
		}
		if ctxCfg.CookieDomain != ".example.com" {
			t.Errorf("expected cookie domain '.example.com', got '%s'", ctxCfg.CookieDomain)
		}
		w.WriteHeader(http.StatusOK)
	})

	// We need to manually apply the middleware to test it
	mux := http.NewServeMux()
	mux.Handle("/test", testHandler)

	// Apply the config middleware
	configMW := configMiddleware(cfg)
	wrappedHandler := configMW(mux)

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestLoginEndpoint(t *testing.T) {
	// Create test config with allowed hosts
	cfg := config.Config{
		Env:                "test",
		AppHostname:        "localhost",
		Port:               "8080",
		EnableHSTS:         false,
		RedirectTTL:        30 * time.Minute,
		SessionTTL:         24 * time.Hour,
		LogLevel:           "info",
		AllowedReturnHosts: []string{"localhost", "example.com", "*.example.com"},
		AllowedQueryParams: []string{"utm_source", "utm_campaign"},
	}
	router := NewRouter(cfg)

	tests := []struct {
		name           string
		url            string
		referer        string
		expectedStatus int
		expectedBody   map[string]string
	}{
		{
			name:           "valid return URL with allowed referer",
			url:            "/login?return_to=https://example.com/path?utm_source=test",
			referer:        "https://localhost/",
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]string{"sanitized": "https://example.com/path?utm_source=test"},
		},
		{
			name:           "valid return URL with empty referer",
			url:            "/login?return_to=https://example.com/path",
			referer:        "",
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]string{"sanitized": "https://example.com/path"},
		},
		{
			name:           "valid return URL with subdomain",
			url:            "/login?return_to=https://sub.example.com/page",
			referer:        "https://localhost/",
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]string{"sanitized": "https://sub.example.com/page"},
		},
		{
			name:           "missing return_to parameter",
			url:            "/login",
			referer:        "https://localhost/",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "missing_return_to"},
		},
		{
			name:           "disallowed host in return_to",
			url:            "/login?return_to=https://malicious.com/attack",
			referer:        "https://localhost/",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "invalid_return_url"},
		},
		{
			name:           "non-HTTPS return URL",
			url:            "/login?return_to=http://example.com/path",
			referer:        "https://localhost/",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "invalid_return_url"},
		},
		{
			name:           "disallowed referer",
			url:            "/login?return_to=https://example.com/path",
			referer:        "https://malicious.com/",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "invalid_referrer"},
		},
		{
			name:           "non-HTTPS referer",
			url:            "/login?return_to=https://example.com/path",
			referer:        "http://localhost/",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "invalid_referrer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("expected Content-Type 'application/json', got '%s'", rec.Header().Get("Content-Type"))
			}

			var response map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Check specific fields based on expected response
			for key, expectedValue := range tt.expectedBody {
				actualValue, exists := response[key]
				if !exists {
					t.Errorf("expected key '%s' not found in response", key)
					continue
				}
				if key == "message" {
					// For message field, just verify it exists (don't check exact value)
					continue
				}
				if actualValue != expectedValue {
					t.Errorf("for key '%s': expected '%s', got '%s'", key, expectedValue, actualValue)
				}
			}
		})
	}
}