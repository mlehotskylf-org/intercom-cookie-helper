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