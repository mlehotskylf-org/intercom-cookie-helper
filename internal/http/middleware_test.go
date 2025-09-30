package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

func TestRequireReferrerHost(t *testing.T) {
	// Setup test configuration and allowlist
	allowlist, err := security.NewHostAllowlist([]string{
		"example.com",
		"*.example.com",
		"trusted.org",
	})
	if err != nil {
		t.Fatalf("failed to create allowlist: %v", err)
	}

	cfg := config.Config{}
	middleware := RequireReferrerHost(cfg, allowlist)

	// Test handler that the middleware wraps
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	wrappedHandler := middleware(nextHandler)

	tests := []struct {
		name           string
		referer        string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "empty referer should be allowed",
			referer:        "",
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "valid https referer from allowed host",
			referer:        "https://example.com/path",
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "valid https referer from allowed subdomain",
			referer:        "https://sub.example.com/path",
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "valid https referer from exact allowed host",
			referer:        "https://trusted.org/",
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "invalid http referer (not https)",
			referer:        "http://example.com/path",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid_request"}`,
		},
		{
			name:           "referer from disallowed host",
			referer:        "https://malicious.com/path",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid_request"}`,
		},
		{
			name:           "invalid referer URL",
			referer:        "not-a-valid-url",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid_request"}`,
		},
		{
			name:           "referer with query params and fragment",
			referer:        "https://example.com/path?param=value#fragment",
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "referer from subdomain not in wildcard allowlist",
			referer:        "https://sub.trusted.org/path",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid_request"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			w := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			body := w.Body.String()
			if tt.expectedStatus == http.StatusBadRequest {
				// For error responses, parse JSON to verify structure
				var response map[string]string
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Errorf("failed to parse error response JSON: %v", err)
				}
				if response["error"] != "invalid_request" {
					t.Errorf("expected error 'invalid_request', got %q", response["error"])
				}
			} else {
				if body != tt.expectedBody {
					t.Errorf("expected body %q, got %q", tt.expectedBody, body)
				}
			}

			// Verify Content-Type header for error responses
			if tt.expectedStatus == http.StatusBadRequest {
				contentType := w.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("expected Content-Type 'application/json', got %q", contentType)
				}
			}
		})
	}
}

func TestRequireReferrerHost_ProductionEmpty(t *testing.T) {
	// Production environment should reject empty referer
	cfg := config.Config{
		Env:                "prod",
		AllowedReturnHosts: []string{"example.com"},
	}

	allowlist, err := security.NewHostAllowlist(cfg.AllowedReturnHosts)
	if err != nil {
		t.Fatalf("failed to create allowlist: %v", err)
	}

	handler := RequireReferrerHost(cfg, allowlist)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/login", nil)
	// No Referer header set
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d in prod with empty referer, got %d", http.StatusBadRequest, rec.Code)
	}

	var response ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if response.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got '%s'", response.Error)
	}
}

func TestRequireReferrerHost_DevEmpty(t *testing.T) {
	// Dev environment should allow empty referer
	cfg := config.Config{
		Env:                "dev",
		AllowedReturnHosts: []string{"example.com"},
	}

	allowlist, err := security.NewHostAllowlist(cfg.AllowedReturnHosts)
	if err != nil {
		t.Fatalf("failed to create allowlist: %v", err)
	}

	handler := RequireReferrerHost(cfg, allowlist)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/login", nil)
	// No Referer header set
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d in dev with empty referer, got %d", http.StatusOK, rec.Code)
	}

	if rec.Body.String() != "OK" {
		t.Errorf("expected body 'OK', got '%s'", rec.Body.String())
	}
}

func TestRequireReferrerHost_IPLiteral(t *testing.T) {
	tests := []struct {
		name    string
		referer string
	}{
		{"IPv4", "https://192.168.1.1/page"},
		{"IPv4 with port", "https://192.168.1.1:8080/page"},
		{"IPv6", "https://[2001:db8::1]/page"},
		{"IPv6 with port", "https://[2001:db8::1]:8080/page"},
		{"localhost IP", "https://127.0.0.1/page"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{
				Env:                "dev",
				AllowedReturnHosts: []string{"example.com"},
			}

			allowlist, err := security.NewHostAllowlist(cfg.AllowedReturnHosts)
			if err != nil {
				t.Fatalf("failed to create allowlist: %v", err)
			}

			handler := RequireReferrerHost(cfg, allowlist)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", "/login", nil)
			req.Header.Set("Referer", tt.referer)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected status %d for IP literal, got %d", http.StatusBadRequest, rec.Code)
			}

			var response ErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}

			if response.Error != "invalid_request" {
				t.Errorf("expected error 'invalid_request', got '%s'", response.Error)
			}
		})
	}
}

func TestRequireReferrerHost_InvalidScheme(t *testing.T) {
	tests := []struct {
		name    string
		referer string
	}{
		{"http", "http://example.com/page"},
		{"ftp", "ftp://example.com/file"},
		{"no scheme", "//example.com/page"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{
				Env:                "dev",
				AllowedReturnHosts: []string{"example.com"},
			}

			allowlist, err := security.NewHostAllowlist(cfg.AllowedReturnHosts)
			if err != nil {
				t.Fatalf("failed to create allowlist: %v", err)
			}

			handler := RequireReferrerHost(cfg, allowlist)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", "/login", nil)
			req.Header.Set("Referer", tt.referer)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected status %d for invalid scheme, got %d", http.StatusBadRequest, rec.Code)
			}

			var response ErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}

			if response.Error != "invalid_request" {
				t.Errorf("expected error 'invalid_request', got '%s'", response.Error)
			}
		})
	}
}

func TestRequireReferrerHost_HostNotAllowed(t *testing.T) {
	cfg := config.Config{
		Env:                "dev",
		AllowedReturnHosts: []string{"example.com", "*.example.com"},
	}

	allowlist, err := security.NewHostAllowlist(cfg.AllowedReturnHosts)
	if err != nil {
		t.Fatalf("failed to create allowlist: %v", err)
	}

	handler := RequireReferrerHost(cfg, allowlist)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/login", nil)
	req.Header.Set("Referer", "https://evil.com/page")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d for disallowed host, got %d", http.StatusBadRequest, rec.Code)
	}

	var response ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if response.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got '%s'", response.Error)
	}
}
