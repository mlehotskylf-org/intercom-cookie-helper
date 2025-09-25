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
			expectedBody:   `{"error":"invalid_referrer"}`,
		},
		{
			name:           "referer from disallowed host",
			referer:        "https://malicious.com/path",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid_referrer"}`,
		},
		{
			name:           "invalid referer URL",
			referer:        "not-a-valid-url",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid_referrer"}`,
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
			expectedBody:   `{"error":"invalid_referrer"}`,
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
				if response["error"] != "invalid_referrer" {
					t.Errorf("expected error 'invalid_referrer', got %q", response["error"])
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

func TestWriteReferrerError(t *testing.T) {
	w := httptest.NewRecorder()
	writeReferrerError(w)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("failed to parse response JSON: %v", err)
	}

	if response["error"] != "invalid_referrer" {
		t.Errorf("expected error 'invalid_referrer', got %q", response["error"])
	}
}
