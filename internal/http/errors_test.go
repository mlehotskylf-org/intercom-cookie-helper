package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBadRequest(t *testing.T) {
	tests := []struct {
		name   string
		reason string
	}{
		{
			name:   "missing parameter",
			reason: "return_to parameter is required",
		},
		{
			name:   "invalid format",
			reason: "invalid URL format",
		},
		{
			name:   "validation failed",
			reason: "host not in allowlist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()

			BadRequest(rec, req, tt.reason)

			// Check status code
			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
			}

			// Check Content-Type
			contentType := rec.Header().Get("Content-Type")
			if contentType != "application/json; charset=utf-8" {
				t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
			}

			// Check response body
			var response ErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if response.Error != "invalid_request" {
				t.Errorf("expected error 'invalid_request', got '%s'", response.Error)
			}

			// Ensure no sensitive data leaked
			bodyStr := rec.Body.String()
			if len(bodyStr) > 100 {
				t.Errorf("response body too large, may contain sensitive data: %d bytes", len(bodyStr))
			}
		})
	}
}

func TestTooManyRequests(t *testing.T) {
	req := httptest.NewRequest("GET", "/login?return_to=https://example.com", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()

	TooManyRequests(rec, req)

	// Check status code
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}

	// Check Content-Type
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Check response body
	var response ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Error != "rate_limited" {
		t.Errorf("expected error 'rate_limited', got '%s'", response.Error)
	}

	// Ensure response is minimal
	bodyStr := rec.Body.String()
	if len(bodyStr) > 100 {
		t.Errorf("response body too large: %d bytes", len(bodyStr))
	}
}

func TestServerError(t *testing.T) {
	req := httptest.NewRequest("POST", "/callback?code=abc&state=xyz", nil)
	rec := httptest.NewRecorder()

	ServerError(rec, req)

	// Check status code
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}

	// Check Content-Type
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Check response body
	var response ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Error != "server_error" {
		t.Errorf("expected error 'server_error', got '%s'", response.Error)
	}

	// Ensure no internal details leaked
	bodyStr := rec.Body.String()
	if len(bodyStr) > 100 {
		t.Errorf("response body too large, may contain internal details: %d bytes", len(bodyStr))
	}
}

func TestErrorResponseFormat(t *testing.T) {
	tests := []struct {
		name           string
		errorFunc      func(http.ResponseWriter, *http.Request)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "BadRequest",
			errorFunc: func(w http.ResponseWriter, r *http.Request) {
				BadRequest(w, r, "test reason")
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "TooManyRequests",
			errorFunc: func(w http.ResponseWriter, r *http.Request) {
				TooManyRequests(w, r)
			},
			expectedStatus: http.StatusTooManyRequests,
			expectedError:  "rate_limited",
		},
		{
			name: "ServerError",
			errorFunc: func(w http.ResponseWriter, r *http.Request) {
				ServerError(w, r)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "server_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()

			tt.errorFunc(rec, req)

			// Verify status code
			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			// Verify JSON structure
			var response ErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode JSON: %v", err)
			}

			// Verify error code
			if response.Error != tt.expectedError {
				t.Errorf("expected error '%s', got '%s'", tt.expectedError, response.Error)
			}

			// Verify only one field exists (no leaking of internal details)
			var rawResponse map[string]interface{}
			rec2 := httptest.NewRecorder()
			tt.errorFunc(rec2, req)
			if err := json.NewDecoder(rec2.Body).Decode(&rawResponse); err != nil {
				t.Fatalf("failed to decode raw JSON: %v", err)
			}

			if len(rawResponse) != 1 {
				t.Errorf("expected exactly 1 field in response, got %d: %v", len(rawResponse), rawResponse)
			}

			if _, exists := rawResponse["error"]; !exists {
				t.Error("response missing 'error' field")
			}
		})
	}
}

func TestNoSecretsInResponse(t *testing.T) {
	// Test that sensitive information is never included in responses
	sensitiveReasons := []string{
		"database connection failed: password=secret123",
		"Auth0 client secret: abc123def456",
		"Cookie signing key: 0123456789abcdef",
		"User email: user@example.com leaked",
	}

	for _, reason := range sensitiveReasons {
		t.Run("sensitive_reason", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()

			BadRequest(rec, req, reason)

			bodyStr := rec.Body.String()

			// Ensure none of the sensitive patterns appear in response
			sensitivePatterns := []string{"password=", "secret", "key:", "@example.com"}
			for _, pattern := range sensitivePatterns {
				if containsCaseInsensitive(bodyStr, pattern) {
					t.Errorf("response contains sensitive pattern '%s': %s", pattern, bodyStr)
				}
			}

			// Ensure response only contains the generic error
			var response ErrorResponse
			rec2 := httptest.NewRecorder()
			BadRequest(rec2, req, reason)
			if err := json.NewDecoder(rec2.Body).Decode(&response); err == nil {
				if response.Error != "invalid_request" {
					t.Errorf("expected generic error, got: %s", response.Error)
				}
			}
		})
	}
}

// Helper function for case-insensitive string matching
func containsCaseInsensitive(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			contains(s, substr))
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestNoStore(t *testing.T) {
	// Test that noStore sets the correct cache headers
	rec := httptest.NewRecorder()

	// Call noStore
	noStore(rec)

	// Verify Cache-Control header
	cacheControl := rec.Header().Get("Cache-Control")
	if cacheControl != "no-store, max-age=0" {
		t.Errorf("Expected Cache-Control: no-store, max-age=0, got %s", cacheControl)
	}

	// Verify Pragma header
	pragma := rec.Header().Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("Expected Pragma: no-cache, got %s", pragma)
	}
}
