package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderErrorHTML(t *testing.T) {
	tests := []struct {
		name               string
		status             int
		errView            ErrView
		expectStatus       int
		expectContentType  string
		expectCacheControl string
		expectInBody       []string
	}{
		{
			name:   "renders 400 error with all fields",
			status: http.StatusBadRequest,
			errView: ErrView{
				Title:      "Invalid Request",
				Message:    "The request was malformed. Please try again.",
				RetryURL:   "/login?return_to=https://example.com",
				SupportURL: "https://example.com/support",
			},
			expectStatus:       http.StatusBadRequest,
			expectContentType:  ContentTypeHTML,
			expectCacheControl: "no-store",
			expectInBody: []string{
				"Invalid Request",
				"The request was malformed. Please try again.",
				`href="/login?return_to=https://example.com"`,
				"Try again",
				`href="https://example.com/support"`,
				"Get help",
			},
		},
		{
			name:   "renders 500 error without support URL",
			status: http.StatusInternalServerError,
			errView: ErrView{
				Title:      "Server Error",
				Message:    "An unexpected error occurred. Please try again later.",
				RetryURL:   "/",
				SupportURL: "",
			},
			expectStatus:       http.StatusInternalServerError,
			expectContentType:  ContentTypeHTML,
			expectCacheControl: "no-store",
			expectInBody: []string{
				"Server Error",
				"An unexpected error occurred. Please try again later.",
				`href="/"`,
				"Try again",
			},
		},
		{
			name:   "renders 401 unauthorized",
			status: http.StatusUnauthorized,
			errView: ErrView{
				Title:      "Unauthorized",
				Message:    "Your session has expired. Please sign in again.",
				RetryURL:   "/login",
				SupportURL: "",
			},
			expectStatus:       http.StatusUnauthorized,
			expectContentType:  ContentTypeHTML,
			expectCacheControl: "no-store",
			expectInBody: []string{
				"Unauthorized",
				"Your session has expired. Please sign in again.",
				`href="/login"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create response recorder
			rec := httptest.NewRecorder()

			// Call renderErrorHTML
			renderErrorHTML(rec, tt.status, tt.errView)

			// Check status code
			if rec.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rec.Code)
			}

			// Check Content-Type header
			contentType := rec.Header().Get("Content-Type")
			if contentType != tt.expectContentType {
				t.Errorf("expected Content-Type %q, got %q", tt.expectContentType, contentType)
			}

			// Check Cache-Control header
			cacheControl := rec.Header().Get("Cache-Control")
			if cacheControl != tt.expectCacheControl {
				t.Errorf("expected Cache-Control %q, got %q", tt.expectCacheControl, cacheControl)
			}

			// Check body contains expected strings
			body := rec.Body.String()
			for _, expected := range tt.expectInBody {
				if !strings.Contains(body, expected) {
					t.Errorf("expected body to contain %q, but it didn't.\nBody:\n%s", expected, body)
				}
			}
		})
	}
}

func TestRenderErrorHTML_Headers(t *testing.T) {
	rec := httptest.NewRecorder()

	errView := ErrView{
		Title:    "Test Error",
		Message:  "Test message",
		RetryURL: "/test",
	}

	renderErrorHTML(rec, http.StatusBadRequest, errView)

	// Verify all required headers are set
	headers := map[string]string{
		"Content-Type":  ContentTypeHTML,
		"Cache-Control": "no-store",
	}

	for header, expectedValue := range headers {
		actualValue := rec.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("header %s: expected %q, got %q", header, expectedValue, actualValue)
		}
	}
}

func TestRenderErrorHTML_EscapesHTML(t *testing.T) {
	rec := httptest.NewRecorder()

	errView := ErrView{
		Title:    "<script>alert('xss')</script>",
		Message:  "<img src=x onerror=alert('xss')>",
		RetryURL: "/safe",
	}

	renderErrorHTML(rec, http.StatusBadRequest, errView)

	body := rec.Body.String()

	// Check that dangerous content is escaped
	if strings.Contains(body, "<script>alert('xss')</script>") {
		t.Error("XSS vulnerability: script tag not escaped")
	}

	if strings.Contains(body, "<img src=x onerror=") {
		t.Error("XSS vulnerability: img tag not escaped")
	}

	// Check that escaped versions ARE present
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("Expected HTML entities for script tag")
	}
}

func TestRenderErrorHTML_StatusWrittenBeforeBody(t *testing.T) {
	rec := httptest.NewRecorder()

	errView := ErrView{
		Title:    "Test",
		Message:  "Test message",
		RetryURL: "/test",
	}

	renderErrorHTML(rec, http.StatusNotFound, errView)

	// Verify status is 404
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}

	// Verify body was written (not empty)
	if rec.Body.Len() == 0 {
		t.Error("expected body to be written")
	}
}
