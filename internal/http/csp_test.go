package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithIdentifyCSP_AppliesCSP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := WithIdentifyCSP(handler)

	req := httptest.NewRequest("GET", "/callback", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected Content-Security-Policy header, got none")
	}

	// Verify all required directives
	requiredDirectives := map[string]string{
		"default-src":     "'self'",
		"script-src":      "'self' 'unsafe-inline' https://widget.intercom.io https://js.intercomcdn.com",
		"connect-src":     "'self' https://*.intercom.io https://api-iam.intercom.io",
		"img-src":         "'self' data: https://*.intercomcdn.com",
		"style-src":       "'self' 'unsafe-inline'",
		"frame-ancestors": "'none'",
	}

	for directive, expected := range requiredDirectives {
		if !strings.Contains(csp, directive+" "+expected) {
			t.Errorf("CSP missing or incorrect directive %s, expected: %s", directive, expected)
		}
	}
}

func TestWithIdentifyCSP_UnsafeInlineRequired(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithIdentifyCSP(handler)

	req := httptest.NewRequest("GET", "/callback", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")

	// Note: 'unsafe-inline' is required for both script-src and style-src
	// because the identify page has inline scripts for Intercom initialization
	// Future improvement: Use nonce-based CSP for better security
	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("CSP must allow 'unsafe-inline' in script-src (required by identify template)")
	}

	if !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") {
		t.Error("CSP must allow 'unsafe-inline' in style-src (required by Intercom)")
	}
}

func TestWithIdentifyCSP_NoWebsockets(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithIdentifyCSP(handler)

	req := httptest.NewRequest("GET", "/callback", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")

	// Verify websockets are not included (not needed for this implementation)
	if strings.Contains(csp, "wss://") {
		t.Error("CSP should not include websocket URLs (not required)")
	}
}

func TestWithIdentifyCSP_CallsNextHandler(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithIdentifyCSP(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if !called {
		t.Error("wrapped handler did not call next handler")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestWithIdentifyCSP_IntercomDomains(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithIdentifyCSP(handler)

	req := httptest.NewRequest("GET", "/callback", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")

	// Verify all Intercom domains are present
	intercomDomains := []string{
		"widget.intercom.io",
		"js.intercomcdn.com",
		"*.intercom.io",
		"api-iam.intercom.io",
		"*.intercomcdn.com",
	}

	for _, domain := range intercomDomains {
		if !strings.Contains(csp, domain) {
			t.Errorf("CSP missing required Intercom domain: %s", domain)
		}
	}
}

func TestWithIdentifyCSP_FrameAncestorsNone(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithIdentifyCSP(handler)

	req := httptest.NewRequest("GET", "/callback", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")

	// Verify clickjacking protection
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Error("CSP must include frame-ancestors 'none' for clickjacking protection")
	}
}
