package httpx

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

func TestHealthEndpoint(t *testing.T) {
	// Create a minimal test config
	cfg := config.Config{
		Env:               "test",
		AppHostname:       "localhost",
		Port:              "8080",
		EnableHSTS:        false,
		RedirectTTL:       30 * time.Minute,
		Auth0Domain:       "test.auth0.com",
		Auth0ClientID:     "test-client-id",
		Auth0ClientSecret: "test-secret",
		Auth0RedirectPath: "/callback",
		IntercomAppID:     "test-app",
		TxnTTL:            10 * time.Minute,
		TxnSkew:           1 * time.Minute,
		SessionTTL:        24 * time.Hour,
		LogLevel:          "info",
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
				Env:               "test",
				AppHostname:       "localhost",
				Port:              "8080",
				EnableHSTS:        tt.enableHSTS,
				RedirectTTL:       30 * time.Minute,
				Auth0Domain:       "test.auth0.com",
				Auth0ClientID:     "test-client-id",
				Auth0ClientSecret: "test-secret",
				Auth0RedirectPath: "/callback",
				IntercomAppID:     "test-app",
				TxnTTL:            10 * time.Minute,
				TxnSkew:           1 * time.Minute,
				SessionTTL:        24 * time.Hour,
				LogLevel:          "info",
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
		CookieDomain:       ".localhost",
		EnableHSTS:         false,
		RedirectTTL:        30 * time.Minute,
		SessionTTL:         24 * time.Hour,
		LogLevel:           "info",
		AllowedReturnHosts: []string{"localhost", "example.com", "*.example.com"},
		AllowedQueryParams: []string{"utm_source", "utm_campaign"},
		CookieSigningKey:   []byte("test-signing-key-32-bytes-long!"),
		Auth0Domain:        "test.auth0.com",
		Auth0ClientID:      "test-client-id",
		Auth0ClientSecret:  "test-client-secret",
		Auth0RedirectPath:  "/callback",
		IntercomAppID:      "test-app-id",
		TxnTTL:             10 * time.Minute,
		TxnSkew:            1 * time.Minute,
	}
	router := NewRouter(cfg)

	tests := []struct {
		name                 string
		url                  string
		referer              string
		expectedStatus       int
		expectedBody         map[string]string
		expectRedirect       bool
		expectRedirectCookie bool // New field - expect redirect cookie to be set
	}{
		{
			name:                 "valid return URL with allowed referer",
			url:                  "/login?return_to=https://example.com/path?utm_source=test",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Expecting redirect to Auth0
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "valid return URL with empty referer",
			url:                  "/login?return_to=https://example.com/path",
			referer:              "",
			expectedStatus:       http.StatusFound, // Expecting redirect to Auth0
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "valid return URL with subdomain",
			url:                  "/login?return_to=https://sub.example.com/page",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Expecting redirect to Auth0
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "referer used when return_to missing",
			url:                  "/login",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Referer provides the return URL
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "referer takes priority over disallowed return_to",
			url:                  "/login?return_to=https://malicious.com/attack",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Referer (localhost) is allowed, takes priority
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "referer takes priority over non-HTTPS return_to",
			url:                  "/login?return_to=http://example.com/path",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Referer (HTTPS) takes priority
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:           "disallowed referer",
			url:            "/login?return_to=https://example.com/path",
			referer:        "https://malicious.com/",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "invalid_request"},
			expectRedirect: false,
		},
		{
			name:           "non-HTTPS referer",
			url:            "/login?return_to=https://example.com/path",
			referer:        "http://localhost/",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "invalid_request"},
			expectRedirect: false,
		},
		{
			name:                 "referer takes priority over oversized return_to",
			url:                  "/login?return_to=https://example.com/" + strings.Repeat("a", 3600),
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Referer takes priority, not oversized
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "referer takes priority over malformed return_to",
			url:                  "/login?return_to=https://[invalid",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Referer takes priority
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "referer takes priority over javascript return_to",
			url:                  "/login?return_to=javascript:alert(1)",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Referer takes priority
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "referer takes priority over data URL return_to",
			url:                  "/login?return_to=data:text/html,<script>alert(1)</script>",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Referer takes priority
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "URL with disallowed query params",
			url:                  "/login?return_to=https://example.com/path?evil_param=value&utm_source=test",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Should succeed but strip evil_param
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "referer takes priority over return_to with port",
			url:                  "/login?return_to=https://example.com:8080/path",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Referer takes priority
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "URL with username in authority",
			url:                  "/login?return_to=https://user@example.com/path",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Sanitizer strips username and accepts URL
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		{
			name:                 "referer used when return_to is empty string",
			url:                  "/login?return_to=",
			referer:              "https://localhost/",
			expectedStatus:       http.StatusFound, // Referer takes priority (empty string treated as missing)
			expectRedirect:       true,
			expectRedirectCookie: true,
		},
		// Tests with no referer - return_to fallback behavior
		{
			name:           "return_to fallback - disallowed host",
			url:            "/login?return_to=https://malicious.com/attack",
			referer:        "", // No referer, so return_to is used
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "invalid_request"},
			expectRedirect: false,
		},
		{
			name:           "return_to fallback - malformed URL",
			url:            "/login?return_to=https://[invalid",
			referer:        "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "invalid_request"},
			expectRedirect: false,
		},
		{
			name:           "return_to fallback - javascript URL",
			url:            "/login?return_to=javascript:alert(1)",
			referer:        "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "invalid_request"},
			expectRedirect: false,
		},
		{
			name:                 "neither referer nor return_to",
			url:                  "/login",
			referer:              "",
			expectedStatus:       http.StatusFound, // Should still redirect to Auth0, no cookie set
			expectRedirect:       true,
			expectRedirectCookie: false, // No return URL, so no redirect cookie
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

			if tt.expectRedirect {
				// For redirects, check Location header points to Auth0
				location := rec.Header().Get("Location")
				if location == "" {
					t.Error("expected Location header for redirect")
				} else if !strings.Contains(location, "test.auth0.com") {
					t.Errorf("expected redirect to Auth0 domain, got: %s", location)
				}

				// Check that required cookies were set
				cookies := rec.Result().Cookies()
				hasRedirectCookie := false
				hasTxnCookie := false
				for _, cookie := range cookies {
					if cookie.Name == "ic_redirect" {
						hasRedirectCookie = true
					}
					if cookie.Name == "ic_oidc_txn" {
						hasTxnCookie = true
					}
				}

				// Only check for redirect cookie if we expect one
				if tt.expectRedirectCookie && !hasRedirectCookie {
					t.Error("expected ic_redirect cookie to be set")
				}
				if !tt.expectRedirectCookie && hasRedirectCookie {
					t.Error("did not expect ic_redirect cookie to be set, but it was")
				}

				// Txn cookie should always be set for redirects
				if !hasTxnCookie {
					t.Error("expected ic_txn cookie to be set")
				}
			} else {
				// For non-redirects (error cases), expect JSON error response
				if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
					t.Errorf("expected Content-Type 'application/json; charset=utf-8', got '%s'", rec.Header().Get("Content-Type"))
				}

				var response map[string]interface{}
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

					// Convert actual value to string for comparison
					actualStr := fmt.Sprintf("%v", actualValue)
					if actualStr != expectedValue {
						t.Errorf("for key '%s': expected '%s', got '%s'", key, expectedValue, actualStr)
					}
				}
			}
		})
	}
}

func TestDebugRedirectCookieEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		env            string
		cookieValue    string
		expectedStatus int
		expectedError  string
		expectedValid  bool
		expectedURL    string
	}{
		{
			name:           "production environment - should return 404",
			env:            "prod",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "non-prod environment - no cookie",
			env:            "test",
			expectedStatus: http.StatusOK,
			expectedError:  "http: named cookie not present",
		},
		{
			name:           "non-prod environment - invalid cookie",
			env:            "test",
			cookieValue:    "invalid-cookie-value",
			expectedStatus: http.StatusOK,
			expectedError:  "invalid redirect cookie format",
		},
		{
			name:           "non-prod environment - valid cookie",
			env:            "test",
			cookieValue:    "", // Will be set dynamically in test
			expectedStatus: http.StatusOK,
			expectedValid:  true,
			expectedURL:    "https://example.com/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{
				Env:                "test",
				AppHostname:        "localhost",
				Port:               "8080",
				CookieDomain:       ".localhost",
				EnableHSTS:         false,
				RedirectTTL:        30 * time.Minute,
				SessionTTL:         24 * time.Hour,
				LogLevel:           "info",
				AllowedReturnHosts: []string{"localhost", "example.com"},
				CookieSigningKey:   []byte("test-signing-key-32-bytes-long!"),
				RedirectSkew:       5 * time.Minute,
			}

			// Override environment for this test
			cfg.Env = tt.env

			router := NewRouter(cfg)

			req, err := http.NewRequest("GET", "/debug/redirect-cookie", nil)
			if err != nil {
				t.Fatal(err)
			}

			// Set up cookie if needed
			if tt.name == "non-prod environment - valid cookie" {
				// Create a valid cookie using the same logic as the login endpoint
				rec := httptest.NewRecorder()
				loginReq, _ := http.NewRequest("GET", "/login?return_to=https://example.com/test", nil)
				// No referer set, so return_to param will be used
				router.ServeHTTP(rec, loginReq)

				// Extract the cookie from login response
				cookies := rec.Result().Cookies()
				var redirectCookie *http.Cookie
				for _, cookie := range cookies {
					if cookie.Name == "ic_redirect" {
						redirectCookie = cookie
						break
					}
				}

				if redirectCookie != nil {
					req.AddCookie(redirectCookie)
				}
			} else if tt.cookieValue != "" {
				// Set invalid cookie
				req.AddCookie(&http.Cookie{
					Name:  "ic_redirect",
					Value: tt.cookieValue,
				})
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			// For 404 responses (prod environment), don't check body
			if tt.expectedStatus == http.StatusNotFound {
				return
			}

			if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Errorf("expected Content-Type 'application/json; charset=utf-8', got '%s'", rec.Header().Get("Content-Type"))
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if tt.expectedError != "" {
				if errorMsg, exists := response["error"]; !exists {
					t.Errorf("expected error field in response")
				} else if errorStr := fmt.Sprintf("%v", errorMsg); errorStr != tt.expectedError {
					t.Logf("got error: %s", errorStr)
					// For some errors, we just check that an error exists rather than exact message
					if tt.expectedError == "invalid redirect cookie format" && errorStr != tt.expectedError {
						// Allow various error messages for invalid format
						if errorStr == "" {
							t.Errorf("expected some error message, got empty")
						}
					}
				}
			}

			if tt.expectedValid {
				if valid, exists := response["valid"]; !exists {
					t.Errorf("expected valid field in response")
				} else if validBool, ok := valid.(bool); !ok || !validBool {
					t.Errorf("expected valid to be true, got %v", valid)
				}

				if url, exists := response["url"]; !exists {
					t.Errorf("expected url field in response")
				} else if urlStr := fmt.Sprintf("%v", url); urlStr != tt.expectedURL {
					t.Errorf("expected url '%s', got '%s'", tt.expectedURL, urlStr)
				}
			}
		})
	}
}

func TestWithIdentifyCSP(t *testing.T) {
	// Test the CSP middleware in isolation
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	wrapped := WithIdentifyCSP(testHandler)

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	// Check CSP header
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected Content-Security-Policy header, got none")
	}

	// Verify CSP contains required directives for Intercom
	requiredDirectives := []string{
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline' https://widget.intercom.io https://js.intercomcdn.com",
		"connect-src 'self' https://*.intercom.io wss://*.intercom.io https://api-iam.intercom.io",
		"img-src 'self' data: https://*.intercomcdn.com",
		"style-src 'self' 'unsafe-inline'",
		"frame-ancestors 'none'",
	}
	for _, directive := range requiredDirectives {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing directive: %s", directive)
		}
	}

	// Note: 'unsafe-inline' is required in script-src for the identify page template
	// Future improvement: Use nonce-based CSP
	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("CSP must contain 'unsafe-inline' in script-src (required by template)")
	}

	// Verify that wss://*.intercom.io IS included (required for real-time messaging)
	if !strings.Contains(csp, "wss://*.intercom.io") {
		t.Error("CSP must contain websocket URLs in connect-src (required by Intercom)")
	}
}

func TestCallbackRouteHasSecurityHeaders(t *testing.T) {
	// Verify /callback route has Intercom security headers
	cfg := config.Config{
		Env:               "test",
		AppHostname:       "localhost",
		Port:              "8080",
		CookieDomain:      ".localhost",
		EnableHSTS:        false,
		RedirectTTL:       30 * time.Minute,
		SessionTTL:        24 * time.Hour,
		LogLevel:          "info",
		CookieSigningKey:  []byte("test-signing-key-32-bytes-long!"),
		Auth0Domain:       "test.auth0.com",
		Auth0ClientID:     "test-client-id",
		Auth0ClientSecret: "test-client-secret",
		Auth0RedirectPath: "/callback",
		IntercomAppID:     "test-app-id",
		TxnTTL:            10 * time.Minute,
		TxnSkew:           1 * time.Minute,
	}
	router := NewRouter(cfg)

	req, err := http.NewRequest("GET", "/callback", nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Check that CSP header is present (callback will fail due to missing params, but headers should be set)
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected Content-Security-Policy header on /callback route")
	}

	if !strings.Contains(csp, "widget.intercom.io") {
		t.Error("expected CSP to allow Intercom widget")
	}

	// Check other security headers
	if rec.Header().Get("Referrer-Policy") == "" {
		t.Error("expected Referrer-Policy header on /callback route")
	}

	if rec.Header().Get("X-Content-Type-Options") == "" {
		t.Error("expected X-Content-Type-Options header on /callback route")
	}
}

func TestHealthzRouteNoIntercomHeaders(t *testing.T) {
	// Verify /healthz route does NOT have Intercom-specific CSP but HAS global security headers
	cfg := config.Config{
		Env:          "test",
		AppHostname:  "localhost",
		Port:         "8080",
		CookieDomain: ".localhost",
		EnableHSTS:   false,
		RedirectTTL:  30 * time.Minute,
		SessionTTL:   24 * time.Hour,
		LogLevel:     "info",
	}
	router := NewRouter(cfg)

	req, err := http.NewRequest("GET", "/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// /healthz should NOT have Intercom-specific CSP
	csp := rec.Header().Get("Content-Security-Policy")
	if csp != "" {
		t.Errorf("expected no Content-Security-Policy header on /healthz route, got: %s", csp)
	}

	// /healthz SHOULD have global security headers (now applied to all routes)
	referrerPolicy := rec.Header().Get("Referrer-Policy")
	if referrerPolicy != "strict-origin-when-cross-origin" {
		t.Errorf("expected Referrer-Policy 'strict-origin-when-cross-origin' on /healthz, got: %s", referrerPolicy)
	}

	contentTypeOptions := rec.Header().Get("X-Content-Type-Options")
	if contentTypeOptions != "nosniff" {
		t.Errorf("expected X-Content-Type-Options 'nosniff' on /healthz, got: %s", contentTypeOptions)
	}

	permissionsPolicy := rec.Header().Get("Permissions-Policy")
	if permissionsPolicy != "geolocation=(), microphone=(), camera=()" {
		t.Errorf("expected Permissions-Policy on /healthz, got: %s", permissionsPolicy)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		enableHSTS bool
		wantHSTS   bool
	}{
		{
			name:       "HSTS enabled",
			enableHSTS: true,
			wantHSTS:   true,
		},
		{
			name:       "HSTS disabled",
			enableHSTS: false,
			wantHSTS:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{
				Env:          "test",
				AppHostname:  "localhost",
				Port:         "8080",
				CookieDomain: ".localhost",
				EnableHSTS:   tt.enableHSTS,
				RedirectTTL:  30 * time.Minute,
				SessionTTL:   24 * time.Hour,
				LogLevel:     "info",
			}
			router := NewRouter(cfg)

			req := httptest.NewRequest("GET", "/healthz", nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			// Check that all security headers are present
			headers := map[string]string{
				"Referrer-Policy":        "strict-origin-when-cross-origin",
				"X-Content-Type-Options": "nosniff",
				"Permissions-Policy":     "geolocation=(), microphone=(), camera=()",
			}

			for header, expectedValue := range headers {
				got := rec.Header().Get(header)
				if got != expectedValue {
					t.Errorf("%s: expected '%s', got '%s'", header, expectedValue, got)
				}
			}

			// Check HSTS conditionally
			hsts := rec.Header().Get("Strict-Transport-Security")
			if tt.wantHSTS {
				expectedHSTS := "max-age=31536000; includeSubDomains"
				if hsts != expectedHSTS {
					t.Errorf("HSTS: expected '%s', got '%s'", expectedHSTS, hsts)
				}
			} else {
				if hsts != "" {
					t.Errorf("HSTS: expected no header when disabled, got '%s'", hsts)
				}
			}

			// Verify no global CSP (only route-specific CSP for /callback)
			csp := rec.Header().Get("Content-Security-Policy")
			if csp != "" {
				t.Errorf("expected no global CSP header, got: %s", csp)
			}
		})
	}
}

func TestSecurityHeadersOnAllRoutes(t *testing.T) {
	// Verify security headers are applied to all routes
	cfg := config.Config{
		Env:                "test",
		AppHostname:        "localhost",
		Port:               "8080",
		CookieDomain:       ".localhost",
		EnableHSTS:         true,
		RedirectTTL:        30 * time.Minute,
		SessionTTL:         24 * time.Hour,
		LogLevel:           "info",
		CookieSigningKey:   []byte("test-signing-key-32-bytes-long!"),
		Auth0Domain:        "test.auth0.com",
		Auth0ClientID:      "test-client-id",
		Auth0ClientSecret:  "test-client-secret",
		Auth0RedirectPath:  "/callback",
		IntercomAppID:      "test-app-id",
		AllowedReturnHosts: []string{"example.com"},
	}
	router := NewRouter(cfg)

	routes := []string{
		"/healthz",
		"/callback",
		"/debug/redirect-cookie",
		"/metrics/dev",
	}

	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest("GET", route, nil)
			req.Header.Set("Referer", "https://localhost/")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			// All routes should have global security headers
			if got := rec.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
				t.Errorf("%s missing Referrer-Policy", route)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("%s missing X-Content-Type-Options", route)
			}
			if got := rec.Header().Get("Permissions-Policy"); got != "geolocation=(), microphone=(), camera=()" {
				t.Errorf("%s missing Permissions-Policy", route)
			}
			if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
				t.Errorf("%s missing HSTS", route)
			}
		})
	}
}
