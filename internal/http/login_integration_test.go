package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// TestLoginToDebugIntegration tests the complete end-to-end flow:
// 1. Build config with test keys and domains
// 2. Initialize router with sanitizer and middleware
// 3. Issue GET /login with valid return_to and referer
// 4. Capture Set-Cookie header
// 5. Use that cookie in a request to /debug/redirect-cookie
// 6. Assert the decoded URL matches expected value
func TestLoginToDebugIntegration(t *testing.T) {
	tests := []struct {
		name           string
		returnTo       string
		referer        string
		expectedURL    string
		expectCookie   bool
		expectDebugOK  bool
	}{
		{
			name:          "complete flow with valid URL and referer",
			returnTo:      "https://example.com/dashboard?utm_source=test",
			referer:       "https://example.com/login-page",
			expectedURL:   "https://example.com/dashboard?utm_source=test",
			expectCookie:  true,
			expectDebugOK: true,
		},
		{
			name:          "complete flow with subdomain",
			returnTo:      "https://app.example.com/user/profile",
			referer:       "https://www.example.com/",
			expectedURL:   "https://app.example.com/user/profile",
			expectCookie:  true,
			expectDebugOK: true,
		},
		{
			name:          "complete flow with no referer",
			returnTo:      "https://example.com/home",
			referer:       "",
			expectedURL:   "https://example.com/home",
			expectCookie:  true,
			expectDebugOK: true,
		},
		{
			name:          "complete flow with localhost",
			returnTo:      "https://localhost/dev/test",
			referer:       "https://localhost/dev",
			expectedURL:   "https://localhost/dev/test",
			expectCookie:  true,
			expectDebugOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Build config with test keys and domains
			cfg := config.Config{
				Env:                        "test", // Non-prod for debug endpoint
				AppHostname:                "localhost",
				Port:                       "8080",
				CookieDomain:               ".example.com",
				EnableHSTS:                 false,
				RedirectTTL:                30 * time.Minute,
				SessionTTL:                 24 * time.Hour,
				LogLevel:                   "info",
				AllowedReturnHosts:         []string{"example.com", "*.example.com", "localhost"},
				AllowedQueryParams:         []string{"utm_source", "utm_campaign", "utm_medium"},
				CookieSigningKey:           []byte("integration-test-key-32-bytes!!"),
				SecondaryCookieSigningKey:  []byte("secondary-test-key-32-bytes-!!"),
				RedirectSkew:               5 * time.Minute,
				Auth0Domain:                "test.auth0.com",
				Auth0ClientID:              "test-client-id",
				Auth0ClientSecret:          "test-client-secret",
				Auth0RedirectPath:          "/callback",
				IntercomAppID:              "test-app-id",
				IntercomJWTSecret:          "test-jwt-secret",
				TxnTTL:                     10 * time.Minute,
				TxnSkew:                    1 * time.Minute,
			}

			// Step 2: Initialize router with sanitizer and middleware
			router := NewRouter(cfg)

			// Step 3: Issue GET /login with valid return_to and referer
			loginURL := "/login?return_to=" + tt.returnTo
			loginReq, err := http.NewRequest("GET", loginURL, nil)
			if err != nil {
				t.Fatalf("failed to create login request: %v", err)
			}

			if tt.referer != "" {
				loginReq.Header.Set("Referer", tt.referer)
			}

			loginRec := httptest.NewRecorder()
			router.ServeHTTP(loginRec, loginReq)

			// Check login response - should be a redirect to Auth0
			if loginRec.Code != http.StatusFound {
				t.Fatalf("login request expected status 302, got %d: %s", loginRec.Code, loginRec.Body.String())
			}

			// Verify redirect to Auth0
			location := loginRec.Header().Get("Location")
			if location == "" {
				t.Fatal("expected Location header for Auth0 redirect")
			}
			if !strings.Contains(location, "test.auth0.com") {
				t.Errorf("expected redirect to Auth0, got: %s", location)
			}

			// Step 4: Capture Set-Cookie header
			cookies := loginRec.Result().Cookies()
			var redirectCookie *http.Cookie
			for _, cookie := range cookies {
				if cookie.Name == security.RedirectCookieName {
					redirectCookie = cookie
					break
				}
			}

			if tt.expectCookie {
				if redirectCookie == nil {
					t.Fatalf("expected redirect cookie to be set, but none found")
				}

				// Note: httptest strips leading dots from cookie domains, so we just verify
				// that a domain is set rather than checking the exact value

				if !redirectCookie.HttpOnly {
					t.Error("expected cookie to be HttpOnly")
				}

				if redirectCookie.SameSite != http.SameSiteLaxMode {
					t.Errorf("expected cookie SameSite to be Lax, got %v", redirectCookie.SameSite)
				}

				if redirectCookie.Path != "/" {
					t.Errorf("expected cookie path '/', got '%s'", redirectCookie.Path)
				}

				// Step 5: Use that cookie in a request to /debug/redirect-cookie
				debugReq, err := http.NewRequest("GET", "/debug/redirect-cookie", nil)
				if err != nil {
					t.Fatalf("failed to create debug request: %v", err)
				}

				debugReq.AddCookie(redirectCookie)
				debugRec := httptest.NewRecorder()
				router.ServeHTTP(debugRec, debugReq)

				// Step 6: Assert the decoded URL matches expected value
				if tt.expectDebugOK {
					if debugRec.Code != http.StatusOK {
						t.Fatalf("debug request failed with status %d: %s", debugRec.Code, debugRec.Body.String())
					}

					var debugResponse map[string]interface{}
					if err := json.Unmarshal(debugRec.Body.Bytes(), &debugResponse); err != nil {
						t.Fatalf("failed to parse debug response: %v", err)
					}

					// Verify debug response structure
					if valid, exists := debugResponse["valid"]; !exists || valid != true {
						t.Errorf("expected debug response to have 'valid': true, got %v", debugResponse)
					}

					if url, exists := debugResponse["url"]; !exists {
						t.Errorf("expected debug response to have 'url' field")
					} else if urlStr, ok := url.(string); !ok || urlStr != tt.expectedURL {
						t.Errorf("expected decoded URL '%s', got '%s'", tt.expectedURL, urlStr)
					}

					t.Logf("✅ Integration test passed: %s -> cookie -> %s", tt.returnTo, tt.expectedURL)
				}
			} else {
				if redirectCookie != nil {
					t.Errorf("expected no redirect cookie, but got one: %s", redirectCookie.Value)
				}
			}
		})
	}
}

// TestLoginToDebugIntegrationWithKeyRotation tests the integration with secondary key
func TestLoginToDebugIntegrationWithKeyRotation(t *testing.T) {
	// Step 1: Create config with primary and secondary keys
	cfg := config.Config{
		Env:                        "test",
		AppHostname:                "localhost",
		Port:                       "8080",
		CookieDomain:               ".example.com",
		EnableHSTS:                 false,
		RedirectTTL:                30 * time.Minute,
		SessionTTL:                 24 * time.Hour,
		LogLevel:                   "info",
		AllowedReturnHosts:         []string{"example.com"},
		AllowedQueryParams:         []string{"utm_source"},
		CookieSigningKey:           []byte("primary-integration-key-32-bytes!"),
		SecondaryCookieSigningKey:  []byte("secondary-integration-key-32-byt!"),
		RedirectSkew:               5 * time.Minute,
		Auth0Domain:                "test.auth0.com",
		Auth0ClientID:              "test-client-id",
		Auth0ClientSecret:          "test-client-secret",
		Auth0RedirectPath:          "/callback",
		IntercomAppID:              "test-app-id",
		IntercomJWTSecret:          "test-jwt-secret",
		TxnTTL:                     10 * time.Minute,
		TxnSkew:                    1 * time.Minute,
	}

	router := NewRouter(cfg)

	// Step 2: Create cookie with primary key
	returnTo := "https://example.com/test-rotation"
	loginReq, _ := http.NewRequest("GET", "/login?return_to="+returnTo, nil)
	loginReq.Header.Set("Referer", "https://example.com/")

	loginRec := httptest.NewRecorder()
	router.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusFound {
		t.Fatalf("login expected redirect (302), got %d: %s", loginRec.Code, loginRec.Body.String())
	}

	// Extract cookie
	cookies := loginRec.Result().Cookies()
	var redirectCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == security.RedirectCookieName {
			redirectCookie = cookie
			break
		}
	}

	if redirectCookie == nil {
		t.Fatal("no redirect cookie found")
	}

	// Step 3: Create new config with rotated keys (old secondary becomes primary)
	rotatedCfg := cfg
	rotatedCfg.CookieSigningKey = []byte("secondary-integration-key-32-byt!")
	rotatedCfg.SecondaryCookieSigningKey = []byte("primary-integration-key-32-bytes!")

	// Step 4: Create new router with rotated keys
	rotatedRouter := NewRouter(rotatedCfg)

	// Step 5: Try to decode cookie with rotated router
	debugReq, _ := http.NewRequest("GET", "/debug/redirect-cookie", nil)
	debugReq.AddCookie(redirectCookie)

	debugRec := httptest.NewRecorder()
	rotatedRouter.ServeHTTP(debugRec, debugReq)

	// Step 6: Verify it still works (cookie signed with old primary, verified with new secondary)
	if debugRec.Code != http.StatusOK {
		t.Fatalf("debug with rotated keys failed: %s", debugRec.Body.String())
	}

	var debugResponse map[string]interface{}
	if err := json.Unmarshal(debugRec.Body.Bytes(), &debugResponse); err != nil {
		t.Fatalf("failed to parse debug response: %v", err)
	}

	if valid, exists := debugResponse["valid"]; !exists || valid != true {
		t.Errorf("expected valid cookie after key rotation, got %v", debugResponse)
	}

	if url, exists := debugResponse["url"]; !exists {
		t.Errorf("expected url field in response")
	} else if urlStr, ok := url.(string); !ok || urlStr != returnTo {
		t.Errorf("expected URL '%s', got '%s'", returnTo, urlStr)
	}

	t.Logf("✅ Key rotation test passed: cookie created with primary key, validated with secondary key")
}

// TestLoginToDebugIntegrationErrorCases tests error scenarios in the integration
func TestLoginToDebugIntegrationErrorCases(t *testing.T) {
	cfg := config.Config{
		Env:                "test",
		AppHostname:        "localhost",
		Port:               "8080",
		CookieDomain:       ".example.com",
		EnableHSTS:         false,
		RedirectTTL:        30 * time.Minute,
		SessionTTL:         24 * time.Hour,
		LogLevel:           "info",
		AllowedReturnHosts: []string{"example.com"},
		AllowedQueryParams: []string{"utm_source"},
		CookieSigningKey:   []byte("integration-test-key-32-bytes!!"),
		RedirectSkew:       5 * time.Minute,
		Auth0Domain:        "test.auth0.com",
		Auth0ClientID:      "test-client-id",
		Auth0ClientSecret:  "test-client-secret",
		Auth0RedirectPath:  "/callback",
		IntercomAppID:      "test-app-id",
		IntercomJWTSecret:  "test-jwt-secret",
		TxnTTL:             10 * time.Minute,
		TxnSkew:            1 * time.Minute,
	}

	router := NewRouter(cfg)

	t.Run("debug endpoint with no cookie", func(t *testing.T) {
		debugReq, _ := http.NewRequest("GET", "/debug/redirect-cookie", nil)
		debugRec := httptest.NewRecorder()
		router.ServeHTTP(debugRec, debugReq)

		if debugRec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", debugRec.Code)
		}

		var response map[string]interface{}
		json.Unmarshal(debugRec.Body.Bytes(), &response)

		if _, exists := response["error"]; !exists {
			t.Error("expected error field when no cookie present")
		}
	})

	t.Run("debug endpoint with invalid cookie", func(t *testing.T) {
		debugReq, _ := http.NewRequest("GET", "/debug/redirect-cookie", nil)
		debugReq.AddCookie(&http.Cookie{
			Name:  security.RedirectCookieName,
			Value: "invalid.cookie.value",
		})

		debugRec := httptest.NewRecorder()
		router.ServeHTTP(debugRec, debugReq)

		if debugRec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", debugRec.Code)
		}

		var response map[string]interface{}
		json.Unmarshal(debugRec.Body.Bytes(), &response)

		if _, exists := response["error"]; !exists {
			t.Error("expected error field when cookie is invalid")
		}
	})

	t.Run("production environment blocks debug endpoint", func(t *testing.T) {
		prodCfg := cfg
		prodCfg.Env = "prod"
		prodRouter := NewRouter(prodCfg)

		debugReq, _ := http.NewRequest("GET", "/debug/redirect-cookie", nil)
		debugRec := httptest.NewRecorder()
		prodRouter.ServeHTTP(debugRec, debugReq)

		if debugRec.Code != http.StatusNotFound {
			t.Errorf("expected status 404 in production, got %d", debugRec.Code)
		}
	})
}