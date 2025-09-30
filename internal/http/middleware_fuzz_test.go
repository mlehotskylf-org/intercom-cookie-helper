package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// FuzzRefererParsing tests the RequireReferrerHost middleware against random referer strings
// to ensure it never panics and handles all edge cases gracefully.
func FuzzRefererParsing(f *testing.F) {
	// Seed corpus with known edge cases
	seedCases := []string{
		"",                                           // empty
		"https://example.com",                        // valid
		"http://example.com",                         // wrong scheme
		"https://192.168.1.1",                        // IP literal
		"https://example.com:8080",                   // non-standard port
		"https://evil.com",                           // not in allowlist
		"javascript:alert(1)",                        // javascript scheme
		"data:text/html,<script>alert(1)</script>",  // data scheme
		"file:///etc/passwd",                         // file scheme
		"ftp://example.com",                          // ftp scheme
		"//example.com",                              // protocol-relative
		"https://",                                   // incomplete
		"https://example.com.",                       // trailing dot
		"https://EXAMPLE.COM",                        // uppercase
		"https://example.com/../../../etc/passwd",    // path traversal
		"https://example.com?param=value",            // query params
		"https://example.com#fragment",               // fragment
		"https://example.com:443",                    // explicit 443
		"https://[::1]",                              // IPv6 localhost
		"https://[2001:db8::1]",                      // IPv6
		"https://exam\x00ple.com",                    // null byte
		"https://exam\nple.com",                      // newline
		"https://exam\rple.com",                      // carriage return
		"https://exam\tple.com",                      // tab
		"https://exam ple.com",                       // space
		"https://example.com\x00/path",               // null in path
		"https://.example.com",                       // leading dot
		"https://..example.com",                      // double dots in domain
		"https://example..com",                       // double dots
		"https://example.com..",                      // trailing double dots
		"https://sub.example.com",                    // subdomain (allowed via wildcard)
		"https://sub.sub.example.com",                // deep subdomain
		"https://example.com" + string(rune(0x7F)),   // DEL character
		"https://example.com" + string(rune(0x1F)),   // control character
		"HTTPS://EXAMPLE.COM",                        // all caps
		"hTtPs://ExAmPlE.cOm",                        // mixed case
		"https://example.com:0",                      // port 0
		"https://example.com:65536",                  // port overflow
		"https://example.com:-1",                     // negative port
		"https://example.com:",                       // empty port
		"https://:443",                               // missing host
		"https://user:pass@example.com",              // userinfo
		"https://user@example.com",                   // user only
		"https://@example.com",                       // empty userinfo
		"https://example.com/path?query#fragment",    // full URL
		"\x00https://example.com",                    // leading null
		"https://example.com\x00",                    // trailing null
		"   https://example.com   ",                  // leading/trailing spaces
		"https://127.0.0.1",                          // IPv4 loopback
		"https://0.0.0.0",                            // IPv4 zero
		"https://255.255.255.255",                    // IPv4 max
		"https://[::ffff:192.168.1.1]",               // IPv4-mapped IPv6
		"https://example",                            // no TLD
		"https://.com",                               // TLD only
		"https://example.com" + string(make([]byte, 1000)), // very long URL
		"https://" + string(make([]byte, 500)),       // very long host
	}

	for _, seed := range seedCases {
		f.Add(seed)
	}

	// Setup test dependencies
	cfg := config.Config{
		Env:                "dev",
		AllowedReturnHosts: []string{"example.com", "*.example.com"},
	}

	allowlist, err := security.NewHostAllowlist(cfg.AllowedReturnHosts)
	if err != nil {
		f.Fatal(err)
	}

	// Create test handler that should be called if validation passes
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := RequireReferrerHost(cfg, allowlist)
	handler := middleware(testHandler)

	// Fuzz test
	f.Fuzz(func(t *testing.T, referer string) {
		// This should never panic, regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("PANIC with referer %q: %v", referer, r)
			}
		}()

		req := httptest.NewRequest("GET", "/login", nil)
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		rec := httptest.NewRecorder()

		// Execute middleware
		handler.ServeHTTP(rec, req)

		// Validate response
		statusCode := rec.Code

		// Status must be either 200 (allowed), 400 (rejected), or 500 (server error)
		// We never expect any other status codes
		if statusCode != http.StatusOK && statusCode != http.StatusBadRequest && statusCode != http.StatusInternalServerError {
			t.Errorf("unexpected status code %d for referer %q", statusCode, referer)
		}

		// 500 errors should never happen in this middleware
		if statusCode == http.StatusInternalServerError {
			t.Errorf("unexpected server error (500) for referer %q", referer)
		}

		// Response body should always be valid (either JSON error or OK)
		body := rec.Body.String()
		if body == "" {
			t.Errorf("empty response body for referer %q (status %d)", referer, statusCode)
		}

		// Content-Type should be set appropriately
		contentType := rec.Header().Get("Content-Type")
		if statusCode == http.StatusBadRequest && contentType != "application/json; charset=utf-8" {
			t.Errorf("expected JSON content type for 400 response, got %q (referer: %q)", contentType, referer)
		}
	})
}

// FuzzReturnURLParsing tests URL sanitization against random return_to values
// to ensure no panics and proper validation.
func FuzzReturnURLParsing(f *testing.F) {
	// Seed corpus with known edge cases
	seedCases := []string{
		"",                                           // empty
		"https://example.com",                        // valid
		"http://example.com",                         // wrong scheme
		"https://example.com:8080",                   // non-standard port
		"https://evil.com",                           // not in allowlist
		"javascript:alert(1)",                        // javascript scheme
		"data:text/html,<script>",                    // data scheme
		"https://192.168.1.1",                        // IP literal
		"https://example.com/../../../etc/passwd",    // path traversal (fine after host)
		"https://example.com?param=value",            // query params
		"https://example.com#fragment",               // fragment
		"https://EXAMPLE.COM",                        // uppercase
		"https://example.com.",                       // trailing dot
		"https://example.com..",                      // trailing double dots
		"https://sub.example.com",                    // subdomain
		"https://[::1]",                              // IPv6
		"https://example.com\x00",                    // null byte
		"https://example.com" + string(make([]byte, 10000)), // very long
		"//example.com",                              // protocol-relative
		"https://",                                   // incomplete
		"https://user:pass@example.com",              // userinfo
		"HTTPS://EXAMPLE.COM/PATH",                   // all caps
		"https://example.com:443",                    // explicit 443 (should normalize)
		"https://example.com:0",                      // port 0
		"https://example.com:-1",                     // negative port
		"https://example.com:99999",                  // port overflow
	}

	for _, seed := range seedCases {
		f.Add(seed)
	}

	// Setup test dependencies
	cfg := config.Config{
		AllowedReturnHosts: []string{"example.com", "*.example.com"},
	}

	sanitizer, err := cfg.BuildSanitizer()
	if err != nil {
		f.Fatal(err)
	}

	// Fuzz test
	f.Fuzz(func(t *testing.T, returnURL string) {
		// This should never panic, regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("PANIC with return_to %q: %v", returnURL, r)
			}
		}()

		// Call SanitizeReturnURL
		sanitized, err := sanitizer.SanitizeReturnURL(returnURL)

		// Validate result
		if err != nil {
			// Error is acceptable - validate it's not empty
			if err.Error() == "" {
				t.Errorf("empty error message for return_to %q", returnURL)
			}
			// When there's an error, sanitized should be empty
			if sanitized != "" {
				t.Errorf("non-empty sanitized URL with error: %q (error: %v)", sanitized, err)
			}
		} else {
			// Success - validate sanitized URL
			if sanitized == "" {
				t.Errorf("empty sanitized URL without error for return_to %q", returnURL)
			}

			// Sanitized URL should always start with https://
			if len(sanitized) > 0 && sanitized[:8] != "https://" {
				t.Errorf("sanitized URL doesn't start with https://: %q (input: %q)", sanitized, returnURL)
			}

			// Sanitized URL should not contain control characters
			for i, ch := range sanitized {
				if ch < 32 || ch == 127 {
					t.Errorf("sanitized URL contains control character at position %d: %q (input: %q)", i, sanitized, returnURL)
				}
			}
		}
	})
}
