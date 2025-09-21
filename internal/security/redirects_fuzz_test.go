//go:build go1.22

package security

import (
	"strings"
	"testing"
)

func FuzzSanitizeReturnURL(f *testing.F) {
	// Create a sanitizer with test hosts
	allowlist, _ := NewHostAllowlist([]string{
		"example.com",
		"*.example.com",
		"test.org",
	})
	sanitizer := NewSanitizer(allowlist, []string{"utm_source", "utm_campaign"})

	// Add seed corpus with various test cases
	seeds := []string{
		// Valid URLs
		"https://example.com",
		"https://example.com/path",
		"https://example.com/path?query=value",
		"https://sub.example.com/path?utm_source=test",
		"https://test.org:443/path",

		// Various schemes
		"http://example.com",
		"ftp://example.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"gopher://example.com",
		"ws://example.com",
		"wss://example.com",

		// Unicode and internationalization
		"https://examplе.com", // Cyrillic 'е'
		"https://еxample.com", // Cyrillic 'е' at start
		"https://example.com/påth",
		"https://example.com/路径",
		"https://example.com/مسار",
		"https://example.com/\u0000path",
		"https://example.com/\ufffdpath",
		"https://xn--exmple-cua.com", // Punycode

		// Long query strings
		"https://example.com?" + strings.Repeat("a=b&", 1000),
		"https://example.com/path?" + strings.Repeat("param=", 500) + "value",
		"https://example.com?" + strings.Repeat("x", 10000),

		// CRLF injection attempts
		"https://example.com\r\nSet-Cookie: evil=true",
		"https://example.com%0d%0aSet-Cookie:%20evil=true",
		"https://example.com\r\n\r\n<script>alert(1)</script>",
		"https://example.com?param=value\r\nHeader: injected",
		"https://example.com#fragment\r\nHeader: value",

		// Path traversal attempts
		"https://example.com/../../../etc/passwd",
		"https://example.com/..\\..\\..\\windows\\system32",
		"https://example.com/path/../../../../etc/passwd",
		"https://example.com/%2e%2e%2f%2e%2e%2f",
		"https://example.com/./././../../../",

		// URL encoding edge cases
		"https://example.com/%00",
		"https://example.com/%",
		"https://example.com/%%30",
		"https://example.com/%zz",
		"https://example.com/%20%20%20",
		"https://example.com/?%00param=value",

		// Special characters
		"https://example.com/<script>",
		"https://example.com/'><script>alert(1)</script>",
		"https://example.com/\"><script>alert(1)</script>",
		"https://example.com/';alert(1)//",
		"https://example.com/`alert(1)`",
		"https://example.com/${alert(1)}",

		// Port variations
		"https://example.com:443",
		"https://example.com:8443",
		"https://example.com:80",
		"https://example.com:0",
		"https://example.com:65536",
		"https://example.com:-1",
		"https://example.com:abc",

		// Fragment variations
		"https://example.com#fragment",
		"https://example.com#",
		"https://example.com##double",
		"https://example.com#<script>",
		"https://example.com#/../etc/passwd",

		// IPv4 and IPv6
		"https://192.168.1.1",
		"https://127.0.0.1",
		"https://[::1]",
		"https://[2001:db8::1]",
		"https://[::ffff:192.168.1.1]",

		// Malformed URLs
		"",
		" ",
		"https://",
		"://example.com",
		"https:/example.com",
		"https:///example.com",
		"https://example..com",
		"https://example.com..",
		"https://.example.com",
		"https://example.com./",

		// Mixed case
		"HTTPS://EXAMPLE.COM",
		"HtTpS://ExAmPlE.CoM/PaTh",
		"https://EXAMPLE.com/PATH?PARAM=VALUE",

		// Special domains
		"https://localhost",
		"https://127.0.0.1",
		"https://example.com.evil.com",
		"https://evil.com#@example.com",
		"https://example.com@evil.com",
		"https://user:pass@example.com",

		// Extremely long URLs
		"https://example.com/" + strings.Repeat("a", 10000),
		"https://" + strings.Repeat("sub.", 100) + "example.com",
		"https://example.com?" + strings.Repeat("param=value&", 1000),

		// Null bytes and control characters
		"https://example.com/path\x00/more",
		"https://example.com/\x01\x02\x03",
		"https://example.com/\t\n\r",
		"https://example.com/\x1b[31mred\x1b[0m",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	// The actual fuzzing function
	f.Fuzz(func(t *testing.T, input string) {
		// The function should never panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SanitizeReturnURL panicked on input %q: %v", input, r)
			}
		}()

		result, err := sanitizer.SanitizeReturnURL(input)

		if err == nil {
			// If no error, the result should be a valid HTTPS URL
			if !strings.HasPrefix(result, "https://") {
				t.Errorf("Sanitized URL doesn't start with https://: %q from input %q", result, input)
			}

			// The result should not contain control characters
			for _, ch := range result {
				if ch < 32 && ch != '\t' {
					t.Errorf("Sanitized URL contains control character %d: %q from input %q", ch, result, input)
				}
			}

			// The result should not contain CRLF
			if strings.Contains(result, "\r") || strings.Contains(result, "\n") {
				t.Errorf("Sanitized URL contains CRLF: %q from input %q", result, input)
			}

			// The result should not contain fragments
			if strings.Contains(result, "#") {
				t.Errorf("Sanitized URL contains fragment: %q from input %q", result, input)
			}

			// Verify the host is actually allowed
			// Extract host from result (simple check)
			if len(result) > 8 { // "https://" is 8 chars
				remaining := result[8:]

				// Only consider @ for userinfo if it comes before the first /
				slashIdx := strings.Index(remaining, "/")
				atIdx := strings.Index(remaining, "@")

				// Skip userinfo if @ comes before / (or if there's no /)
				if atIdx != -1 && (slashIdx == -1 || atIdx < slashIdx) {
					remaining = remaining[atIdx+1:]
				}

				hostEnd := strings.IndexAny(remaining, "/?")
				var host string
				if hostEnd == -1 {
					host = remaining
				} else {
					host = remaining[:hostEnd]
				}

				// Remove port if present
				if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
					// But make sure it's not part of an IPv6 address
					if !strings.Contains(host, "[") {
						host = host[:colonIdx]
					}
				}

				if host != "" && !allowlist.IsAllowed(host) {
					t.Errorf("Sanitized URL has disallowed host %q: %q from input %q", host, result, input)
				}
			}
		}
		// If there's an error, that's fine - the function handled invalid input correctly
	})
}

func BenchmarkSanitizeReturnURL(b *testing.B) {
	// Create a sanitizer with test hosts
	allowlist, _ := NewHostAllowlist([]string{
		"example.com",
		"*.example.com",
		"test.org",
	})
	sanitizer := NewSanitizer(allowlist, []string{"utm_source", "utm_campaign"})

	testCases := []struct {
		name string
		url  string
	}{
		{
			name: "GoodURL",
			url:  "https://example.com/path?utm_source=test&utm_campaign=spring&other=filtered",
		},
		{
			name: "BadURL",
			url:  "javascript:alert('xss')",
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = sanitizer.SanitizeReturnURL(tc.url)
			}
		})
	}
}