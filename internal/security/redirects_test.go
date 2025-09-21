package security

import (
	"testing"
)

func TestNewSanitizer(t *testing.T) {
	allowlist, err := NewHostAllowlist([]string{"example.com", "*.allowed.com"})
	if err != nil {
		t.Fatalf("NewHostAllowlist() error = %v", err)
	}

	sanitizer := NewSanitizer(allowlist, []string{"utm_campaign", "utm_source", "ref"})

	if sanitizer.Allow != allowlist {
		t.Error("Sanitizer.Allow not set correctly")
	}

	expectedQueries := []string{"utm_campaign", "utm_source", "ref"}
	for _, query := range expectedQueries {
		if _, ok := sanitizer.AllowedQuery[query]; !ok {
			t.Errorf("Expected query parameter %q not found in AllowedQuery", query)
		}
	}

	if len(sanitizer.AllowedQuery) != len(expectedQueries) {
		t.Errorf("Expected %d allowed query parameters, got %d", len(expectedQueries), len(sanitizer.AllowedQuery))
	}
}

func TestSanitizer_SanitizeReturnURL(t *testing.T) {
	allowlist, err := NewHostAllowlist([]string{"example.com", "*.allowed.com", "localhost"})
	if err != nil {
		t.Fatalf("NewHostAllowlist() error = %v", err)
	}

	sanitizer := NewSanitizer(allowlist, []string{"utm_campaign", "utm_source"})

	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
		errMsg   string
	}{
		// Valid cases
		{
			name:     "basic https url",
			input:    "https://example.com/path",
			expected: "https://example.com/path",
		},
		{
			name:     "url with default path",
			input:    "https://example.com",
			expected: "https://example.com/",
		},
		{
			name:     "url with default port 443",
			input:    "https://example.com:443/path",
			expected: "https://example.com/path",
		},
		{
			name:     "url with allowed query params",
			input:    "https://example.com/path?utm_campaign=test&utm_source=email&other=removed",
			expected: "https://example.com/path?utm_campaign=test&utm_source=email",
		},
		{
			name:     "url with query params in different order",
			input:    "https://example.com/path?utm_source=email&utm_campaign=test&other=removed",
			expected: "https://example.com/path?utm_campaign=test&utm_source=email",
		},
		{
			name:     "url with fragment removed",
			input:    "https://example.com/path#fragment",
			expected: "https://example.com/path",
		},
		{
			name:     "wildcard subdomain",
			input:    "https://api.allowed.com/endpoint",
			expected: "https://api.allowed.com/endpoint",
		},
		{
			name:     "wildcard base domain",
			input:    "https://allowed.com/endpoint",
			expected: "https://allowed.com/endpoint",
		},
		{
			name:     "hostname with trailing dot",
			input:    "https://example.com./path",
			expected: "https://example.com/path",
		},
		{
			name:     "uppercase hostname normalized",
			input:    "https://EXAMPLE.COM/path",
			expected: "https://example.com/path",
		},
		{
			name:     "complex valid url",
			input:    "https://api.allowed.com:443/v1/endpoint?utm_campaign=summer&other=removed&utm_source=newsletter#section",
			expected: "https://api.allowed.com/v1/endpoint?utm_campaign=summer&utm_source=newsletter",
		},

		// Error cases
		{
			name:    "empty url",
			input:   "",
			wantErr: true,
			errMsg:  "empty URL",
		},
		{
			name:    "invalid url",
			input:   "not-a-url",
			wantErr: true,
			errMsg:  "must use HTTPS scheme",
		},
		{
			name:    "http scheme not allowed",
			input:   "http://example.com/path",
			wantErr: true,
			errMsg:  "must use HTTPS scheme",
		},
		{
			name:    "ftp scheme not allowed",
			input:   "ftp://example.com/path",
			wantErr: true,
			errMsg:  "must use HTTPS scheme",
		},
		{
			name:    "host not in allowlist",
			input:   "https://evil.com/path",
			wantErr: true,
			errMsg:  "is not allowed",
		},
		{
			name:    "non-standard port",
			input:   "https://example.com:8080/path",
			wantErr: true,
			errMsg:  "must use default HTTPS port (443)",
		},
		{
			name:    "port 80",
			input:   "https://example.com:80/path",
			wantErr: true,
			errMsg:  "must use default HTTPS port (443)",
		},
		{
			name:    "custom port 9000",
			input:   "https://example.com:9000/path",
			wantErr: true,
			errMsg:  "must use default HTTPS port (443)",
		},
		{
			name:    "subdomain not matching wildcard",
			input:   "https://api.notallowed.com/path",
			wantErr: true,
			errMsg:  "is not allowed",
		},
		{
			name:    "relative url",
			input:   "/path",
			wantErr: true,
			errMsg:  "must use HTTPS scheme",
		},
		{
			name:    "protocol relative url",
			input:   "//example.com/path",
			wantErr: true,
			errMsg:  "must use HTTPS scheme",
		},
		{
			name:    "javascript scheme attack",
			input:   "javascript:alert(1)",
			wantErr: true,
			errMsg:  "must use HTTPS scheme",
		},
		{
			name:    "data scheme attack",
			input:   "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
			wantErr: true,
			errMsg:  "must use HTTPS scheme",
		},
		{
			name:    "IPv4 address not allowed",
			input:   "https://127.0.0.1/path",
			wantErr: true,
			errMsg:  "is not allowed",
		},
		{
			name:    "IPv6 address not allowed",
			input:   "https://[::1]/path",
			wantErr: true,
			errMsg:  "is not allowed",
		},
		{
			name:    "whitespace only input",
			input:   "   ",
			wantErr: true,
			errMsg:  "empty URL",
		},
		{
			name:    "riscv.org with forbidden port",
			input:   "https://riscv.org:8444/path",
			wantErr: true,
			errMsg:  "must use default HTTPS port (443)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeReturnURL(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("SanitizeReturnURL(%q) expected error, got nil", tt.input)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("SanitizeReturnURL(%q) error = %q, want substring %q", tt.input, err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("SanitizeReturnURL(%q) unexpected error = %v", tt.input, err)
				return
			}

			if result != tt.expected {
				t.Errorf("SanitizeReturnURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizer_QueryParameterFiltering(t *testing.T) {
	allowlist, err := NewHostAllowlist([]string{"example.com"})
	if err != nil {
		t.Fatalf("NewHostAllowlist() error = %v", err)
	}

	sanitizer := NewSanitizer(allowlist, []string{"utm_campaign", "utm_source", "ref"})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no query parameters",
			input:    "https://example.com/path",
			expected: "https://example.com/path",
		},
		{
			name:     "all parameters allowed",
			input:    "https://example.com/path?utm_campaign=test&utm_source=email&ref=homepage",
			expected: "https://example.com/path?ref=homepage&utm_campaign=test&utm_source=email",
		},
		{
			name:     "mixed allowed and disallowed",
			input:    "https://example.com/path?utm_campaign=test&tracking_id=123&utm_source=email&session=abc",
			expected: "https://example.com/path?utm_campaign=test&utm_source=email",
		},
		{
			name:     "all parameters disallowed",
			input:    "https://example.com/path?tracking_id=123&session=abc&user_id=456",
			expected: "https://example.com/path",
		},
		{
			name:     "duplicate parameters",
			input:    "https://example.com/path?utm_campaign=test1&utm_campaign=test2&utm_source=email",
			expected: "https://example.com/path?utm_campaign=test1&utm_campaign=test2&utm_source=email",
		},
		{
			name:     "empty parameter values",
			input:    "https://example.com/path?utm_campaign=&utm_source=email&ref=",
			expected: "https://example.com/path?ref=&utm_campaign=&utm_source=email",
		},
		{
			name:     "url encoded parameters",
			input:    "https://example.com/path?utm_campaign=summer%20sale&utm_source=email%2Bnewsletter",
			expected: "https://example.com/path?utm_campaign=summer+sale&utm_source=email%2Bnewsletter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeReturnURL(tt.input)
			if err != nil {
				t.Errorf("SanitizeReturnURL(%q) unexpected error = %v", tt.input, err)
				return
			}

			if result != tt.expected {
				t.Errorf("SanitizeReturnURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizer_HostNormalization(t *testing.T) {
	allowlist, err := NewHostAllowlist([]string{"example.com", "*.sub.example.com"})
	if err != nil {
		t.Fatalf("NewHostAllowlist() error = %v", err)
	}

	sanitizer := NewSanitizer(allowlist, []string{})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase normalization",
			input:    "https://EXAMPLE.COM/path",
			expected: "https://example.com/path",
		},
		{
			name:     "mixed case normalization",
			input:    "https://Example.Com/path",
			expected: "https://example.com/path",
		},
		{
			name:     "multiple trailing dots",
			input:    "https://example.com../path",
			expected: "https://example.com/path", // Removes all trailing dots
		},
		{
			name:     "subdomain normalization",
			input:    "https://API.SUB.EXAMPLE.COM./path",
			expected: "https://api.sub.example.com/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeReturnURL(tt.input)
			if err != nil {
				t.Errorf("SanitizeReturnURL(%q) unexpected error = %v", tt.input, err)
				return
			}

			if result != tt.expected {
				t.Errorf("SanitizeReturnURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizer_PathNormalization(t *testing.T) {
	allowlist, err := NewHostAllowlist([]string{"example.com"})
	if err != nil {
		t.Fatalf("NewHostAllowlist() error = %v", err)
	}

	sanitizer := NewSanitizer(allowlist, []string{})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty path gets default slash",
			input:    "https://example.com",
			expected: "https://example.com/",
		},
		{
			name:     "existing path preserved",
			input:    "https://example.com/api/v1",
			expected: "https://example.com/api/v1",
		},
		{
			name:     "root path preserved",
			input:    "https://example.com/",
			expected: "https://example.com/",
		},
		{
			name:     "path with query and fragment",
			input:    "https://example.com/path?param=value#section",
			expected: "https://example.com/path", // Fragment removed, no allowed query params
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeReturnURL(tt.input)
			if err != nil {
				t.Errorf("SanitizeReturnURL(%q) unexpected error = %v", tt.input, err)
				return
			}

			if result != tt.expected {
				t.Errorf("SanitizeReturnURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizer_RiscvOrgSpecificCases(t *testing.T) {
	// Test specific RISCV.org cases with exact string assertions
	allowlist, err := NewHostAllowlist([]string{"riscv.org", "*.riscv.org"})
	if err != nil {
		t.Fatalf("NewHostAllowlist() error = %v", err)
	}

	sanitizer := NewSanitizer(allowlist, []string{"utm_source", "utm_campaign"})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "riscv.org with query filtering and fragment removal",
			input:    "https://riscv.org/members/resources/?utm_source=x&foo=bar#frag",
			expected: "https://riscv.org/members/resources/?utm_source=x",
		},
		{
			name:     "www.riscv.org empty path gets default slash",
			input:    "https://www.riscv.org",
			expected: "https://www.riscv.org/",
		},
		{
			name:     "subdomain allowed via wildcard",
			input:    "https://api.riscv.org/endpoint",
			expected: "https://api.riscv.org/endpoint",
		},
		{
			name:     "host case normalization",
			input:    "https://WWW.RISCV.ORG/path",
			expected: "https://www.riscv.org/path",
		},
		{
			name:     "host with trailing dot normalization",
			input:    "https://riscv.org./members/",
			expected: "https://riscv.org/members/",
		},
		{
			name:     "complex case: uppercase, trailing dot, query filtering, fragment removal",
			input:    "https://API.RISCV.ORG./docs?utm_source=newsletter&utm_campaign=2024&tracking=remove&session=abc#section",
			expected: "https://api.riscv.org/docs?utm_campaign=2024&utm_source=newsletter",
		},
		{
			name:     "base domain with empty path and mixed case",
			input:    "https://RISCV.ORG",
			expected: "https://riscv.org/",
		},
		{
			name:     "subdomain with port 443 removal",
			input:    "https://docs.riscv.org:443/spec/",
			expected: "https://docs.riscv.org/spec/",
		},
		{
			name:     "multiple trailing dots with query params",
			input:    "https://riscv.org../members?utm_source=email&other=filtered",
			expected: "https://riscv.org/members?utm_source=email",
		},
		{
			name:     "deep subdomain with all normalizations",
			input:    "https://VERY.DEEP.SUB.RISCV.ORG.:443/api/v1/endpoint?utm_campaign=test&utm_source=web&malicious=evil#anchor",
			expected: "https://very.deep.sub.riscv.org/api/v1/endpoint?utm_campaign=test&utm_source=web",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeReturnURL(tt.input)
			if err != nil {
				t.Errorf("SanitizeReturnURL(%q) unexpected error = %v", tt.input, err)
				return
			}

			if result != tt.expected {
				t.Errorf("SanitizeReturnURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}