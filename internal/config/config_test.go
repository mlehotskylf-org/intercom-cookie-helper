package config

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		def      string
		envValue string
		want     string
	}{
		{
			name:     "returns environment value when set",
			key:      "TEST_VAR",
			def:      "default",
			envValue: "actual",
			want:     "actual",
		},
		{
			name:     "returns default when env not set",
			key:      "TEST_VAR",
			def:      "default",
			envValue: "",
			want:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			}

			got := getEnv(tt.key, tt.def)
			if got != tt.want {
				t.Errorf("getEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCSV(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envValue string
		want     []string
	}{
		{
			name:     "parses simple CSV",
			key:      "TEST_CSV",
			envValue: "one,two,three",
			want:     []string{"one", "two", "three"},
		},
		{
			name:     "trims spaces",
			key:      "TEST_CSV",
			envValue: " one , two , three ",
			want:     []string{"one", "two", "three"},
		},
		{
			name:     "converts to lowercase",
			key:      "TEST_CSV",
			envValue: "ONE,Two,THREE",
			want:     []string{"one", "two", "three"},
		},
		{
			name:     "deduplicates values",
			key:      "TEST_CSV",
			envValue: "one,two,one,three,two",
			want:     []string{"one", "two", "three"},
		},
		{
			name:     "drops empty values",
			key:      "TEST_CSV",
			envValue: "one,,two,,,three",
			want:     []string{"one", "two", "three"},
		},
		{
			name:     "handles empty string",
			key:      "TEST_CSV",
			envValue: "",
			want:     nil,
		},
		{
			name:     "handles spaces and mixed case with dedup",
			key:      "TEST_CSV",
			envValue: " Host1.com, HOST1.COM, host2.com ",
			want:     []string{"host1.com", "host2.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			} else {
				os.Unsetenv(tt.key)
			}

			got := parseCSV(tt.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseCSV() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		def      string
		envValue string
		want     time.Duration
		wantErr  bool
	}{
		{
			name:     "parses environment value",
			key:      "TEST_DURATION",
			def:      "1h",
			envValue: "30m",
			want:     30 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "uses default when not set",
			key:      "TEST_DURATION",
			def:      "1h",
			envValue: "",
			want:     time.Hour,
			wantErr:  false,
		},
		{
			name:     "returns error for invalid duration",
			key:      "TEST_DURATION",
			def:      "1h",
			envValue: "invalid",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "handles hours",
			key:      "TEST_DURATION",
			def:      "1h",
			envValue: "24h",
			want:     24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "handles seconds",
			key:      "TEST_DURATION",
			def:      "1h",
			envValue: "30s",
			want:     30 * time.Second,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			} else {
				os.Unsetenv(tt.key)
			}

			got, err := parseDuration(tt.key, tt.def)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		def      bool
		envValue string
		want     bool
	}{
		{
			name:     "parses true",
			key:      "TEST_BOOL",
			def:      false,
			envValue: "true",
			want:     true,
		},
		{
			name:     "parses false",
			key:      "TEST_BOOL",
			def:      true,
			envValue: "false",
			want:     false,
		},
		{
			name:     "parses 1 as true",
			key:      "TEST_BOOL",
			def:      false,
			envValue: "1",
			want:     true,
		},
		{
			name:     "parses 0 as false",
			key:      "TEST_BOOL",
			def:      true,
			envValue: "0",
			want:     false,
		},
		{
			name:     "uses default when not set",
			key:      "TEST_BOOL",
			def:      true,
			envValue: "",
			want:     true,
		},
		{
			name:     "uses default for invalid value",
			key:      "TEST_BOOL",
			def:      true,
			envValue: "invalid",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			} else {
				os.Unsetenv(tt.key)
			}

			got := parseBool(tt.key, tt.def)
			if got != tt.want {
				t.Errorf("parseBool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeKey(t *testing.T) {
	// Test data
	testBytes := []byte("test key data")
	hexEncoded := hex.EncodeToString(testBytes)
	base64Encoded := base64.StdEncoding.EncodeToString(testBytes)
	base64URLEncoded := base64.RawURLEncoding.EncodeToString(testBytes)

	tests := []struct {
		name    string
		key     string
		want    []byte
		wantErr bool
	}{
		{
			name:    "decodes hex",
			key:     hexEncoded,
			want:    testBytes,
			wantErr: false,
		},
		{
			name:    "decodes base64",
			key:     base64Encoded,
			want:    testBytes,
			wantErr: false,
		},
		{
			name:    "decodes base64 URL encoding",
			key:     base64URLEncoded,
			want:    testBytes,
			wantErr: false,
		},
		{
			name:    "returns error for empty key",
			key:     "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "returns error for invalid encoding",
			key:     "not-valid-encoding!@#",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "handles hex with even length",
			key:     "48656c6c6f",
			want:    []byte("Hello"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
		wantErr  bool
	}{
		{
			name:     "normalizes simple hostname",
			hostname: "Example.COM",
			want:     "example.com",
			wantErr:  false,
		},
		{
			name:     "trims whitespace",
			hostname: "  localhost  ",
			want:     "localhost",
			wantErr:  false,
		},
		{
			name:     "rejects hostname with scheme",
			hostname: "https://example.com",
			want:     "",
			wantErr:  true,
		},
		{
			name:     "rejects hostname with port",
			hostname: "example.com:8080",
			want:     "",
			wantErr:  true,
		},
		{
			name:     "handles subdomain",
			hostname: "sub.EXAMPLE.com",
			want:     "sub.example.com",
			wantErr:  false,
		},
		{
			name:     "handles empty hostname",
			hostname: "",
			want:     "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeHostname(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeHostname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("normalizeHostname() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeAllowedHosts(t *testing.T) {
	tests := []struct {
		name           string
		hosts          []string
		wantNormalized []string
		wantProcessed  []ProcessedHost
	}{
		{
			name:           "handles empty slice",
			hosts:          []string{},
			wantNormalized: []string{},
			wantProcessed:  []ProcessedHost{},
		},
		{
			name:  "normalizes mixed case hosts",
			hosts: []string{"Example.COM", "SUB.domain.org"},
			wantNormalized: []string{"example.com", "sub.domain.org"},
			wantProcessed: []ProcessedHost{
				{Original: "example.com", Canonical: "example.com", IsWildcard: false},
				{Original: "sub.domain.org", Canonical: "sub.domain.org", IsWildcard: false},
			},
		},
		{
			name:  "processes wildcard patterns",
			hosts: []string{"*.EXAMPLE.COM", "specific.host.org"},
			wantNormalized: []string{"*.example.com", "specific.host.org"},
			wantProcessed: []ProcessedHost{
				{Original: "*.example.com", Canonical: "example.com", IsWildcard: true},
				{Original: "specific.host.org", Canonical: "specific.host.org", IsWildcard: false},
			},
		},
		{
			name:  "trims whitespace",
			hosts: []string{"  localhost  ", " *.example.com "},
			wantNormalized: []string{"localhost", "*.example.com"},
			wantProcessed: []ProcessedHost{
				{Original: "localhost", Canonical: "localhost", IsWildcard: false},
				{Original: "*.example.com", Canonical: "example.com", IsWildcard: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNormalized, gotProcessed := normalizeAllowedHosts(tt.hosts)
			if !reflect.DeepEqual(gotNormalized, tt.wantNormalized) {
				t.Errorf("normalizeAllowedHosts() normalized = %v, want %v", gotNormalized, tt.wantNormalized)
			}
			if !reflect.DeepEqual(gotProcessed, tt.wantProcessed) {
				t.Errorf("normalizeAllowedHosts() processed = %v, want %v", gotProcessed, tt.wantProcessed)
			}
		})
	}
}

func TestValidateErrorMessages(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectedErr string
	}{
		{
			name: "invalid PORT number",
			config: Config{
				AppHostname: "example.com",
				Port:        "99999",
			},
			expectedErr: `PORT must be 1-65535 (got "99999")`,
		},
		{
			name: "invalid PORT non-numeric",
			config: Config{
				AppHostname: "example.com",
				Port:        "abc",
			},
			expectedErr: `PORT must be a valid number 1-65535 (got "abc")`,
		},
		{
			name: "COOKIE_DOMAIN without leading dot",
			config: Config{
				AppHostname:  "example.com",
				Port:         "8080",
				CookieDomain: "example.com",
			},
			expectedErr: `COOKIE_DOMAIN must start with '.' for subdomain sharing (got "example.com", use ".example.com")`,
		},
		{
			name: "COOKIE_DOMAIN without second dot",
			config: Config{
				AppHostname:  "example.com",
				Port:         "8080",
				CookieDomain: ".com",
			},
			expectedErr: `COOKIE_DOMAIN must contain a dot after the leading dot (got ".com", expected format like '.example.com')`,
		},
		{
			name: "prod environment with INTERCOM_JWT_SECRET set",
			config: Config{
				Env:                "prod",
				AppHostname:        "example.com",
				Port:               "8080",
				CookieDomain:       ".example.com",
				IntercomAppID:      "ic_123",
				Auth0Domain:        "tenant.auth0.com",
				Auth0ClientID:      "client123",
				CookieSigningKey:   make([]byte, 32),
				IntercomJWTSecret:  "should-not-be-set",
				RedirectTTL:        30 * time.Minute,
				SessionTTL:         24 * time.Hour,
				LogLevel:           "info",
			},
			expectedErr: "in prod, INTERCOM_JWT_SECRET must be unset (use secret manager instead)",
		},
		{
			name: "invalid ENV value",
			config: Config{
				AppHostname:      "example.com",
				Port:             "8080",
				CookieDomain:     ".example.com",
				IntercomAppID:    "ic_123",
				Auth0Domain:      "tenant.auth0.com",
				Auth0ClientID:    "client123",
				CookieSigningKey: make([]byte, 32),
				Env:              "invalid",
				RedirectTTL:      30 * time.Minute,
				SessionTTL:       24 * time.Hour,
				LogLevel:         "info",
			},
			expectedErr: `ENV must be 'dev', 'staging', or 'prod' (got "invalid")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err == nil {
				t.Fatalf("expected error but got none")
			}
			if err.Error() != tt.expectedErr {
				t.Errorf("expected error %q, got %q", tt.expectedErr, err.Error())
			}
		})
	}
}

func TestConfig_BuildSanitizer(t *testing.T) {
	tests := []struct {
		name               string
		config             Config
		wantErr            bool
		testURL            string
		expectedSanitized  string
	}{
		{
			name: "valid config with custom allowed hosts and query params",
			config: Config{
				AllowedReturnHosts: []string{"example.com", "*.allowed.com"},
				AllowedQueryParams: []string{"utm_campaign", "utm_source", "ref"},
			},
			testURL:           "https://example.com/path?utm_campaign=test&other=filtered&ref=homepage",
			expectedSanitized: "https://example.com/path?ref=homepage&utm_campaign=test",
		},
		{
			name: "config with default query params",
			config: Config{
				AllowedReturnHosts: []string{"example.com"},
				AllowedQueryParams: nil, // Should default to utm_campaign, utm_source
			},
			testURL:           "https://example.com/path?utm_campaign=test&utm_source=email&other=filtered",
			expectedSanitized: "https://example.com/path?utm_campaign=test&utm_source=email",
		},
		{
			name: "config with empty query params list",
			config: Config{
				AllowedReturnHosts: []string{"example.com"},
				AllowedQueryParams: []string{}, // Should default to utm_campaign, utm_source
			},
			testURL:           "https://example.com/path?utm_campaign=test&utm_source=email&other=filtered",
			expectedSanitized: "https://example.com/path?utm_campaign=test&utm_source=email",
		},
		{
			name: "invalid allowed hosts",
			config: Config{
				AllowedReturnHosts: []string{"https://example.com"}, // Invalid - contains scheme
				AllowedQueryParams: []string{"utm_campaign"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitizer, err := tt.config.BuildSanitizer()

			if tt.wantErr {
				if err == nil {
					t.Errorf("BuildSanitizer() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("BuildSanitizer() unexpected error = %v", err)
				return
			}

			if sanitizer == nil {
				t.Errorf("BuildSanitizer() returned nil sanitizer")
				return
			}

			// Test the sanitizer works correctly
			if tt.testURL != "" {
				result, err := sanitizer.SanitizeReturnURL(tt.testURL)
				if err != nil {
					t.Errorf("SanitizeReturnURL() unexpected error = %v", err)
					return
				}

				if result != tt.expectedSanitized {
					t.Errorf("SanitizeReturnURL() = %q, want %q", result, tt.expectedSanitized)
				}
			}
		})
	}
}