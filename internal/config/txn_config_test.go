package config

import (
	"os"
	"testing"
	"time"
)

func TestTxnTTLParsing(t *testing.T) {
	tests := []struct {
		name    string
		envVal  string
		want    time.Duration
		wantErr bool
	}{
		{
			name:   "default value",
			envVal: "",
			want:   10 * time.Minute,
		},
		{
			name:   "custom value",
			envVal: "15m",
			want:   15 * time.Minute,
		},
		{
			name:   "minimum valid",
			envVal: "5m",
			want:   5 * time.Minute,
		},
		{
			name:   "maximum valid",
			envVal: "20m",
			want:   20 * time.Minute,
		},
		{
			name:    "invalid format",
			envVal:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env
			os.Clearenv()

			// Set required env vars
			os.Setenv("ENV", "dev")
			os.Setenv("APP_HOSTNAME", "example.com")
			os.Setenv("PORT", "8080")
			os.Setenv("COOKIE_DOMAIN", ".example.com")
			os.Setenv("INTERCOM_APP_ID", "ic_123")
			os.Setenv("INTERCOM_JWT_SECRET", "secret")
			os.Setenv("AUTH0_DOMAIN", "auth0.com")
			os.Setenv("AUTH0_CLIENT_ID", "client")
			os.Setenv("AUTH0_CLIENT_SECRET", "secret")
			os.Setenv("COOKIE_SIGNING_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

			if tt.envVal != "" {
				os.Setenv("TXN_TTL", tt.envVal)
			}

			cfg, err := FromEnv()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if cfg.TxnTTL != tt.want {
				t.Errorf("TxnTTL = %v, want %v", cfg.TxnTTL, tt.want)
			}
		})
	}
}

func TestTxnSkewParsing(t *testing.T) {
	tests := []struct {
		name    string
		envVal  string
		want    time.Duration
		wantErr bool
	}{
		{
			name:   "default value",
			envVal: "",
			want:   1 * time.Minute,
		},
		{
			name:   "custom value",
			envVal: "30s",
			want:   30 * time.Second,
		},
		{
			name:   "zero value",
			envVal: "0s",
			want:   0,
		},
		{
			name:   "maximum valid",
			envVal: "2m",
			want:   2 * time.Minute,
		},
		{
			name:    "invalid format",
			envVal:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env
			os.Clearenv()

			// Set required env vars
			os.Setenv("ENV", "dev")
			os.Setenv("APP_HOSTNAME", "example.com")
			os.Setenv("PORT", "8080")
			os.Setenv("COOKIE_DOMAIN", ".example.com")
			os.Setenv("INTERCOM_APP_ID", "ic_123")
			os.Setenv("INTERCOM_JWT_SECRET", "secret")
			os.Setenv("AUTH0_DOMAIN", "auth0.com")
			os.Setenv("AUTH0_CLIENT_ID", "client")
			os.Setenv("AUTH0_CLIENT_SECRET", "secret")
			os.Setenv("COOKIE_SIGNING_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

			if tt.envVal != "" {
				os.Setenv("TXN_SKEW", tt.envVal)
			}

			cfg, err := FromEnv()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if cfg.TxnSkew != tt.want {
				t.Errorf("TxnSkew = %v, want %v", cfg.TxnSkew, tt.want)
			}
		})
	}
}

func TestTxnTTLValidation(t *testing.T) {
	tests := []struct {
		name    string
		ttl     time.Duration
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimum",
			ttl:  5 * time.Minute,
		},
		{
			name: "valid maximum",
			ttl:  20 * time.Minute,
		},
		{
			name: "valid middle",
			ttl:  10 * time.Minute,
		},
		{
			name:    "too short",
			ttl:     4 * time.Minute,
			wantErr: true,
			errMsg:  "TXN_TTL must be at least 5m",
		},
		{
			name:    "too long",
			ttl:     21 * time.Minute,
			wantErr: true,
			errMsg:  "TXN_TTL must be at most 20m",
		},
		{
			name: "zero value (skipped)",
			ttl:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Env:               "dev",
				AppHostname:       "example.com",
				Port:              "8080",
				CookieDomain:      ".example.com",
				IntercomAppID:     "ic_123",
				IntercomJWTSecret: "secret",
				Auth0Domain:       "auth0.com",
				Auth0ClientID:     "client",
				Auth0ClientSecret: "secret",
				CookieSigningKey:  []byte("test-key-32-bytes-long-for-tests"),
				TxnTTL:            tt.ttl,
				LogLevel:          "info",
			}

			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestTxnSkewValidation(t *testing.T) {
	tests := []struct {
		name    string
		skew    time.Duration
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid zero",
			skew: 0,
		},
		{
			name: "valid middle",
			skew: 1 * time.Minute,
		},
		{
			name: "valid maximum",
			skew: 2 * time.Minute,
		},
		{
			name:    "too long",
			skew:    3 * time.Minute,
			wantErr: true,
			errMsg:  "TXN_SKEW must be at most 2m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Env:               "dev",
				AppHostname:       "example.com",
				Port:              "8080",
				CookieDomain:      ".example.com",
				IntercomAppID:     "ic_123",
				IntercomJWTSecret: "secret",
				Auth0Domain:       "auth0.com",
				Auth0ClientID:     "client",
				Auth0ClientSecret: "secret",
				CookieSigningKey:  []byte("test-key-32-bytes-long-for-tests"),
				TxnSkew:           tt.skew,
				LogLevel:          "info",
			}

			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSecondaryTxnSigningKeyParsing(t *testing.T) {
	tests := []struct {
		name    string
		envVal  string
		wantLen int
		wantErr bool
	}{
		{
			name:    "empty (optional)",
			envVal:  "",
			wantLen: 0,
		},
		{
			name:    "valid hex",
			envVal:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantLen: 32,
		},
		{
			name:    "valid base64",
			envVal:  "dGVzdC1rZXktMzItYnl0ZXMtbG9uZy0hISEhISEh",
			wantLen: 30,
		},
		{
			name:    "invalid encoding",
			envVal:  "invalid!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env
			os.Clearenv()

			// Set required env vars
			os.Setenv("ENV", "dev")
			os.Setenv("APP_HOSTNAME", "example.com")
			os.Setenv("PORT", "8080")
			os.Setenv("COOKIE_DOMAIN", ".example.com")
			os.Setenv("INTERCOM_APP_ID", "ic_123")
			os.Setenv("INTERCOM_JWT_SECRET", "secret")
			os.Setenv("AUTH0_DOMAIN", "auth0.com")
			os.Setenv("AUTH0_CLIENT_ID", "client")
			os.Setenv("AUTH0_CLIENT_SECRET", "secret")
			os.Setenv("COOKIE_SIGNING_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

			if tt.envVal != "" {
				os.Setenv("SECONDARY_TXN_SIGNING_KEY", tt.envVal)
			}

			cfg, err := FromEnv()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(cfg.SecondaryTxnSigningKey) != tt.wantLen {
				t.Errorf("SecondaryTxnSigningKey length = %d, want %d", len(cfg.SecondaryTxnSigningKey), tt.wantLen)
			}
		})
	}
}

func TestTxnCookieOpts(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want struct {
			domain       string
			ttl          time.Duration
			skew         time.Duration
			secure       bool
			hasKey       bool
			hasSecondary bool
		}
	}{
		{
			name: "dev environment",
			cfg: Config{
				Env:                    "dev",
				CookieDomain:           ".example.com",
				TxnTTL:                 10 * time.Minute,
				TxnSkew:                1 * time.Minute,
				CookieSigningKey:       []byte("primary-key"),
				SecondaryTxnSigningKey: []byte("secondary-key"),
			},
			want: struct {
				domain       string
				ttl          time.Duration
				skew         time.Duration
				secure       bool
				hasKey       bool
				hasSecondary bool
			}{
				domain:       ".example.com",
				ttl:          10 * time.Minute,
				skew:         1 * time.Minute,
				secure:       false,
				hasKey:       true,
				hasSecondary: true,
			},
		},
		{
			name: "prod environment",
			cfg: Config{
				Env:              "prod",
				CookieDomain:     ".example.com",
				TxnTTL:           15 * time.Minute,
				TxnSkew:          30 * time.Second,
				CookieSigningKey: []byte("primary-key"),
			},
			want: struct {
				domain       string
				ttl          time.Duration
				skew         time.Duration
				secure       bool
				hasKey       bool
				hasSecondary bool
			}{
				domain:       ".example.com",
				ttl:          15 * time.Minute,
				skew:         30 * time.Second,
				secure:       true,
				hasKey:       true,
				hasSecondary: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.cfg.TxnCookieOpts()

			if opts.Domain != tt.want.domain {
				t.Errorf("Domain = %q, want %q", opts.Domain, tt.want.domain)
			}
			if opts.TTL != tt.want.ttl {
				t.Errorf("TTL = %v, want %v", opts.TTL, tt.want.ttl)
			}
			if opts.Skew != tt.want.skew {
				t.Errorf("Skew = %v, want %v", opts.Skew, tt.want.skew)
			}
			if opts.Secure != tt.want.secure {
				t.Errorf("Secure = %v, want %v", opts.Secure, tt.want.secure)
			}
			if (len(opts.SigningKey) > 0) != tt.want.hasKey {
				t.Errorf("has SigningKey = %v, want %v", len(opts.SigningKey) > 0, tt.want.hasKey)
			}
			if (len(opts.SecondaryKey) > 0) != tt.want.hasSecondary {
				t.Errorf("has SecondaryKey = %v, want %v", len(opts.SecondaryKey) > 0, tt.want.hasSecondary)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || len(substr) > 0 && len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
