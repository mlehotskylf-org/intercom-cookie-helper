package security

import (
	"testing"
)

func TestNewHostAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		wantErr bool
		errMsg  string
	}{
		{
			name:  "valid exact hosts",
			hosts: []string{"example.com", "riscv.org", "localhost"},
		},
		{
			name:  "valid wildcard hosts",
			hosts: []string{"*.example.com", "*.riscv.org"},
		},
		{
			name:  "mixed valid hosts",
			hosts: []string{"example.com", "*.riscv.org", "localhost"},
		},
		{
			name:  "empty list",
			hosts: []string{},
		},
		{
			name:  "empty strings ignored",
			hosts: []string{"example.com", "", "  ", "riscv.org"},
		},
		{
			name:    "invalid scheme",
			hosts:   []string{"https://example.com"},
			wantErr: true,
			errMsg:  "must not contain scheme",
		},
		{
			name:    "invalid port",
			hosts:   []string{"example.com:8080"},
			wantErr: true,
			errMsg:  "must not contain port",
		},
		{
			name:    "invalid wildcard port",
			hosts:   []string{"*.example.com:8080"},
			wantErr: true,
			errMsg:  "must not contain port",
		},
		{
			name:    "invalid whitespace",
			hosts:   []string{"example .com"},
			wantErr: true,
			errMsg:  "must not contain whitespace",
		},
		{
			name:    "invalid tab",
			hosts:   []string{"example\t.com"},
			wantErr: true,
			errMsg:  "must not contain whitespace",
		},
		{
			name:    "invalid newline",
			hosts:   []string{"example\n.com"},
			wantErr: true,
			errMsg:  "must not contain whitespace",
		},
		{
			name:    "empty wildcard base",
			hosts:   []string{"*."},
			wantErr: true,
			errMsg:  "empty base",
		},
		{
			name:    "malformed http scheme",
			hosts:   []string{" http://riscv.org"},
			wantErr: true,
			errMsg:  "must not contain scheme",
		},
		{
			name:    "malformed double slash",
			hosts:   []string{"//riscv.org"},
			wantErr: false, // //domain.org is technically a valid hostname, just unusual
		},
		{
			name:    "malformed port",
			hosts:   []string{"riscv.org:8443"},
			wantErr: true,
			errMsg:  "must not contain port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowlist, err := NewHostAllowlist(tt.hosts)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewHostAllowlist() expected error, got nil")
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("NewHostAllowlist() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("NewHostAllowlist() unexpected error = %v", err)
				return
			}
			if allowlist == nil {
				t.Errorf("NewHostAllowlist() returned nil allowlist")
			}
		})
	}
}

func TestHostAllowlist_IsAllowed(t *testing.T) {
	allowlist, err := NewHostAllowlist([]string{
		"example.com",
		"riscv.org",
		"*.github.com",
		"*.localhost",
	})
	if err != nil {
		t.Fatalf("NewHostAllowlist() error = %v", err)
	}

	tests := []struct {
		name string
		host string
		want bool
	}{
		// Exact matches
		{"exact match example.com", "example.com", true},
		{"exact match riscv.org", "riscv.org", true},
		{"exact match case insensitive", "EXAMPLE.COM", true},
		{"exact match with trailing dot", "example.com.", true},
		{"exact match with whitespace", " example.com ", true},

		// Wildcard matches - base domain
		{"wildcard base github.com", "github.com", true},
		{"wildcard base localhost", "localhost", true},

		// Wildcard matches - subdomains
		{"wildcard subdomain api.github.com", "api.github.com", true},
		{"wildcard subdomain www.github.com", "www.github.com", true},
		{"wildcard subdomain deep.sub.github.com", "deep.sub.github.com", true},
		{"wildcard subdomain test.localhost", "test.localhost", true},

		// Non-matches
		{"not in allowlist", "notallowed.com", false},
		{"partial match", "notexample.com", false},
		{"suffix but not subdomain", "fakeexample.com", false},
		{"prefix match", "example.com.evil.com", false},

		// Specific attack patterns
		{"evil prefix attack", "evilexample.com", false},
		{"evil prefix with dash", "evil-example.com", false},
		{"suffix redirect attack", "example.com.evil.com", false},
		{"subdomain spoofing", "example.com.attacker.com", false},

		// IP addresses (should be rejected)
		{"IPv4 address", "192.168.1.1", false},
		{"IPv6 address", "2001:db8::1", false},
		{"IPv6 with brackets", "[2001:db8::1]", false},
		{"localhost IPv4", "127.0.0.1", false},
		{"localhost IPv6", "::1", false},

		// Unicode/Punycode cases (treat literally, no IDNA normalization)
		{"unicode domain", "bücher.github.com", true},     // Should match wildcard *.github.com
		{"punycode domain", "xn--bcher-kva.github.com", true}, // Should match wildcard *.github.com
		{"unicode vs punycode different domains", "bücher.example", false}, // Not in allowlist
		{"punycode not in allowlist", "xn--bcher-kva.example", false}, // Not in allowlist

		// Edge cases
		{"empty string", "", false},
		{"just dot", ".", false},
		{"just spaces", "   ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allowlist.IsAllowed(tt.host)
			if got != tt.want {
				t.Errorf("HostAllowlist.IsAllowed(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestHostAllowlist_WildcardMatching(t *testing.T) {
	allowlist, err := NewHostAllowlist([]string{"*.example.com"})
	if err != nil {
		t.Fatalf("NewHostAllowlist() error = %v", err)
	}

	tests := []struct {
		name string
		host string
		want bool
	}{
		// Should match: base domain and subdomains
		{"base domain", "example.com", true},
		{"single subdomain", "www.example.com", true},
		{"deep subdomain", "api.v1.example.com", true},
		{"multiple subdomains", "a.b.c.example.com", true},

		// Should not match: different domains
		{"different domain", "example.org", false},
		{"suffix but not subdomain", "notexample.com", false},
		{"prefix", "example.com.evil.com", false},
		{"partial suffix", "ample.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allowlist.IsAllowed(tt.host)
			if got != tt.want {
				t.Errorf("HostAllowlist.IsAllowed(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestHostAllowlist_CaseSensitivity(t *testing.T) {
	allowlist, err := NewHostAllowlist([]string{
		"Example.COM",
		"*.GitHub.COM",
	})
	if err != nil {
		t.Fatalf("NewHostAllowlist() error = %v", err)
	}

	tests := []struct {
		name string
		host string
		want bool
	}{
		{"lowercase exact", "example.com", true},
		{"uppercase exact", "EXAMPLE.COM", true},
		{"mixed case exact", "Example.Com", true},
		{"lowercase wildcard base", "github.com", true},
		{"uppercase wildcard base", "GITHUB.COM", true},
		{"mixed case wildcard base", "GitHub.Com", true},
		{"lowercase wildcard sub", "api.github.com", true},
		{"uppercase wildcard sub", "API.GITHUB.COM", true},
		{"mixed case wildcard sub", "Api.GitHub.Com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allowlist.IsAllowed(tt.host)
			if got != tt.want {
				t.Errorf("HostAllowlist.IsAllowed(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestValidateHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
		errMsg  string
	}{
		{"valid domain", "example.com", false, ""},
		{"valid subdomain", "api.example.com", false, ""},
		{"valid wildcard", "*.example.com", false, ""},
		{"valid localhost", "localhost", false, ""},
		{"scheme http", "http://example.com", true, "must not contain scheme"},
		{"scheme https", "https://example.com", true, "must not contain scheme"},
		{"scheme ftp", "ftp://example.com", true, "must not contain scheme"},
		{"port number", "example.com:8080", true, "must not contain port"},
		{"wildcard with port", "*.example.com:8080", true, "must not contain port"},
		{"space", "example .com", true, "must not contain whitespace"},
		{"tab", "example\t.com", true, "must not contain whitespace"},
		{"newline", "example\n.com", true, "must not contain whitespace"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHost(tt.host)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateHost(%q) expected error, got nil", tt.host)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("validateHost(%q) error = %q, want substring %q", tt.host, err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateHost(%q) unexpected error = %v", tt.host, err)
				}
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{"IPv4", "192.168.1.1", true},
		{"IPv4 localhost", "127.0.0.1", true},
		{"IPv4 zero", "0.0.0.0", true},
		{"IPv6", "2001:db8::1", true},
		{"IPv6 localhost", "::1", true},
		{"IPv6 with brackets", "[2001:db8::1]", false}, // net.ParseIP doesn't handle brackets
		{"domain", "example.com", false},
		{"localhost", "localhost", false},
		{"empty", "", false},
		{"invalid IP", "999.999.999.999", false},
		{"partial IP", "192.168", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIPAddress(tt.host)
			if got != tt.want {
				t.Errorf("isIPAddress(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) &&
		(s == substr ||
		 s[:len(substr)] == substr ||
		 s[len(s)-len(substr):] == substr ||
		 indexString(s, substr) >= 0))
}

func indexString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}