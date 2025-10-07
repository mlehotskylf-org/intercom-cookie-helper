package config

import "testing"

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{
			name:     "localhost lowercase",
			hostname: "localhost",
			want:     true,
		},
		{
			name:     "localhost uppercase",
			hostname: "LOCALHOST",
			want:     true,
		},
		{
			name:     "localhost with whitespace",
			hostname: "  localhost  ",
			want:     true,
		},
		{
			name:     "127.0.0.1",
			hostname: "127.0.0.1",
			want:     true,
		},
		{
			name:     "IPv6 localhost",
			hostname: "::1",
			want:     true,
		},
		{
			name:     "IPv6 localhost with brackets",
			hostname: "[::1]",
			want:     true,
		},
		{
			name:     "production domain",
			hostname: "example.com",
			want:     false,
		},
		{
			name:     "dev subdomain",
			hostname: "dev.example.com",
			want:     false,
		},
		{
			name:     "localhost subdomain (not localhost)",
			hostname: "localhost.example.com",
			want:     false,
		},
		{
			name:     "127 subnet (not localhost)",
			hostname: "127.0.0.2",
			want:     false,
		},
		{
			name:     "empty string",
			hostname: "",
			want:     false,
		},
		{
			name:     "whitespace only",
			hostname: "   ",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsLocalhost(tt.hostname)
			if got != tt.want {
				t.Errorf("IsLocalhost(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}
