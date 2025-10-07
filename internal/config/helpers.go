package config

import "strings"

// IsLocalhost returns true if the hostname is a local development address.
// This includes localhost, 127.0.0.1, and IPv6 localhost (::1).
func IsLocalhost(hostname string) bool {
	// Normalize to lowercase for comparison
	h := strings.ToLower(strings.TrimSpace(hostname))

	return h == "localhost" ||
		h == "127.0.0.1" ||
		h == "::1" ||
		h == "[::1]" // IPv6 with brackets
}
