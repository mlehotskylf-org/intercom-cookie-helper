package security

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type Sanitizer struct {
	Allow        *HostAllowlist
	AllowedQuery map[string]struct{}
}

func NewSanitizer(allow *HostAllowlist, allowedQuery []string) *Sanitizer {
	allowedMap := make(map[string]struct{})
	for _, key := range allowedQuery {
		allowedMap[key] = struct{}{}
	}

	return &Sanitizer{
		Allow:        allow,
		AllowedQuery: allowedMap,
	}
}

func (s *Sanitizer) SanitizeReturnURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty URL")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Require absolute HTTPS
	if u.Scheme != "https" {
		return "", fmt.Errorf("URL must use HTTPS scheme, got %q", u.Scheme)
	}

	// Extract hostname and port using URL's built-in methods (handles IPv6 correctly)
	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	port := u.Port()

	// Only allow default HTTPS port (443) or no port
	if port != "" && port != "443" {
		return "", fmt.Errorf("URL must use default HTTPS port (443), got port %q", port)
	}

	// Normalize the hostname by removing trailing dots
	hostname = strings.TrimRight(hostname, ".")

	// Set the final host (without port since we only allow 443)
	host := hostname

	// Check if hostname is allowed
	if !s.Allow.IsAllowed(hostname) {
		return "", fmt.Errorf("host %q is not allowed", hostname)
	}

	// Set normalized host
	u.Host = host

	// Ensure path defaults to / if empty
	if u.Path == "" {
		u.Path = "/"
	}

	// Strip fragment
	u.Fragment = ""

	// Filter and rebuild query parameters
	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return "", fmt.Errorf("invalid query string: %w", err)
		}

		filtered := url.Values{}

		// Collect allowed keys in sorted order for deterministic output
		var allowedKeys []string
		for key := range values {
			if _, allowed := s.AllowedQuery[key]; allowed {
				allowedKeys = append(allowedKeys, key)
			}
		}
		sort.Strings(allowedKeys)

		// Add filtered parameters in sorted order
		for _, key := range allowedKeys {
			filtered[key] = values[key]
		}

		u.RawQuery = filtered.Encode()
	}

	return u.String(), nil
}