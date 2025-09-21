package security

import (
	"fmt"
	"net"
	"strings"
)

type HostAllowlist struct {
	raw   []string
	exact map[string]struct{}
	wild  map[string]struct{}
}

func NewHostAllowlist(hosts []string) (*HostAllowlist, error) {
	h := &HostAllowlist{
		raw:   make([]string, len(hosts)),
		exact: make(map[string]struct{}),
		wild:  make(map[string]struct{}),
	}

	for i, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}

		if err := validateHost(host); err != nil {
			return nil, fmt.Errorf("invalid host %q: %w", host, err)
		}

		h.raw[i] = host
		host = strings.ToLower(host)

		if strings.HasPrefix(host, "*.") {
			base := host[2:]
			if base == "" {
				return nil, fmt.Errorf("invalid wildcard host %q: empty base", host)
			}
			h.wild[base] = struct{}{}
		} else {
			h.exact[host] = struct{}{}
		}
	}

	return h, nil
}

func (h *HostAllowlist) IsAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")

	if host == "" {
		return false
	}

	if isIPAddress(host) {
		return false
	}

	if _, ok := h.exact[host]; ok {
		return true
	}

	for base := range h.wild {
		if host == base || strings.HasSuffix(host, "."+base) {
			return true
		}
	}

	return false
}

func validateHost(host string) error {
	if strings.Contains(host, "://") {
		return fmt.Errorf("must not contain scheme")
	}

	if strings.Contains(host, " ") || strings.Contains(host, "\t") || strings.Contains(host, "\n") {
		return fmt.Errorf("must not contain whitespace")
	}

	cleaned := host
	if strings.HasPrefix(host, "*.") {
		cleaned = host[2:]
	}

	if strings.Contains(cleaned, ":") {
		return fmt.Errorf("must not contain port")
	}

	return nil
}

func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}