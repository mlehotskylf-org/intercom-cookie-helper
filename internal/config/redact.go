package config

import (
	"fmt"
)

// Redacted returns a map suitable for logging/json with secrets replaced by "***"
func (c Config) Redacted() map[string]any {
	redacted := make(map[string]any)

	// Non-sensitive fields
	redacted["env"] = c.Env
	redacted["app_hostname"] = c.AppHostname
	redacted["port"] = c.Port
	redacted["cookie_domain"] = c.CookieDomain
	redacted["allowed_return_hosts"] = c.AllowedReturnHosts
	redacted["allowed_query_params"] = c.AllowedQueryParams
	redacted["intercom_app_id"] = c.IntercomAppID
	redacted["auth0_domain"] = c.Auth0Domain
	redacted["auth0_client_id"] = c.Auth0ClientID
	redacted["auth0_redirect_path"] = c.Auth0RedirectPath
	redacted["redirect_ttl"] = c.RedirectTTL.String()
	redacted["session_ttl"] = c.SessionTTL.String()
	redacted["log_level"] = c.LogLevel
	redacted["enable_hsts"] = c.EnableHSTS

	// Redact sensitive fields
	if c.IntercomJWTSecret != "" {
		redacted["intercom_jwt_secret"] = "***"
	}
	if c.Auth0ClientSecret != "" {
		redacted["auth0_client_secret"] = "***"
	}
	if len(c.CookieSigningKey) > 0 {
		redacted["cookie_signing_key"] = fmt.Sprintf("*** (%d bytes)", len(c.CookieSigningKey))
	}

	// Include processed hosts info for debugging
	if len(c.AllowedReturnHostsPreprocessed) > 0 {
		processed := make([]map[string]any, len(c.AllowedReturnHostsPreprocessed))
		for i, host := range c.AllowedReturnHostsPreprocessed {
			processed[i] = map[string]any{
				"original":    host.Original,
				"canonical":   host.Canonical,
				"is_wildcard": host.IsWildcard,
			}
		}
		redacted["allowed_return_hosts_processed"] = processed
	}

	return redacted
}
