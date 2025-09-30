package httpx

import (
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// RequireReferrerHost middleware validates the Referer header against allowed hosts.
// Enforces strict validation in production while allowing flexibility in development.
func RequireReferrerHost(cfg config.Config, allow *security.HostAllowlist) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			referer := r.Header.Get("Referer")

			// Handle empty referer
			if referer == "" {
				// Allow empty referer in all environments because:
				// 1. return_to validation provides strong security (HTTPS, allowlist, port checks)
				// 2. Modern browsers/widgets strip Referer for privacy (Referrer-Policy)
				// 3. Blocking breaks legitimate users (Intercom widgets, browser extensions)
				// 4. CSRF protection comes from SameSite cookies, not Referer validation
				log.Printf("event=ref_check ok=true referer_host=empty path=%s env=%s", r.URL.Path, cfg.Env)
				next.ServeHTTP(w, r)
				return
			}

			// Parse the referer URL
			refURL, err := url.Parse(referer)
			if err != nil {
				metrics.LoginBadReferer.Add(1)
				log.Printf("event=ref_check ok=false reason=parse_error referer=%s path=%s", referer, r.URL.Path)
				BadRequest(w, r, "Invalid Referer URL format")
				return
			}

			// Require HTTPS scheme
			if refURL.Scheme != "https" {
				metrics.LoginBadReferer.Add(1)
				log.Printf("event=ref_check ok=false reason=invalid_scheme scheme=%s referer_host=%s path=%s",
					refURL.Scheme, refURL.Host, r.URL.Path)
				BadRequest(w, r, "Referer must use HTTPS")
				return
			}

			// Deny IP address literals (only allow domain names)
			host := refURL.Host
			// Strip port if present
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if net.ParseIP(host) != nil {
				metrics.LoginBadReferer.Add(1)
				log.Printf("event=ref_check ok=false reason=ip_literal referer_host=%s path=%s", refURL.Host, r.URL.Path)
				BadRequest(w, r, "Referer cannot be an IP address")
				return
			}

			// Check if host is in allowlist
			if !allow.IsAllowed(refURL.Host) {
				metrics.LoginBadReferer.Add(1)
				log.Printf("event=ref_check ok=false reason=not_allowed referer_host=%s path=%s", refURL.Host, r.URL.Path)
				BadRequest(w, r, "Referer host not in allowlist")
				return
			}

			// Referer is valid
			log.Printf("event=ref_check ok=true referer_host=%s path=%s", refURL.Host, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}
