package httpx

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// RequireReferrerHost middleware validates the Referer header against allowed hosts
func RequireReferrerHost(cfg config.Config, allow *security.HostAllowlist) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			referer := r.Header.Get("Referer")

			// Allow empty referer (some clients strip it)
			if referer == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Parse the referer URL
			refURL, err := url.Parse(referer)
			if err != nil {
				writeReferrerError(w)
				return
			}

			// Ensure HTTPS scheme
			if refURL.Scheme != "https" {
				writeReferrerError(w)
				return
			}

			// Check if host is allowed
			if !allow.IsAllowed(refURL.Host) {
				writeReferrerError(w)
				return
			}

			// Referer is valid, continue to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// writeReferrerError writes a 400 JSON error response
func writeReferrerError(w http.ResponseWriter) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusBadRequest)

	response := map[string]string{
		"error": "invalid_referrer",
	}

	json.NewEncoder(w).Encode(response)
}
