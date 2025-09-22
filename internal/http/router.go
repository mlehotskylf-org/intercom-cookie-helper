package httpx

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// Context key for storing config in request context
type contextKey string

const ConfigContextKey contextKey = "config"

// NewRouter creates and configures a new HTTP router with the given config
func NewRouter(cfg config.Config) http.Handler {
	// Build sanitizer at router init - config has been validated earlier
	sanitizer, err := cfg.BuildSanitizer()
	if err != nil {
		log.Fatalf("Failed to build sanitizer: %v", err)
	}

	r := chi.NewRouter()

	// Add middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Add config to request context
	r.Use(configMiddleware(cfg))

	// Add HSTS header if enabled
	if cfg.EnableHSTS {
		r.Use(hstsMiddleware)
	}

	// Routes
	r.Get("/healthz", healthzHandler)

	// Login endpoint with referrer validation
	r.With(RequireReferrerHost(cfg, sanitizer.Allow)).Get("/login", loginHandler(sanitizer))

	// Debug endpoint (only in non-prod environments)
	if cfg.Env != "prod" {
		r.Get("/debug/redirect-cookie", debugRedirectCookieHandler)
	}

	return r
}

// configMiddleware adds the config to the request context
func configMiddleware(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ConfigContextKey, cfg)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// hstsMiddleware adds the Strict-Transport-Security header
func hstsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// GetConfigFromContext retrieves the config from the request context
func GetConfigFromContext(ctx context.Context) (config.Config, bool) {
	cfg, ok := ctx.Value(ConfigContextKey).(config.Config)
	return cfg, ok
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// loginHandler creates a login handler with access to the sanitizer
func loginHandler(sanitizer *security.Sanitizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Get config from context
		cfg, ok := GetConfigFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "internal_error",
				"message": "configuration not available",
			})
			return
		}

		returnTo := r.URL.Query().Get("return_to")
		if returnTo == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "missing_return_to",
			})
			return
		}

		sanitizedURL, err := sanitizer.SanitizeReturnURL(returnTo)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid_return_url",
				"message": err.Error(),
			})
			return
		}

		// Extract referrer host for cookie payload
		referrerHost := ""
		if referer := r.Header.Get("Referer"); referer != "" {
			if refURL, err := url.Parse(referer); err == nil {
				referrerHost = strings.ToLower(refURL.Host)
			}
		}

		// Set redirect cookie using config options
		_, err = security.SetSignedRedirectCookie(w, sanitizedURL, referrerHost, cfg.CookieSigningKey, cfg.RedirectCookieOpts(), time.Now())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "cookie_error",
				"message": err.Error(),
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":        true,
			"sanitized": sanitizedURL,
		})
	}
}

// debugRedirectCookieHandler handles debugging of redirect cookies (non-prod only)
func debugRedirectCookieHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get config from context
	cfg, ok := GetConfigFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "configuration not available",
		})
		return
	}

	// Additional check for production environment (defense in depth)
	if cfg.Env == "prod" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Prepare keys for reading the cookie
	primaryKey := cfg.CookieSigningKey
	var secondaryKey []byte
	if len(cfg.SecondaryCookieSigningKey) > 0 {
		secondaryKey = cfg.SecondaryCookieSigningKey
	}

	// Read and validate the redirect cookie
	redirectURL, err := security.ReadSignedRedirectCookie(r, primaryKey, secondaryKey, time.Now(), cfg.RedirectSkew)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Return successful result
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"url":   redirectURL,
		"valid": true,
	})
}
