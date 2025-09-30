// Package httpx provides HTTP handlers, middleware, and routing for the OAuth2/OIDC flow.
// This package serves as the HTTP layer orchestrating authentication between Intercom and Auth0.
package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/auth"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// Context key for storing config in request context
type contextKey string

const ConfigContextKey contextKey = "config"

// NewRouter creates and configures a new HTTP router with all application endpoints.
// Sets up middleware for logging, recovery, HSTS, and request context enrichment.
// Routes are configured with appropriate security middleware where needed.
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
	r.With(RequireReferrerHost(cfg, sanitizer.Allow)).Get(RouteLogin, loginHandler(sanitizer))

	// Callback endpoint - OAuth2 callback handler with Intercom security headers
	r.With(intercomSecurityHeadersMiddleware).Get(RouteCallback, handleCallback)

	// Debug endpoint (only in non-prod environments)
	if cfg.Env != "prod" {
		r.Get("/debug/redirect-cookie", debugRedirectCookieHandler)
	}

	return r
}

// configMiddleware adds the config to the request context.
// This allows handlers to access configuration without global state.
func configMiddleware(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ConfigContextKey, cfg)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// hstsMiddleware adds the Strict-Transport-Security header.
// Forces HTTPS for one year with subdomains included for security.
// TODO(DevOps): Move to API Gateway/Load Balancer for centralized security policy
func hstsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// intercomSecurityHeadersMiddleware adds security headers for the Intercom identify page.
// Includes CSP to allow Intercom assets while maintaining tight security policy.
func intercomSecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Content Security Policy - Allow Intercom assets
		// NOTE: This is route-specific CSP for /callback (Intercom identify page)
		// Keep this in application as it requires knowledge of Intercom dependencies
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' https://widget.intercom.io https://js.intercomcdn.com; " +
			"connect-src 'self' https://*.intercom.io https://api-iam.intercom.io wss://*.intercom.io; " +
			"img-src 'self' data: https://*.intercomcdn.com; " +
			"style-src 'self' 'unsafe-inline'; " +
			"frame-ancestors 'none'"
		w.Header().Set("Content-Security-Policy", csp)

		// TODO(DevOps): Move these generic headers to API Gateway/Load Balancer
		// They should apply to all routes, not just /callback
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		next.ServeHTTP(w, r)
	})
}

// GetConfigFromContext retrieves the config from the request context.
// Returns false if config is not found in context.
func GetConfigFromContext(ctx context.Context) (config.Config, bool) {
	cfg, ok := ctx.Value(ConfigContextKey).(config.Config)
	return cfg, ok
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// loginHandler creates a login handler that redirects to Auth0 for authentication.
// Sets redirect and transaction cookies before initiating OAuth2 flow with PKCE.
// Validates return_to URL and referrer before processing.
func loginHandler(sanitizer *security.Sanitizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get config from context
		cfg, ok := GetConfigFromContext(r.Context())
		if !ok {
			WriteJSONError(w, http.StatusInternalServerError, ErrCodeInternalError, "Configuration not available")
			return
		}

		// Step 1: Read and sanitize return_to
		returnTo := r.URL.Query().Get("return_to")
		if returnTo == "" {
			WriteJSONError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Missing return_to parameter")
			return
		}

		sanitizedURL, err := sanitizer.SanitizeReturnURL(returnTo)
		if err != nil {
			WriteJSONError(w, http.StatusBadRequest, ErrCodeInvalidReturnURL, err.Error())
			return
		}

		// Extract referrer host for cookie payload
		referrerHost := ""
		if referer := r.Header.Get(HeaderReferer); referer != "" {
			if refURL, err := url.Parse(referer); err == nil {
				referrerHost = strings.ToLower(refURL.Host)
			}
		}

		// Step 2: Set redirect cookie
		_, err = security.SetSignedRedirectCookie(w, sanitizedURL, referrerHost, cfg.CookieSigningKey, cfg.RedirectCookieOpts(), time.Now())
		if err != nil {
			WriteJSONError(w, http.StatusBadRequest, ErrCodeCookieError, fmt.Sprintf("Failed to set redirect cookie: %v", err))
			return
		}

		// Step 3: Set transaction cookie with PKCE parameters
		state, codeChallenge, nonce, err := auth.SetTxnCookie(w, cfg.TxnCookieOpts())
		if err != nil {
			WriteJSONError(w, http.StatusInternalServerError, ErrCodeCookieError, fmt.Sprintf("Failed to set transaction cookie: %v", err))
			return
		}

		// Step 4: Build redirect URI
		// Use HTTP for local development, HTTPS for production
		var redirectURI string
		if cfg.Env == "dev" && cfg.AppHostname == "localhost" {
			redirectURI = fmt.Sprintf("http://%s:%s%s", cfg.AppHostname, cfg.Port, cfg.Auth0RedirectPath)
		} else {
			redirectURI = fmt.Sprintf("https://%s%s", cfg.AppHostname, cfg.Auth0RedirectPath)
		}

		// Step 5: Build Auth0 authorize URL
		authorizeURL, err := auth.BuildAuthorizeURL(auth.AuthorizeParams{
			Domain:              cfg.Auth0Domain,
			ClientID:            cfg.Auth0ClientID,
			RedirectURI:         redirectURI,
			Scope:               "openid profile email",
			State:               state,
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: "S256",
		})
		if err != nil {
			WriteJSONError(w, http.StatusInternalServerError, ErrCodeInternalError, fmt.Sprintf("Failed to build authorization URL: %v", err))
			return
		}

		// Log the login event (without secrets)
		log.Printf("Login initiated - return_to: %s, referrer_host: %s, auth0_domain: %s",
			sanitizedURL, referrerHost, cfg.Auth0Domain)

		// Step 6: Redirect to Auth0
		http.Redirect(w, r, authorizeURL, http.StatusFound)
	}
}

// debugRedirectCookieHandler handles debugging of redirect cookies (non-prod only).
// Reads and validates the signed redirect cookie, returning its contents.
// This endpoint is disabled in production environments for security.
func debugRedirectCookieHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)

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
