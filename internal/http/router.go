package httpx

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

// Context key for storing config in request context
type contextKey string

const ConfigContextKey contextKey = "config"

// NewRouter creates and configures a new HTTP router with the given config
func NewRouter(cfg config.Config) http.Handler {
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
