package httpx

import (
	"net/http"
	"sync/atomic"
)

// Metrics holds atomic counters for monitoring authentication flow.
// These are lightweight in-memory counters that provide visibility without heavy dependencies.
type Metrics struct {
	// Login flow counters
	LoginStart       atomic.Uint64 // Login endpoint invoked
	LoginBadReferer  atomic.Uint64 // Referer validation failed
	LoginBadReturn   atomic.Uint64 // return_to validation failed
	LoginCookieFail  atomic.Uint64 // Cookie setting failed
	LoginOK          atomic.Uint64 // Login redirect to Auth0 successful

	// Callback flow counters
	CbStart          atomic.Uint64 // Callback endpoint invoked
	CbStateMismatch  atomic.Uint64 // State parameter validation failed
	CbExchangeFail   atomic.Uint64 // Token exchange with Auth0 failed
	CbNonceFail      atomic.Uint64 // Nonce verification failed
	CbUserinfoFail   atomic.Uint64 // User info extraction failed
	CbCookieFail     atomic.Uint64 // Cookie read/clear failed
	CbOK             atomic.Uint64 // Callback successful, user identified
}

// Global metrics instance
var metrics = &Metrics{}

// MetricsSnapshot represents a point-in-time view of all metrics.
type MetricsSnapshot struct {
	Login    LoginMetrics    `json:"login"`
	Callback CallbackMetrics `json:"callback"`
}

// LoginMetrics groups login-related counters.
type LoginMetrics struct {
	Start      uint64 `json:"start"`
	BadReferer uint64 `json:"bad_referer"`
	BadReturn  uint64 `json:"bad_return"`
	CookieFail uint64 `json:"cookie_fail"`
	OK         uint64 `json:"ok"`
}

// CallbackMetrics groups callback-related counters.
type CallbackMetrics struct {
	Start         uint64 `json:"start"`
	StateMismatch uint64 `json:"state_mismatch"`
	ExchangeFail  uint64 `json:"exchange_fail"`
	NonceFail     uint64 `json:"nonce_fail"`
	UserinfoFail  uint64 `json:"userinfo_fail"`
	CookieFail    uint64 `json:"cookie_fail"`
	OK            uint64 `json:"ok"`
}

// Snapshot returns a consistent view of all metrics at this moment.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		Login: LoginMetrics{
			Start:      m.LoginStart.Load(),
			BadReferer: m.LoginBadReferer.Load(),
			BadReturn:  m.LoginBadReturn.Load(),
			CookieFail: m.LoginCookieFail.Load(),
			OK:         m.LoginOK.Load(),
		},
		Callback: CallbackMetrics{
			Start:         m.CbStart.Load(),
			StateMismatch: m.CbStateMismatch.Load(),
			ExchangeFail:  m.CbExchangeFail.Load(),
			NonceFail:     m.CbNonceFail.Load(),
			UserinfoFail:  m.CbUserinfoFail.Load(),
			CookieFail:    m.CbCookieFail.Load(),
			OK:            m.CbOK.Load(),
		},
	}
}

// metricsHandler serves metrics in JSON format (dev/staging only).
// Returns current counter values for monitoring authentication flow health.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	// Get config from context to check environment
	cfg, ok := GetConfigFromContext(r.Context())
	if !ok {
		http.Error(w, "configuration not available", http.StatusInternalServerError)
		return
	}

	// Only allow in non-production environments
	if cfg.Env == "prod" {
		http.NotFound(w, r)
		return
	}

	snapshot := metrics.Snapshot()
	writeJSON(w, http.StatusOK, snapshot)
}