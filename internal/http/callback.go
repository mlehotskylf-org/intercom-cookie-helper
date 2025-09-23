// Package httpx provides HTTP handlers and middleware
package httpx

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/auth"
)

// handleCallback processes the OAuth2 callback from Auth0
func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get config from context
	cfg, ok := GetConfigFromContext(r.Context())
	if !ok {
		writeCallbackError(w, http.StatusInternalServerError, "internal_error", "Configuration not available")
		return
	}

	// Step 1: Read query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")
	errorDesc := r.URL.Query().Get("error_description")

	// Log callback parameters (without sensitive code value)
	if errorParam != "" {
		log.Printf("Callback error - error: %s, description: %s", errorParam, errorDesc)
		writeCallbackError(w, http.StatusBadRequest, errorParam, errorDesc)
		return
	}

	// Check for required parameters
	if code == "" || state == "" {
		log.Printf("Callback invalid - missing required parameters (code_present: %v, state_present: %v)",
			code != "", state != "")
		writeCallbackError(w, http.StatusBadRequest, "invalid_request", "Missing required parameters")
		return
	}

	log.Printf("Callback success - state: %s, code_present: true", state)

	// Step 2: Read and validate transaction cookie
	txnOpts := auth.TxnOpts{
		Domain:       cfg.CookieDomain,
		TTL:          cfg.TxnTTL,
		Skew:         cfg.TxnSkew,
		Secure:       cfg.Env == "prod",
		SigningKey:   cfg.CookieSigningKey,
		SecondaryKey: cfg.SecondaryCookieSigningKey,
	}

	txn, err := auth.ReadTxnCookie(r, txnOpts)
	if err != nil {
		log.Printf("Failed to read transaction cookie: %v", err)
		writeCallbackError(w, http.StatusBadRequest, "invalid_request", "Invalid or expired transaction")
		return
	}

	// Step 3: Validate state parameter (constant-time comparison)
	if subtle.ConstantTimeCompare([]byte(state), []byte(txn.State)) != 1 {
		log.Printf("State mismatch - expected: %s, got: %s", txn.State, state)
		writeCallbackError(w, http.StatusBadRequest, "invalid_request", "State parameter mismatch")
		return
	}

	// Step 4: Build redirect URI (must match exactly what was used in /login)
	// Guard against misconfiguration
	if !strings.HasPrefix(cfg.Auth0RedirectPath, "/") {
		log.Printf("Configuration error: Auth0RedirectPath must start with '/', got: %s", cfg.Auth0RedirectPath)
		writeCallbackError(w, http.StatusInternalServerError, "internal_error", "Server misconfiguration")
		return
	}

	redirectURI := "https://" + cfg.AppHostname + cfg.Auth0RedirectPath

	// Step 5: Keep code_verifier and nonce for later use
	// txn.CV (code_verifier) and txn.Nonce will be used for token exchange
	// Do not clear transaction cookie yet - will clear after successful token exchange

	log.Printf("Transaction validated - code_verifier_present: %v, nonce_present: %v, redirect_uri: %s",
		txn.CV != "", txn.Nonce != "", redirectURI)

	// TODO: Implement token exchange and further processing
	// For now, return 501 Not Implemented
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{
		"error": "not_implemented",
		"message": "Token exchange not yet implemented",
		"debug": "Transaction validated successfully",
	})
}

// writeCallbackError writes a JSON error response for callback errors
func writeCallbackError(w http.ResponseWriter, statusCode int, errorCode, errorMessage string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]string{"error": errorCode}
	if errorMessage != "" {
		response["error_description"] = errorMessage
	}

	json.NewEncoder(w).Encode(response)
}