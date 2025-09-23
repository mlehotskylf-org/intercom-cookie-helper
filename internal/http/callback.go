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

	// Step 6: Perform token exchange with Auth0
	tokenResp, err := auth.ExchangeCode(
		r.Context(),
		cfg.Auth0Domain,
		cfg.Auth0ClientID,
		cfg.Auth0ClientSecret, // dev only - in production, use client authentication
		redirectURI,
		code,
		txn.CV, // code_verifier for PKCE
	)
	if err != nil {
		log.Printf("Token exchange failed: %v", err)
		writeCallbackError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}

	// Step 7: Extract tokens (do not log them)
	accessToken := tokenResp.AccessToken
	idToken := tokenResp.IDToken

	// Verify we have the required tokens
	if accessToken == "" {
		log.Printf("Token exchange succeeded but access_token is missing")
		writeCallbackError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}

	log.Printf("Token exchange successful - has_access_token: true, has_id_token: %v", idToken != "")

	// Step 8: Verify nonce in ID token if present (extra CSRF replay defense)
	if idToken != "" {
		idTokenNonce, err := auth.ExtractNonceFromIDToken(idToken)
		if err != nil {
			log.Printf("Failed to extract nonce from ID token: %v", err)
			// Require valid nonce extraction as security policy
			writeCallbackError(w, http.StatusBadRequest, "invalid_request", "")
			return
		}

		// Perform constant-time comparison of nonces
		if idTokenNonce != "" && txn.Nonce != "" {
			if subtle.ConstantTimeCompare([]byte(idTokenNonce), []byte(txn.Nonce)) != 1 {
				log.Printf("Nonce mismatch - expected: %s, got: %s", txn.Nonce, idTokenNonce)
				writeCallbackError(w, http.StatusBadRequest, "invalid_request", "")
				return
			}
			log.Printf("Nonce verification successful")
		} else if idTokenNonce != "" || txn.Nonce != "" {
			// One nonce is present but not the other - this is a mismatch
			log.Printf("Nonce presence mismatch - txn_nonce_present: %v, id_token_nonce_present: %v",
				txn.Nonce != "", idTokenNonce != "")
			writeCallbackError(w, http.StatusBadRequest, "invalid_request", "")
			return
		}
	}

	// TODO: Process tokens and complete authentication flow
	// For now, return success indication
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "token_exchange_complete",
		"message": "Successfully exchanged authorization code for tokens",
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