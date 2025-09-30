// Package httpx provides HTTP handlers and middleware for the authentication flow.
// This package handles the web server routing and OAuth2/OIDC callback processing.
package httpx

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/auth"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// ErrorContext holds data for rendering the error template.
type ErrorContext struct {
	ErrorMessage string // Human-readable error message
	TryAgainURL  string // URL for retry button
}

// handleCallback processes the OAuth2 callback from Auth0 after user authentication.
// It validates the transaction cookie, verifies the state parameter, exchanges the
// authorization code for tokens using PKCE, and validates the nonce in the ID token.
// This is the critical security checkpoint in the OAuth2 flow.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	metrics.CbStart.Add(1)

	// Get config from context
	cfg, ok := GetConfigFromContext(r.Context())
	if !ok {
		renderErrorPage(w, r, ErrorMsgConfigUnavailable, cfg)
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
		errorMessage := "Authentication was cancelled or failed."
		if errorDesc != "" {
			errorMessage = errorDesc
		}
		renderErrorPage(w, r, errorMessage, cfg)
		return
	}

	// Check for required parameters
	if code == "" || state == "" {
		log.Printf("Callback invalid - missing required parameters (code_present: %v, state_present: %v)",
			code != "", state != "")
		renderErrorPage(w, r, ErrorMsgMissingParams, cfg)
		return
	}

	// Log with redacted state value for security
	log.Printf("Callback success - state: [REDACTED], code_present: true")

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
		renderErrorPage(w, r, ErrorMsgSessionExpired, cfg)
		return
	}

	// Step 3: Validate state parameter (constant-time comparison)
	if subtle.ConstantTimeCompare([]byte(state), []byte(txn.State)) != 1 {
		metrics.CbStateMismatch.Add(1)
		log.Printf("State mismatch detected")
		renderErrorPage(w, r, ErrorMsgSecurityValidation, cfg)
		return
	}

	// Step 4: Build redirect URI (must match exactly what was used in /login)
	// Guard against misconfiguration
	if !strings.HasPrefix(cfg.Auth0RedirectPath, "/") {
		log.Printf("Configuration error: Auth0RedirectPath must start with '/', got: %s", cfg.Auth0RedirectPath)
		renderErrorPage(w, r, ErrorMsgServerConfig, cfg)
		return
	}

	// Use HTTP for local development, HTTPS for production
	var redirectURI string
	if cfg.Env == "dev" && cfg.AppHostname == "localhost" {
		// For local development, use HTTP and include the port
		redirectURI = "http://" + cfg.AppHostname + ":" + cfg.Port + cfg.Auth0RedirectPath
	} else {
		// For production, use HTTPS without port
		redirectURI = "https://" + cfg.AppHostname + cfg.Auth0RedirectPath
	}

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
		metrics.CbExchangeFail.Add(1)
		log.Printf("Token exchange failed: %v", err)
		renderErrorPage(w, r, ErrorMsgAuthFailed, cfg)
		return
	}

	// Step 7: Extract tokens (do not log them)
	accessToken := tokenResp.AccessToken
	idToken := tokenResp.IDToken

	// Verify we have the required tokens
	if accessToken == "" {
		log.Printf("Token exchange succeeded but access_token is missing")
		renderErrorPage(w, r, "Authentication incomplete. Please try again.", cfg)
		return
	}

	log.Printf("Token exchange successful - has_access_token: true, has_id_token: %v", idToken != "")

	// Step 8: Verify nonce in ID token if present (extra CSRF replay defense)
	if idToken != "" {
		idTokenNonce, err := auth.ExtractNonceFromIDToken(idToken)
		if err != nil {
			metrics.CbNonceFail.Add(1)
			log.Printf("Failed to extract nonce from ID token: %v", err)
			// Require valid nonce extraction as security policy
			renderErrorPage(w, r, ErrorMsgTokenValidation, cfg)
			return
		}

		// Perform constant-time comparison of nonces
		if idTokenNonce != "" && txn.Nonce != "" {
			if subtle.ConstantTimeCompare([]byte(idTokenNonce), []byte(txn.Nonce)) != 1 {
				metrics.CbNonceFail.Add(1)
				log.Printf("Nonce mismatch detected")
				renderErrorPage(w, r, ErrorMsgSecurityValidation, cfg)
				return
			}
			log.Printf("Nonce verification successful")
		} else if idTokenNonce != "" || txn.Nonce != "" {
			// One nonce is present but not the other - this is a mismatch
			metrics.CbNonceFail.Add(1)
			log.Printf("Nonce presence mismatch - txn_nonce_present: %v, id_token_nonce_present: %v",
				txn.Nonce != "", idTokenNonce != "")
			renderErrorPage(w, r, ErrorMsgSecurityValidation, cfg)
			return
		}
	}

	// Step 9: Parse user information from ID token
	userInfo, err := auth.ParseUserInfoFromIDToken(idToken)
	if err != nil {
		metrics.CbUserinfoFail.Add(1)
		log.Printf("Failed to parse user info from ID token: %v", err)
		renderErrorPage(w, r, ErrorMsgTokenValidation, cfg)
		return
	}

	// Validate that we have a subject identifier
	if userInfo.Sub == "" {
		log.Printf("User info missing required subject identifier")
		renderErrorPage(w, r, ErrorMsgUserInfoIncomplete, cfg)
		return
	}

	log.Printf("User info parsed from ID token - sub: %s, email_present: %v, name_present: %v",
		userInfo.Sub, userInfo.Email != "", userInfo.Name != "")

	// Step 10: Read and validate redirect cookie to get return URL
	var returnTo string
	redirectURL, err := security.ReadSignedRedirectCookie(
		r,
		cfg.CookieSigningKey,
		cfg.SecondaryCookieSigningKey,
		time.Now(),
		cfg.RedirectSkew,
	)
	if err != nil {
		// Fallback to safe default on error
		returnTo = "https://" + cfg.AppHostname + "/"
		log.Printf("Failed to read redirect cookie, using fallback URL - reason: %v", err)
	} else {
		returnTo = redirectURL
		log.Printf("Redirect cookie read successfully - return_to: %s", returnTo)
	}

	// Step 11: Clear the redirect cookie (always, even if read failed)
	security.ClearRedirectCookie(w, cfg.CookieDomain)
	log.Printf("Redirect cookie cleared")

	// Step 12: Clear transaction cookie to prevent replay attacks
	auth.ClearTxnCookie(w, txnOpts)
	log.Printf("Transaction cookie cleared")

	// Step 13: Render Intercom identify page with JWT
	// Build the identify payload with user information
	payload := auth.IdentifyPayload{
		ReturnTo: returnTo,
		Subject:  userInfo.Sub,
		Email:    userInfo.Email,
		Name:     userInfo.Name,
	}

	// Create the Intercom renderer from config and render the response
	renderer := cfg.IntercomRenderer()
	if err := renderer.Render(w, payload); err != nil {
		log.Printf("Failed to render Intercom identify page: %v", err)
		renderErrorPage(w, r, "Failed to complete authentication", cfg)
		return
	}

	// Extract return host for logging (redact full URL for privacy)
	returnHost := ""
	if returnTo != "" {
		if parsedURL, err := url.Parse(returnTo); err == nil {
			returnHost = parsedURL.Host
		}
	}

	// Log successful render with safe observability (no PII, no tokens/JWT)
	metrics.CbOK.Add(1)
	log.Printf("Identify rendered - subject: %s, has_email: %v, return_host: %s",
		userInfo.Sub, userInfo.Email != "", returnHost)
}

// writeCallbackError writes a standardized JSON error response for callback failures.
// It ensures consistent error formatting and prevents information leakage.
func writeCallbackError(w http.ResponseWriter, statusCode int, errorCode, errorMessage string) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(statusCode)

	response := map[string]string{"error": errorCode}
	if errorMessage != "" {
		response["error_description"] = errorMessage
	}

	json.NewEncoder(w).Encode(response)
}

// renderErrorPage renders a user-friendly HTML error page for authentication failures.
// It provides a link back to the return URL (original destination).
func renderErrorPage(w http.ResponseWriter, r *http.Request, errorMessage string, cfg config.Config) {
	// Build a safe default return URL
	var defaultReturnURL string
	if cfg.Env == "dev" && cfg.AppHostname == "localhost" {
		defaultReturnURL = fmt.Sprintf("http://%s:%s/", cfg.AppHostname, cfg.Port)
	} else {
		defaultReturnURL = fmt.Sprintf("https://%s/", cfg.AppHostname)
	}

	// Use the return URL directly (don't go back through login flow)
	backURL := defaultReturnURL

	// Create error context
	errorCtx := ErrorContext{
		ErrorMessage: errorMessage,
		TryAgainURL:  backURL,
	}

	// Render the embedded error template
	w.Header().Set(HeaderContentType, ContentTypeHTML)
	w.WriteHeader(http.StatusBadRequest)
	if err := ErrorTmpl.Execute(w, errorCtx); err != nil {
		log.Printf("Failed to execute error template: %v", err)
		// Don't write another response since headers may have been sent
	}
}
