// Package auth provides OAuth2/OIDC authentication utilities for Auth0 integration.
// This file handles the critical token exchange step where authorization codes are
// swapped for access tokens and ID tokens using PKCE for enhanced security.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenResponse represents the OAuth2 token response from Auth0.
// Contains the access token for API calls and optionally an ID token with user claims.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token,omitempty"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// TokenError represents an OAuth2 error response from the token endpoint.
// Used to parse error details when token exchange fails.
type TokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ExchangeCode exchanges an authorization code for tokens using PKCE.
// This is the critical OAuth2 step where the temporary code is swapped for actual tokens.
// PKCE (code_verifier) prevents authorization code interception attacks.
// The redirect_uri must match exactly what was used in the initial /login request.
func ExchangeCode(ctx context.Context, domain, clientID, clientSecret, redirectURI, code, codeVerifier string) (*TokenResponse, error) {
	// Build token endpoint URL - preserve protocol if already specified
	var tokenURL string
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		tokenURL = fmt.Sprintf("%s/oauth/token", strings.TrimSuffix(domain, "/"))
	} else {
		tokenURL = fmt.Sprintf("https://%s/oauth/token", domain)
	}

	// Build form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("code", code)
	data.Set("code_verifier", codeVerifier)
	data.Set("redirect_uri", redirectURI)

	// Only include client_secret if provided (for confidential clients in dev)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var tokenErr TokenError
		if err := json.Unmarshal(body, &tokenErr); err != nil {
			return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
		}

		// Return friendly error without exposing sensitive details
		if tokenErr.ErrorDescription != "" {
			return nil, fmt.Errorf("token exchange failed: %s", tokenErr.Error)
		}
		return nil, fmt.Errorf("token exchange failed: %s", tokenErr.Error)
	}

	// Parse successful response
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	// Validate response has required fields
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("invalid token response: missing access_token")
	}

	return &tokenResp, nil
}