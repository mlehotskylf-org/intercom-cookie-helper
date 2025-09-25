// Package auth provides OAuth2/OIDC authentication utilities.
// This file handles OAuth2 authorization URL construction.
package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// AuthorizeParams contains parameters for building an OAuth2/OIDC authorization URL.
// It follows OAuth2 (RFC 6749) and OpenID Connect Core 1.0 specifications.
type AuthorizeParams struct {
	// Required fields
	Domain      string // Auth provider domain (e.g., "auth.example.com")
	ClientID    string // OAuth2 client identifier
	RedirectURI string // Callback URL after authorization

	// Standard OAuth2/OIDC parameters
	Scope string // Space-separated scopes (e.g., "openid profile email")
	State string // CSRF protection token (required for security)
	Nonce string // OpenID Connect replay protection (required for OIDC)

	// PKCE parameters (RFC 7636)
	CodeChallenge       string // Base64url-encoded SHA256 hash of code_verifier
	CodeChallengeMethod string // Should be "S256" for SHA256

	// Optional parameters
	Prompt   string // Space-separated prompts (e.g., "login", "consent", "none")
	Audience string // API audience for access token (provider-specific)
}

// BuildAuthorizeURL constructs a standards-compliant OAuth2/OIDC authorization URL.
// It validates required fields and properly URL-encodes all parameters per RFC 3986.
//
// Example output:
//
//	https://auth.example.com/authorize?
//	  response_type=code&
//	  client_id=abc123&
//	  redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&
//	  scope=openid+profile+email&
//	  state=random-state&
//	  nonce=random-nonce&
//	  code_challenge=challenge&
//	  code_challenge_method=S256
func BuildAuthorizeURL(p AuthorizeParams) (string, error) {
	// Validate required fields
	if p.Domain == "" {
		return "", errors.New("domain is required")
	}
	if p.ClientID == "" {
		return "", errors.New("client_id is required")
	}
	if p.RedirectURI == "" {
		return "", errors.New("redirect_uri is required")
	}
	if p.Scope == "" {
		return "", errors.New("scope is required")
	}
	if p.State == "" {
		return "", errors.New("state is required for CSRF protection")
	}

	// For OpenID Connect flows (when scope includes "openid"), nonce is required
	if strings.Contains(p.Scope, "openid") && p.Nonce == "" {
		return "", errors.New("nonce is required for OpenID Connect flows")
	}

	// If PKCE is being used, both challenge and method are required
	if p.CodeChallenge != "" && p.CodeChallengeMethod == "" {
		return "", errors.New("code_challenge_method is required when using PKCE")
	}
	if p.CodeChallengeMethod != "" && p.CodeChallenge == "" {
		return "", errors.New("code_challenge is required when code_challenge_method is set")
	}

	// Validate code_challenge_method if provided
	if p.CodeChallengeMethod != "" && p.CodeChallengeMethod != "S256" && p.CodeChallengeMethod != "plain" {
		return "", fmt.Errorf("invalid code_challenge_method: %s (must be 'S256' or 'plain')", p.CodeChallengeMethod)
	}

	// Validate domain format (no protocol, no path)
	if strings.Contains(p.Domain, "://") {
		return "", errors.New("domain must not contain protocol (e.g., use 'auth.example.com' not 'https://auth.example.com')")
	}
	if strings.Contains(p.Domain, "/") {
		return "", errors.New("domain must not contain path (e.g., use 'auth.example.com' not 'auth.example.com/authorize')")
	}

	// Build base URL
	baseURL := fmt.Sprintf("https://%s/authorize", p.Domain)
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid domain: %w", err)
	}

	// Build query parameters
	q := url.Values{}

	// Required OAuth2 parameters
	q.Set("response_type", "code") // Authorization code flow
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("scope", p.Scope)
	q.Set("state", p.State)

	// OpenID Connect nonce (if provided)
	if p.Nonce != "" {
		q.Set("nonce", p.Nonce)
	}

	// PKCE parameters
	if p.CodeChallenge != "" {
		q.Set("code_challenge", p.CodeChallenge)
		q.Set("code_challenge_method", p.CodeChallengeMethod)
	}

	// Optional parameters
	if p.Prompt != "" {
		q.Set("prompt", p.Prompt)
	}
	if p.Audience != "" {
		q.Set("audience", p.Audience)
	}

	// Set the encoded query string
	u.RawQuery = q.Encode()

	return u.String(), nil
}
