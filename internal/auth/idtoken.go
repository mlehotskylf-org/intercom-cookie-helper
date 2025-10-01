// Package auth provides authentication utilities for OAuth2/OIDC flows.
// This file handles ID token parsing for nonce extraction without signature validation.
// We rely on the authorization code flow for security, not ID token signatures.
package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// jwtPayload represents the minimal JWT payload structure for nonce extraction
type jwtPayload struct {
	Nonce string `json:"nonce,omitempty"`
}

// idTokenClaims represents the ID token payload with user claims
type idTokenClaims struct {
	Sub         string `json:"sub"`                                      // Subject - unique user identifier
	Email       string `json:"email,omitempty"`                          // User's email address
	Name        string `json:"name,omitempty"`                           // User's display name
	Nonce       string `json:"nonce,omitempty"`                          // Nonce for replay protection
	IntercomJWT string `json:"http://lfx.dev/claims/intercom,omitempty"` // Pre-generated Intercom JWT from Auth0 Action
}

// ExtractNonceFromIDToken extracts the nonce claim from an ID token without validating the signature.
// This is used for replay attack prevention by verifying the nonce matches what we sent.
// The function only decodes the JWT payload (middle segment) to extract the nonce value.
// Security note: We rely on the authorization code flow for authentication, not JWT signatures.
//
// The function expects a standard JWT format: header.payload.signature
// Only the payload segment is decoded and parsed for the nonce claim.
func ExtractNonceFromIDToken(idToken string) (string, error) {
	// Check if token is empty
	if idToken == "" {
		return "", fmt.Errorf("id token is empty")
	}

	// Split the JWT into its three segments
	segments := strings.Split(idToken, ".")
	if len(segments) != 3 {
		return "", fmt.Errorf("invalid id token format: expected 3 segments, got %d", len(segments))
	}

	// Get the payload segment (second segment)
	payloadSegment := segments[1]
	if payloadSegment == "" {
		return "", fmt.Errorf("id token payload segment is empty")
	}

	// Base64url decode the payload
	// Add padding if necessary for proper base64 decoding
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return "", fmt.Errorf("failed to decode id token payload: %w", err)
	}

	// Parse the JSON payload to extract the nonce
	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("failed to parse id token payload: %w", err)
	}

	// Return the nonce (may be empty if not present in token)
	return payload.Nonce, nil
}

// ParseUserInfoFromIDToken extracts user claims from an ID token without validating the signature.
// This replaces the need to call the /userinfo endpoint since the ID token already contains this data.
// Security note: We rely on the authorization code flow for authentication, not JWT signatures.
//
// The function expects a standard JWT format: header.payload.signature
// Returns a UserInfo struct with sub, email, and name claims.
func ParseUserInfoFromIDToken(idToken string) (*UserInfo, error) {
	// Check if token is empty
	if idToken == "" {
		return nil, fmt.Errorf("id token is empty")
	}

	// Split the JWT into its three segments
	segments := strings.Split(idToken, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("invalid id token format: expected 3 segments, got %d", len(segments))
	}

	// Get the payload segment (second segment)
	payloadSegment := segments[1]
	if payloadSegment == "" {
		return nil, fmt.Errorf("id token payload segment is empty")
	}

	// Base64url decode the payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return nil, fmt.Errorf("failed to decode id token payload: %w", err)
	}

	// Parse the JSON payload to extract claims
	var claims idTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse id token payload: %w", err)
	}

	// Validate that we have a subject identifier
	if claims.Sub == "" {
		return nil, fmt.Errorf("id token missing required sub claim")
	}

	// Return UserInfo struct with Intercom JWT
	return &UserInfo{
		Sub:         claims.Sub,
		Email:       claims.Email,
		Name:        claims.Name,
		IntercomJWT: claims.IntercomJWT,
	}, nil
}
