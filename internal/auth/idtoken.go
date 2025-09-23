// Package auth provides authentication utilities for OAuth2/OIDC flows
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

// ExtractNonceFromIDToken extracts the nonce claim from an ID token without validating the signature.
// This function only decodes the JWT payload (middle segment) and extracts the nonce value.
// We rely on the authorization code flow and userinfo endpoint for security,
// not on ID token signature validation.
//
// The function expects a standard JWT format: header.payload.signature
// Only the payload segment is decoded and parsed.
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