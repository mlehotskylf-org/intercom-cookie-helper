// Package auth provides OAuth2/OIDC authentication utilities.
// This file implements OIDC transaction cookies for stateless round-trip
// security during authentication flows.
//
// # Transaction Cookie Purpose
//
// Transaction cookies maintain critical security parameters during OAuth2/OIDC
// authentication flows without requiring server-side session storage:
// - State: CSRF protection token matching OAuth2 state parameter
// - Code Verifier: PKCE secret for code exchange
// - Nonce: OpenID Connect replay protection
//
// # Security Design
//
// Like redirect cookies, transaction cookies use HMAC-SHA256 for integrity
// verification but not encryption. The cookie format is:
//   base64url(JSON-payload) + "." + base64url(HMAC-signature)
//
// This provides tamper detection while keeping the implementation simple
// and debuggable. The cookies are HttpOnly to prevent JavaScript access.
//
// # Stateless Operation
//
// All authentication state is contained in the signed cookie, eliminating
// the need for server-side session storage. This enables horizontal scaling
// and simplifies deployment.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// TxnCookieName is the name of the OIDC transaction cookie
const TxnCookieName = "ic_oidc_txn"

// TxnV1 is the version identifier for transaction payload v1
const TxnV1 = "v1"

// TxnPayloadV1 represents the OIDC transaction state stored in a cookie
type TxnPayloadV1 struct {
	V     string `json:"v"`   // Version (always "v1")
	State string `json:"st"`  // OAuth2 state parameter for CSRF protection
	CV    string `json:"cv"`  // PKCE code_verifier
	Nonce string `json:"no"`  // OpenID Connect nonce for ID token validation
	Iat   int64  `json:"iat"` // Issued at (unix timestamp)
	Exp   int64  `json:"exp"` // Expires at (unix timestamp)
}

// EncodeTxnV1 encodes and signs a transaction payload as base64url(JSON) + "." + base64url(HMAC)
func EncodeTxnV1(p TxnPayloadV1, key []byte) (string, error) {
	// Validate inputs
	if len(key) == 0 {
		return "", errors.New("signing key is required")
	}
	if p.V != TxnV1 {
		return "", fmt.Errorf("invalid version: expected %s, got %s", TxnV1, p.V)
	}
	if p.State == "" {
		return "", errors.New("State is required")
	}
	if p.CV == "" {
		return "", errors.New("CV (code verifier) is required")
	}
	if p.Nonce == "" {
		return "", errors.New("Nonce is required")
	}
	if p.Iat <= 0 {
		return "", errors.New("Iat must be positive")
	}
	if p.Exp <= 0 {
		return "", errors.New("Exp must be positive")
	}
	if p.Exp <= p.Iat {
		return "", errors.New("Exp must be after Iat")
	}

	// Validate that State, CV, and Nonce are valid base64url (common format for OAuth2/OIDC)
	if _, err := base64.RawURLEncoding.DecodeString(p.State); err != nil {
		return "", fmt.Errorf("State is not valid base64url: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(p.CV); err != nil {
		return "", fmt.Errorf("CV is not valid base64url: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(p.Nonce); err != nil {
		return "", fmt.Errorf("Nonce is not valid base64url: %w", err)
	}

	// Marshal JSON with no extra spaces
	jsonBytes, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Base64URL encode the JSON (no padding)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonBytes)

	// Compute HMAC-SHA256
	h := hmac.New(sha256.New, key)
	h.Write(jsonBytes)
	signature := h.Sum(nil)

	// Base64URL encode the signature (no padding)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Combine with dot separator
	return encodedPayload + "." + encodedSignature, nil
}

// DecodeTxnV1 decodes and verifies a transaction cookie value
func DecodeTxnV1(s string, keyPrimary, keySecondary []byte, now time.Time, skew time.Duration) (TxnPayloadV1, error) {
	var zero TxnPayloadV1

	// Validate inputs
	if s == "" {
		return zero, errors.New("cookie value is empty")
	}
	if len(keyPrimary) == 0 {
		return zero, errors.New("primary key is required")
	}
	if skew < 0 {
		return zero, errors.New("skew must be non-negative")
	}

	// Split on single dot
	parts := len(s)
	dotIndex := -1
	for i := 0; i < parts; i++ {
		if s[i] == '.' {
			if dotIndex != -1 {
				return zero, errors.New("invalid format: multiple dots found")
			}
			dotIndex = i
		}
	}
	if dotIndex == -1 {
		return zero, errors.New("invalid format: expected payload.signature")
	}

	encodedPayload := s[:dotIndex]
	encodedSignature := s[dotIndex+1:]

	// Decode payload
	jsonBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return zero, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return zero, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify signature with primary key
	h := hmac.New(sha256.New, keyPrimary)
	h.Write(jsonBytes)
	expectedSig := h.Sum(nil)
	validSig := subtle.ConstantTimeCompare(signature, expectedSig) == 1

	// Try secondary key if primary fails and secondary is provided
	if !validSig && len(keySecondary) > 0 {
		h = hmac.New(sha256.New, keySecondary)
		h.Write(jsonBytes)
		expectedSig = h.Sum(nil)
		validSig = subtle.ConstantTimeCompare(signature, expectedSig) == 1
	}

	if !validSig {
		return zero, errors.New("invalid signature")
	}

	// Unmarshal JSON
	var p TxnPayloadV1
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return zero, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Check version
	if p.V != TxnV1 {
		return zero, fmt.Errorf("invalid version: expected %s, got %s", TxnV1, p.V)
	}

	// Check timestamp validity with skew
	iat := time.Unix(p.Iat, 0)
	exp := time.Unix(p.Exp, 0)

	// Check issued-at time (allow future dates up to skew)
	if !now.Add(skew).After(iat) {
		return zero, fmt.Errorf("token not yet valid: issued at %v, current time %v (with %v skew)", iat, now, skew)
	}

	// Check expiration time (allow expired tokens up to skew in the past)
	if !now.Add(-skew).Before(exp) {
		return zero, fmt.Errorf("token expired: expires at %v, current time %v (with %v skew)", exp, now, skew)
	}

	// Basic sanity checks
	if p.State == "" {
		return zero, errors.New("State is empty")
	}
	if p.CV == "" {
		return zero, errors.New("CV is empty")
	}
	if p.Nonce == "" {
		return zero, errors.New("Nonce is empty")
	}

	// Validate that State, CV, and Nonce are valid base64url
	if _, err := base64.RawURLEncoding.DecodeString(p.State); err != nil {
		return zero, fmt.Errorf("State is not valid base64url: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(p.CV); err != nil {
		return zero, fmt.Errorf("CV is not valid base64url: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(p.Nonce); err != nil {
		return zero, fmt.Errorf("Nonce is not valid base64url: %w", err)
	}

	// Validate PKCE code verifier length per RFC 7636 (43-128 characters)
	if len(p.CV) < 43 || len(p.CV) > 128 {
		return zero, fmt.Errorf("CV length %d outside RFC 7636 range 43-128", len(p.CV))
	}

	return p, nil
}