// Package security provides redirect cookie functionality for secure stateless
// redirect information across OIDC authentication roundtrips.
//
// # Purpose
//
// This package implements tamper-evident redirect cookies that preserve user's
// intended destination URL during OAuth/OIDC authentication flows. The cookies
// enable stateless operation without server-side session storage.
//
// # Security Design
//
// HMAC Signatures: Uses HMAC-SHA256 for integrity verification. This provides
// tamper detection but NOT confidentiality - cookie contents are base64-encoded
// JSON and readable by clients. HMAC ensures the server can detect modifications.
//
// HTTPS Requirement: All redirect URLs must use HTTPS to prevent mixed content
// attacks and ensure transport encryption of the cookie.
//
// Host Allowlist: Only pre-approved hosts are permitted in redirect URLs to
// prevent open redirect vulnerabilities. This includes support for wildcard
// subdomains (e.g., "*.example.com").
//
// # Time-based Security
//
// Expiry: Cookies include expiration timestamps and are rejected after their
// TTL expires, preventing replay attacks with old cookies.
//
// Clock Skew: Configurable tolerance (default 1 minute) accommodates clock
// differences between distributed systems while maintaining security.
//
// # Key Rotation
//
// Primary/Secondary Keys: Supports seamless key rotation using primary and
// secondary signing keys. Cookies signed with either key are accepted,
// allowing zero-downtime key updates.
//
// # Privacy
//
// No PII Storage: Cookies contain only technical redirect information:
// - URL: sanitized destination URL
// - Host: extracted hostname for validation
// - Ref: optional referrer hostname (not full URL)
// - Iat/Exp: issued-at and expiration timestamps
// - Nonce: random value for uniqueness
//
// No user identity, session data, or personal information is stored.
//
// # Cookie Format
//
// Structure: base64url(JSON-payload) + "." + base64url(HMAC-signature)
// Example: eyJ2IjoidjEi...fQ.h7HwVSheXOBIxSYwAwSvJbpEZIVrUVfGfEis8PRHs94
//
// The format is similar to JWT but purpose-built for redirect cookies with
// specific validation and security requirements.
package security

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	RedirectCookieName = "ic_redirect"
	RedirectCookieV1   = "v1"
)

type RedirectPayloadV1 struct {
	V     string `json:"v"`             // "v1"
	URL   string `json:"url"`           // sanitized absolute HTTPS return_to
	Host  string `json:"host"`          // host(u.URL) bound defensively
	Ref   string `json:"ref,omitempty"` // optional referrer host if present
	Iat   int64  `json:"iat"`           // issued at (unix)
	Exp   int64  `json:"exp"`           // expires at (unix)
	Nonce string `json:"n"`             // random 96-bit base64url
}

type CookieOpts struct {
	Domain   string        // e.g., ".riscv.org"
	Secure   bool          // true in prod
	Path     string        // default "/"
	SameSite http.SameSite // default Lax
	TTL      time.Duration // e.g., 30m
	Skew     time.Duration // default 1m clock skew
}

// WithDefaults returns a copy of CookieOpts with sensible defaults applied
func (opts CookieOpts) WithDefaults() CookieOpts {
	if opts.Path == "" {
		opts.Path = "/"
	}
	if opts.SameSite == 0 {
		opts.SameSite = http.SameSiteLaxMode
	}
	if opts.Skew == 0 {
		opts.Skew = time.Minute
	}
	return opts
}

// encodeRedirectV1 encodes a redirect payload as base64url(JSON) + "." + base64url(HMAC)
func encodeRedirectV1(p RedirectPayloadV1, key []byte) (string, error) {
	// Validate inputs
	if len(key) == 0 {
		return "", errors.New("signing key is required")
	}
	if p.V != RedirectCookieV1 {
		return "", fmt.Errorf("invalid version: expected %s, got %s", RedirectCookieV1, p.V)
	}
	if p.URL == "" {
		return "", errors.New("URL is required")
	}
	if p.Host == "" {
		return "", errors.New("Host is required")
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

	// Marshal JSON with no extra spaces
	jsonBytes, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Base64URL encode the JSON (no padding)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonBytes)

	// Compute HMAC-SHA256
	signature := hmacSignSHA256(key, jsonBytes)

	// Base64URL encode the signature (no padding)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Combine with dot separator
	return encodedPayload + "." + encodedSignature, nil
}

// decodeRedirectV1 decodes and verifies a redirect cookie value
func decodeRedirectV1(s string, keyPrimary, keySecondary []byte, now time.Time, skew time.Duration) (RedirectPayloadV1, error) {
	var zero RedirectPayloadV1

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
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return zero, errors.New("invalid format: expected payload.signature")
	}

	encodedPayload := parts[0]
	encodedSignature := parts[1]

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
	expectedSig := hmacSignSHA256(keyPrimary, jsonBytes)
	validSig := constantTimeEqual(signature, expectedSig)

	// Try secondary key if primary fails and secondary is provided
	if !validSig && len(keySecondary) > 0 {
		expectedSig = hmacSignSHA256(keySecondary, jsonBytes)
		validSig = constantTimeEqual(signature, expectedSig)
	}

	if !validSig {
		return zero, errors.New("invalid signature")
	}

	// Unmarshal JSON
	var p RedirectPayloadV1
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return zero, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Check version
	if p.V != RedirectCookieV1 {
		return zero, fmt.Errorf("invalid version: expected %s, got %s", RedirectCookieV1, p.V)
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
	if p.URL == "" {
		return zero, errors.New("URL is empty")
	}

	// Parse and validate URL
	u, err := url.Parse(p.URL)
	if err != nil {
		return zero, fmt.Errorf("invalid URL: %w", err)
	}

	// Check URL is absolute
	if !u.IsAbs() {
		return zero, errors.New("URL is not absolute")
	}

	// Check URL is HTTPS
	if u.Scheme != "https" {
		return zero, fmt.Errorf("URL scheme must be https, got %s", u.Scheme)
	}

	// Check Host field
	if p.Host == "" {
		return zero, errors.New("Host is empty")
	}

	// Verify Host matches parsed URL's host
	if p.Host != u.Host {
		return zero, fmt.Errorf("Host mismatch: payload has %s, URL has %s", p.Host, u.Host)
	}

	// Check nonce is present
	if p.Nonce == "" {
		return zero, errors.New("Nonce is empty")
	}

	return p, nil
}

// generateNonce generates a cryptographically secure random nonce
func generateNonce() (string, error) {
	b := make([]byte, 12) // 96 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SetSignedRedirectCookie creates and sets a signed redirect cookie
func SetSignedRedirectCookie(w http.ResponseWriter, sanitizedURL string, refHost string, key []byte, opts CookieOpts, now time.Time) (string, error) {
	// Parse and validate URL
	u, err := url.Parse(sanitizedURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if !u.IsAbs() {
		return "", errors.New("URL must be absolute")
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("URL scheme must be https, got %s", u.Scheme)
	}

	// Extract host from URL
	host := u.Host
	if host == "" {
		return "", errors.New("URL has no host")
	}

	// Generate nonce
	nonce, err := generateNonce()
	if err != nil {
		return "", err
	}

	// Apply defaults to options
	opts = opts.WithDefaults()

	// Build payload
	payload := RedirectPayloadV1{
		V:     RedirectCookieV1,
		URL:   sanitizedURL,
		Host:  host,
		Ref:   refHost,
		Iat:   now.Unix(),
		Exp:   now.Add(opts.TTL).Unix(),
		Nonce: nonce,
	}

	// Encode and sign
	encodedValue, err := encodeRedirectV1(payload, key)
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}

	// Check cookie size to prevent 4KB browser limit overflow
	// We use 3500 bytes to account for cookie attributes and headers
	if len(encodedValue) > 3500 {
		return "", fmt.Errorf("cookie value too large: %d bytes exceeds 3500 byte limit", len(encodedValue))
	}

	// Create cookie
	cookie := &http.Cookie{
		Name:     RedirectCookieName,
		Value:    encodedValue,
		Domain:   opts.Domain,
		Path:     opts.Path,
		HttpOnly: true,
		SameSite: opts.SameSite,
		Secure:   opts.Secure,
		Expires:  time.Unix(payload.Exp, 0),
		MaxAge:   int(opts.TTL.Seconds()),
	}

	// Set cookie
	http.SetCookie(w, cookie)

	// Return the signed value for debugging/logging
	return encodedValue, nil
}

// ReadSignedRedirectCookie reads and verifies a signed redirect cookie
func ReadSignedRedirectCookie(r *http.Request, keyPrimary, keySecondary []byte, now time.Time, skew time.Duration) (string, error) {
	// Get cookie
	cookie, err := r.Cookie(RedirectCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", errors.New("redirect cookie not found")
		}
		return "", fmt.Errorf("failed to read cookie: %w", err)
	}

	// Decode and verify
	payload, err := decodeRedirectV1(cookie.Value, keyPrimary, keySecondary, now, skew)
	if err != nil {
		return "", fmt.Errorf("failed to decode cookie: %w", err)
	}

	// Return the URL from the payload
	return payload.URL, nil
}

// ClearRedirectCookie sets an expired cookie to clear it from the browser
func ClearRedirectCookie(w http.ResponseWriter, domain string) {
	cookie := &http.Cookie{
		Name:     RedirectCookieName,
		Value:    "",
		Domain:   domain,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		MaxAge:   -1,              // Immediately expire
		Expires:  time.Unix(0, 0), // January 1, 1970
	}
	http.SetCookie(w, cookie)
}
