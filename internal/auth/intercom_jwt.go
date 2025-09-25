package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// IntercomClaims represents the claims for an Intercom user JWT.
type IntercomClaims struct {
	UserID string // stable LFID sub
	Email  string // optional
	Name   string // optional
	Iat    int64
	Exp    int64 // ~10m
}

// jwtHeader is the standard JWT header for HS256.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// intercomPayload represents the JWT payload for Intercom.
type intercomPayload struct {
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
}

// MintIntercomJWT creates a signed JWT for Intercom user authentication.
func MintIntercomJWT(secret []byte, c IntercomClaims) (string, error) {
	// Validate required fields
	if c.UserID == "" {
		return "", fmt.Errorf("user_id is required")
	}
	if c.Exp <= c.Iat {
		return "", fmt.Errorf("exp must be greater than iat")
	}

	// Create header
	header := jwtHeader{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	// Create payload
	payload := intercomPayload{
		UserID: c.UserID,
		Email:  c.Email,
		Name:   c.Name,
		Iat:    c.Iat,
		Exp:    c.Exp,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Encode header and payload
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature
	signingInput := headerB64 + "." + payloadB64
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(signingInput))
	signature := h.Sum(nil)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Combine to form JWT
	jwt := signingInput + "." + signatureB64

	return jwt, nil
}

// VerifyIntercomJWT verifies and decodes an Intercom JWT (for testing).
func VerifyIntercomJWT(secret []byte, tokenString string) (*IntercomClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if parts[2] != expectedSig {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload intercomPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return &IntercomClaims{
		UserID: payload.UserID,
		Email:  payload.Email,
		Name:   payload.Name,
		Iat:    payload.Iat,
		Exp:    payload.Exp,
	}, nil
}
