// Package auth provides authentication utilities for OAuth2/OIDC flows
package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestExtractNonceFromIDToken tests the ExtractNonceFromIDToken function
func TestExtractNonceFromIDToken(t *testing.T) {
	tests := []struct {
		name          string
		idToken       string
		expectedNonce string
		expectedError string
	}{
		{
			name:          "valid token with nonce",
			idToken:       createTestToken(t, map[string]interface{}{"nonce": "test-nonce-123"}),
			expectedNonce: "test-nonce-123",
			expectedError: "",
		},
		{
			name:          "valid token without nonce",
			idToken:       createTestToken(t, map[string]interface{}{"sub": "user123"}),
			expectedNonce: "",
			expectedError: "",
		},
		{
			name:          "valid token with empty nonce",
			idToken:       createTestToken(t, map[string]interface{}{"nonce": ""}),
			expectedNonce: "",
			expectedError: "",
		},
		{
			name:          "valid token with multiple claims including nonce",
			idToken:       createTestToken(t, map[string]interface{}{"sub": "user123", "nonce": "complex-nonce", "aud": "client123"}),
			expectedNonce: "complex-nonce",
			expectedError: "",
		},
		{
			name:          "empty token",
			idToken:       "",
			expectedNonce: "",
			expectedError: "id token is empty",
		},
		{
			name:          "malformed token - only one segment",
			idToken:       "onlyone",
			expectedNonce: "",
			expectedError: "invalid id token format: expected 3 segments, got 1",
		},
		{
			name:          "malformed token - two segments",
			idToken:       "header.payload",
			expectedNonce: "",
			expectedError: "invalid id token format: expected 3 segments, got 2",
		},
		{
			name:          "malformed token - four segments",
			idToken:       "header.payload.signature.extra",
			expectedNonce: "",
			expectedError: "invalid id token format: expected 3 segments, got 4",
		},
		{
			name:          "token with empty payload",
			idToken:       "header..signature",
			expectedNonce: "",
			expectedError: "id token payload segment is empty",
		},
		{
			name:          "token with invalid base64 in payload",
			idToken:       "header.!!!invalid-base64!!!.signature",
			expectedNonce: "",
			expectedError: "failed to decode id token payload",
		},
		{
			name:          "token with invalid JSON in payload",
			idToken:       "header." + base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".signature",
			expectedNonce: "",
			expectedError: "failed to parse id token payload",
		},
		{
			name:          "token with JSON array instead of object",
			idToken:       "header." + base64.RawURLEncoding.EncodeToString([]byte(`["not","an","object"]`)) + ".signature",
			expectedNonce: "",
			expectedError: "failed to parse id token payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract nonce from the token
			nonce, err := ExtractNonceFromIDToken(tt.idToken)

			// Check error expectations
			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.expectedError)
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %q", tt.expectedError, err.Error())
				}
				return
			}

			// Check success expectations
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if nonce != tt.expectedNonce {
				t.Errorf("expected nonce %q, got %q", tt.expectedNonce, nonce)
			}
		})
	}
}

// TestExtractNonceFromIDToken_RealWorldTokens tests with more realistic JWT structures
func TestExtractNonceFromIDToken_RealWorldTokens(t *testing.T) {
	// Test with a token that looks like a real Auth0 ID token
	claims := map[string]interface{}{
		"iss":   "https://auth0.example.com/",
		"sub":   "auth0|507f1f77bcf86cd799439011",
		"aud":   "my-client-id",
		"iat":   1516239022,
		"exp":   1516239322,
		"nonce": "n-0S6_WzA2Mj",
		"email": "user@example.com",
		"name":  "John Doe",
	}

	token := createTestToken(t, claims)
	nonce, err := ExtractNonceFromIDToken(token)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedNonce := "n-0S6_WzA2Mj"
	if nonce != expectedNonce {
		t.Errorf("expected nonce %q, got %q", expectedNonce, nonce)
	}
}

// TestExtractNonceFromIDToken_SpecialCharacters tests nonce extraction with special characters
func TestExtractNonceFromIDToken_SpecialCharacters(t *testing.T) {
	specialNonces := []string{
		"nonce-with-dashes",
		"nonce_with_underscores",
		"nonce.with.dots",
		"nonce/with/slashes",
		"nonce+with+plus",
		"nonce=with=equals",
		"複雑な文字列", // Unicode characters
	}

	for _, specialNonce := range specialNonces {
		t.Run("nonce="+specialNonce, func(t *testing.T) {
			token := createTestToken(t, map[string]interface{}{"nonce": specialNonce})
			extractedNonce, err := ExtractNonceFromIDToken(token)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if extractedNonce != specialNonce {
				t.Errorf("expected nonce %q, got %q", specialNonce, extractedNonce)
			}
		})
	}
}

// createTestToken creates a test JWT token with the given payload claims
func createTestToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	// Create a dummy header
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
	}

	// Encode header
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode payload
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create a dummy signature
	signature := "dummy-signature"

	// Combine into JWT format
	return fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signature)
}
