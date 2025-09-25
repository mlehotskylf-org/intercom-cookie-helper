package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewCodeVerifier(t *testing.T) {
	tests := []struct {
		name        string
		nBytes      int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid minimum size",
			nBytes:      32,
			expectError: false,
		},
		{
			name:        "valid medium size",
			nBytes:      48,
			expectError: false,
		},
		{
			name:        "valid maximum size",
			nBytes:      96,
			expectError: false,
		},
		{
			name:        "too small",
			nBytes:      31,
			expectError: true,
			errorMsg:    "must be at least 32 bytes",
		},
		{
			name:        "too large",
			nBytes:      97,
			expectError: true,
			errorMsg:    "must be at most 96 bytes",
		},
		{
			name:        "zero bytes",
			nBytes:      0,
			expectError: true,
			errorMsg:    "must be at least 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewCodeVerifier(tt.nBytes)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify the verifier is valid base64url
			decoded, err := base64.RawURLEncoding.DecodeString(verifier)
			if err != nil {
				t.Errorf("verifier is not valid base64url: %v", err)
			}

			// Verify the decoded length matches input
			if len(decoded) != tt.nBytes {
				t.Errorf("decoded length %d does not match expected %d", len(decoded), tt.nBytes)
			}

			// Verify RFC 7636 length constraints (43-128 characters)
			if len(verifier) < 43 {
				t.Errorf("encoded verifier length %d below RFC 7636 minimum 43", len(verifier))
			}
			if len(verifier) > 128 {
				t.Errorf("encoded verifier length %d above RFC 7636 maximum 128", len(verifier))
			}

			// Verify no padding characters
			if strings.ContainsAny(verifier, "=") {
				t.Errorf("verifier contains padding characters: %s", verifier)
			}

			// Verify only valid base64url characters
			validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
			for _, char := range verifier {
				if !strings.ContainsRune(validChars, char) {
					t.Errorf("verifier contains invalid character: %c", char)
				}
			}
		})
	}
}

func TestNewCodeVerifierUniqueness(t *testing.T) {
	// Generate multiple verifiers and ensure they're unique
	verifiers := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		verifier, err := NewCodeVerifier(32)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if verifiers[verifier] {
			t.Errorf("duplicate verifier found: %s", verifier)
		}
		verifiers[verifier] = true
	}

	if len(verifiers) != iterations {
		t.Errorf("expected %d unique verifiers, got %d", iterations, len(verifiers))
	}
}

func TestCodeChallengeS256(t *testing.T) {
	tests := []struct {
		name        string
		verifier    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid verifier from NewCodeVerifier",
			verifier:    "", // Will be set in test
			expectError: false,
		},
		{
			name:        "minimum length verifier",
			verifier:    strings.Repeat("A", 43), // Minimum length
			expectError: false,
		},
		{
			name:        "maximum length verifier",
			verifier:    strings.Repeat("A", 128), // Maximum length
			expectError: false,
		},
		{
			name:        "empty verifier",
			verifier:    "",
			expectError: true,
			errorMsg:    "cannot be empty",
		},
		{
			name:        "too short verifier",
			verifier:    strings.Repeat("A", 42), // Below minimum
			expectError: true,
			errorMsg:    "too short",
		},
		{
			name:        "too long verifier",
			verifier:    strings.Repeat("A", 129), // Above maximum
			expectError: true,
			errorMsg:    "too long",
		},
		{
			name:        "invalid base64url characters",
			verifier:    strings.Repeat("!", 43), // Invalid characters
			expectError: true,
			errorMsg:    "invalid code verifier format",
		},
		{
			name:        "verifier with padding",
			verifier:    strings.Repeat("A", 42) + "=", // Contains padding
			expectError: true,
			errorMsg:    "invalid code verifier format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := tt.verifier

			// Special case: generate a valid verifier for the first test
			if tt.name == "valid verifier from NewCodeVerifier" {
				var err error
				verifier, err = NewCodeVerifier(32)
				if err != nil {
					t.Fatalf("failed to generate test verifier: %v", err)
				}
			}

			challenge, err := CodeChallengeS256(verifier)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify the challenge is valid base64url
			decoded, err := base64.RawURLEncoding.DecodeString(challenge)
			if err != nil {
				t.Errorf("challenge is not valid base64url: %v", err)
			}

			// Verify the decoded length is 32 bytes (SHA256 hash size)
			if len(decoded) != 32 {
				t.Errorf("decoded challenge length %d, expected 32", len(decoded))
			}

			// Verify no padding characters
			if strings.ContainsAny(challenge, "=") {
				t.Errorf("challenge contains padding characters: %s", challenge)
			}

			// Verify the challenge matches expected SHA256 hash
			expectedHash := sha256.Sum256([]byte(verifier))
			expectedChallenge := base64.RawURLEncoding.EncodeToString(expectedHash[:])
			if challenge != expectedChallenge {
				t.Errorf("challenge %s does not match expected %s", challenge, expectedChallenge)
			}
		})
	}
}

func TestCodeChallengeS256Deterministic(t *testing.T) {
	// Same verifier should always produce the same challenge
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	challenge1, err := CodeChallengeS256(verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	challenge2, err := CodeChallengeS256(verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if challenge1 != challenge2 {
		t.Errorf("challenges should be deterministic: %s != %s", challenge1, challenge2)
	}

	// Verify against known test vector from RFC 7636
	// verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
	// challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if challenge1 != expectedChallenge {
		t.Errorf("challenge %s does not match RFC 7636 test vector %s", challenge1, expectedChallenge)
	}
}

func TestNewNonce(t *testing.T) {
	tests := []struct {
		name        string
		nBytes      int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid minimum size",
			nBytes:      16,
			expectError: false,
		},
		{
			name:        "valid medium size",
			nBytes:      32,
			expectError: false,
		},
		{
			name:        "valid maximum size",
			nBytes:      64,
			expectError: false,
		},
		{
			name:        "too small",
			nBytes:      15,
			expectError: true,
			errorMsg:    "must be at least 16 bytes",
		},
		{
			name:        "too large",
			nBytes:      65,
			expectError: true,
			errorMsg:    "must be at most 64 bytes",
		},
		{
			name:        "zero bytes",
			nBytes:      0,
			expectError: true,
			errorMsg:    "must be at least 16 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce, err := NewNonce(tt.nBytes)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify the nonce is valid base64url
			decoded, err := base64.RawURLEncoding.DecodeString(nonce)
			if err != nil {
				t.Errorf("nonce is not valid base64url: %v", err)
			}

			// Verify the decoded length matches input
			if len(decoded) != tt.nBytes {
				t.Errorf("decoded length %d does not match expected %d", len(decoded), tt.nBytes)
			}

			// Verify no padding characters
			if strings.ContainsAny(nonce, "=") {
				t.Errorf("nonce contains padding characters: %s", nonce)
			}

			// Verify only valid base64url characters
			validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
			for _, char := range nonce {
				if !strings.ContainsRune(validChars, char) {
					t.Errorf("nonce contains invalid character: %c", char)
				}
			}
		})
	}
}

func TestNewNonceUniqueness(t *testing.T) {
	// Generate multiple nonces and ensure they're unique
	nonces := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		nonce, err := NewNonce(16)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if nonces[nonce] {
			t.Errorf("duplicate nonce found: %s", nonce)
		}
		nonces[nonce] = true
	}

	if len(nonces) != iterations {
		t.Errorf("expected %d unique nonces, got %d", iterations, len(nonces))
	}
}

func TestPKCEIntegration(t *testing.T) {
	// Test the complete PKCE flow
	verifier, err := NewCodeVerifier(32)
	if err != nil {
		t.Fatalf("failed to generate code verifier: %v", err)
	}

	challenge, err := CodeChallengeS256(verifier)
	if err != nil {
		t.Fatalf("failed to generate code challenge: %v", err)
	}

	nonce, err := NewNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	// Verify all values are non-empty
	if verifier == "" {
		t.Error("verifier should not be empty")
	}
	if challenge == "" {
		t.Error("challenge should not be empty")
	}
	if nonce == "" {
		t.Error("nonce should not be empty")
	}

	// Verify all values are different
	if verifier == challenge {
		t.Error("verifier and challenge should be different")
	}
	if verifier == nonce {
		t.Error("verifier and nonce should be different")
	}
	if challenge == nonce {
		t.Error("challenge and nonce should be different")
	}

	// Verify lengths are reasonable
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("verifier length %d outside expected range 43-128", len(verifier))
	}
	if len(challenge) != 43 {
		t.Errorf("challenge length %d, expected 43 (SHA256 hash as base64url)", len(challenge))
	}
	if len(nonce) < 22 {
		t.Errorf("nonce length %d seems too short for 16 bytes", len(nonce))
	}

	t.Logf("Generated PKCE parameters:")
	t.Logf("  Code Verifier: %s (length: %d)", verifier, len(verifier))
	t.Logf("  Code Challenge: %s (length: %d)", challenge, len(challenge))
	t.Logf("  Nonce: %s (length: %d)", nonce, len(nonce))
}
