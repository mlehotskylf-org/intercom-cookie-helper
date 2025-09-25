package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEncodeTxnV1(t *testing.T) {
	now := time.Now()
	validPayload := TxnPayloadV1{
		V:     TxnV1,
		State: base64.RawURLEncoding.EncodeToString([]byte("test-state")),
		CV:    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", // 43 chars, valid PKCE verifier
		Nonce: base64.RawURLEncoding.EncodeToString([]byte("test-nonce")),
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Minute).Unix(),
	}

	key := []byte("test-signing-key-32-bytes-long!!")

	tests := []struct {
		name        string
		payload     TxnPayloadV1
		key         []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid payload",
			payload:     validPayload,
			key:         key,
			expectError: false,
		},
		{
			name:        "empty key",
			payload:     validPayload,
			key:         []byte{},
			expectError: true,
			errorMsg:    "signing key is required",
		},
		{
			name: "wrong version",
			payload: TxnPayloadV1{
				V:     "v2",
				State: validPayload.State,
				CV:    validPayload.CV,
				Nonce: validPayload.Nonce,
				Iat:   validPayload.Iat,
				Exp:   validPayload.Exp,
			},
			key:         key,
			expectError: true,
			errorMsg:    "invalid version",
		},
		{
			name: "empty state",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: "",
				CV:    validPayload.CV,
				Nonce: validPayload.Nonce,
				Iat:   validPayload.Iat,
				Exp:   validPayload.Exp,
			},
			key:         key,
			expectError: true,
			errorMsg:    "State is required",
		},
		{
			name: "empty code verifier",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: validPayload.State,
				CV:    "",
				Nonce: validPayload.Nonce,
				Iat:   validPayload.Iat,
				Exp:   validPayload.Exp,
			},
			key:         key,
			expectError: true,
			errorMsg:    "CV (code verifier) is required",
		},
		{
			name: "empty nonce",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: validPayload.State,
				CV:    validPayload.CV,
				Nonce: "",
				Iat:   validPayload.Iat,
				Exp:   validPayload.Exp,
			},
			key:         key,
			expectError: true,
			errorMsg:    "Nonce is required",
		},
		{
			name: "invalid state format",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: "not-base64url!@#$",
				CV:    validPayload.CV,
				Nonce: validPayload.Nonce,
				Iat:   validPayload.Iat,
				Exp:   validPayload.Exp,
			},
			key:         key,
			expectError: true,
			errorMsg:    "State is not valid base64url",
		},
		{
			name: "invalid CV format",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: validPayload.State,
				CV:    "not-base64url!@#$",
				Nonce: validPayload.Nonce,
				Iat:   validPayload.Iat,
				Exp:   validPayload.Exp,
			},
			key:         key,
			expectError: true,
			errorMsg:    "CV is not valid base64url",
		},
		{
			name: "invalid nonce format",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: validPayload.State,
				CV:    validPayload.CV,
				Nonce: "not-base64url!@#$",
				Iat:   validPayload.Iat,
				Exp:   validPayload.Exp,
			},
			key:         key,
			expectError: true,
			errorMsg:    "Nonce is not valid base64url",
		},
		{
			name: "zero Iat",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: validPayload.State,
				CV:    validPayload.CV,
				Nonce: validPayload.Nonce,
				Iat:   0,
				Exp:   validPayload.Exp,
			},
			key:         key,
			expectError: true,
			errorMsg:    "Iat must be positive",
		},
		{
			name: "zero Exp",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: validPayload.State,
				CV:    validPayload.CV,
				Nonce: validPayload.Nonce,
				Iat:   validPayload.Iat,
				Exp:   0,
			},
			key:         key,
			expectError: true,
			errorMsg:    "Exp must be positive",
		},
		{
			name: "Exp before Iat",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: validPayload.State,
				CV:    validPayload.CV,
				Nonce: validPayload.Nonce,
				Iat:   now.Unix(),
				Exp:   now.Add(-1 * time.Hour).Unix(),
			},
			key:         key,
			expectError: true,
			errorMsg:    "Exp must be after Iat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeTxnV1(tt.payload, tt.key)

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

			// Verify format
			parts := strings.Split(encoded, ".")
			if len(parts) != 2 {
				t.Errorf("expected 2 parts separated by dot, got %d", len(parts))
			}

			// Verify payload can be decoded
			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				t.Errorf("failed to decode payload: %v", err)
			}

			// Verify signature can be decoded
			sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Errorf("failed to decode signature: %v", err)
			}

			// Verify signature length (SHA256 = 32 bytes)
			if len(sigBytes) != 32 {
				t.Errorf("expected signature length 32, got %d", len(sigBytes))
			}

			// Verify payload contents
			var decodedPayload TxnPayloadV1
			if err := json.Unmarshal(payloadBytes, &decodedPayload); err != nil {
				t.Errorf("failed to unmarshal payload: %v", err)
			}

			if decodedPayload.V != tt.payload.V {
				t.Errorf("version mismatch: expected %s, got %s", tt.payload.V, decodedPayload.V)
			}
			if decodedPayload.State != tt.payload.State {
				t.Errorf("state mismatch: expected %s, got %s", tt.payload.State, decodedPayload.State)
			}
			if decodedPayload.CV != tt.payload.CV {
				t.Errorf("CV mismatch: expected %s, got %s", tt.payload.CV, decodedPayload.CV)
			}
			if decodedPayload.Nonce != tt.payload.Nonce {
				t.Errorf("Nonce mismatch: expected %s, got %s", tt.payload.Nonce, decodedPayload.Nonce)
			}
		})
	}
}

func TestDecodeTxnV1(t *testing.T) {
	now := time.Now()
	key := []byte("test-signing-key-32-bytes-long!!")
	keySecondary := []byte("secondary-key-32-bytes-long!!!!!!")

	// Create a valid encoded token
	validPayload := TxnPayloadV1{
		V:     TxnV1,
		State: base64.RawURLEncoding.EncodeToString([]byte("test-state")),
		CV:    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", // 43 chars, valid PKCE verifier
		Nonce: base64.RawURLEncoding.EncodeToString([]byte("test-nonce")),
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Minute).Unix(),
	}

	validEncoded, _ := EncodeTxnV1(validPayload, key)
	validEncodedSecondary, _ := EncodeTxnV1(validPayload, keySecondary)

	// Create an expired token
	expiredPayload := validPayload
	expiredPayload.Iat = now.Add(-2 * time.Hour).Unix()
	expiredPayload.Exp = now.Add(-1 * time.Hour).Unix()
	expiredEncoded, _ := EncodeTxnV1(expiredPayload, key)

	// Create a future token
	futurePayload := validPayload
	futurePayload.Iat = now.Add(2 * time.Hour).Unix()
	futurePayload.Exp = now.Add(3 * time.Hour).Unix()
	futureEncoded, _ := EncodeTxnV1(futurePayload, key)

	tests := []struct {
		name         string
		encoded      string
		keyPrimary   []byte
		keySecondary []byte
		now          time.Time
		skew         time.Duration
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "valid token",
			encoded:      validEncoded,
			keyPrimary:   key,
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  false,
		},
		{
			name:         "valid token with secondary key",
			encoded:      validEncodedSecondary,
			keyPrimary:   key,
			keySecondary: keySecondary,
			now:          now,
			skew:         time.Minute,
			expectError:  false,
		},
		{
			name:         "empty cookie value",
			encoded:      "",
			keyPrimary:   key,
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  true,
			errorMsg:     "cookie value is empty",
		},
		{
			name:         "empty primary key",
			encoded:      validEncoded,
			keyPrimary:   []byte{},
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  true,
			errorMsg:     "primary key is required",
		},
		{
			name:         "negative skew",
			encoded:      validEncoded,
			keyPrimary:   key,
			keySecondary: nil,
			now:          now,
			skew:         -1 * time.Minute,
			expectError:  true,
			errorMsg:     "skew must be non-negative",
		},
		{
			name:         "invalid format - no dot",
			encoded:      "nodothere",
			keyPrimary:   key,
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  true,
			errorMsg:     "invalid format",
		},
		{
			name:         "invalid format - multiple dots",
			encoded:      "part1.part2.part3",
			keyPrimary:   key,
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  true,
			errorMsg:     "invalid format",
		},
		{
			name:         "invalid payload encoding",
			encoded:      "not-base64!@#$.validpart",
			keyPrimary:   key,
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  true,
			errorMsg:     "failed to decode payload",
		},
		{
			name:         "invalid signature encoding",
			encoded:      base64.RawURLEncoding.EncodeToString([]byte("test")) + ".not-base64!@#$",
			keyPrimary:   key,
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  true,
			errorMsg:     "failed to decode signature",
		},
		{
			name:         "wrong key",
			encoded:      validEncoded,
			keyPrimary:   []byte("wrong-key-32-bytes-long!!!!!!!!!!"),
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  true,
			errorMsg:     "invalid signature",
		},
		{
			name:         "expired token",
			encoded:      expiredEncoded,
			keyPrimary:   key,
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  true,
			errorMsg:     "token expired",
		},
		{
			name:         "expired token within skew",
			encoded:      expiredEncoded,
			keyPrimary:   key,
			keySecondary: nil,
			now:          now.Add(-1*time.Hour - 30*time.Second),
			skew:         time.Minute,
			expectError:  false,
		},
		{
			name:         "future token",
			encoded:      futureEncoded,
			keyPrimary:   key,
			keySecondary: nil,
			now:          now,
			skew:         time.Minute,
			expectError:  true,
			errorMsg:     "token not yet valid",
		},
		{
			name:         "future token within skew",
			encoded:      futureEncoded,
			keyPrimary:   key,
			keySecondary: nil,
			now:          now.Add(2*time.Hour - 30*time.Second),
			skew:         time.Minute,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := DecodeTxnV1(tt.encoded, tt.keyPrimary, tt.keySecondary, tt.now, tt.skew)

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

			// Verify decoded values
			if decoded.V != TxnV1 {
				t.Errorf("expected version %s, got %s", TxnV1, decoded.V)
			}
			if decoded.State == "" {
				t.Error("State should not be empty")
			}
			if decoded.CV == "" {
				t.Error("CV should not be empty")
			}
			if decoded.Nonce == "" {
				t.Error("Nonce should not be empty")
			}
			if decoded.Iat <= 0 {
				t.Error("Iat should be positive")
			}
			if decoded.Exp <= 0 {
				t.Error("Exp should be positive")
			}
			if decoded.Exp <= decoded.Iat {
				t.Error("Exp should be after Iat")
			}
		})
	}
}

func TestDecodeTxnV1_InvalidPayloads(t *testing.T) {
	now := time.Now()
	key := []byte("test-signing-key-32-bytes-long!!")

	tests := []struct {
		name        string
		payload     TxnPayloadV1
		expectError bool
		errorMsg    string
	}{
		{
			name: "CV too short",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: base64.RawURLEncoding.EncodeToString([]byte("test-state")),
				CV:    "tooShort", // < 43 chars
				Nonce: base64.RawURLEncoding.EncodeToString([]byte("test-nonce")),
				Iat:   now.Unix(),
				Exp:   now.Add(30 * time.Minute).Unix(),
			},
			expectError: true,
			errorMsg:    "CV length",
		},
		{
			name: "CV too long",
			payload: TxnPayloadV1{
				V:     TxnV1,
				State: base64.RawURLEncoding.EncodeToString([]byte("test-state")),
				CV:    strings.Repeat("A", 129), // > 128 chars, but will fail base64 validation first
				Nonce: base64.RawURLEncoding.EncodeToString([]byte("test-nonce")),
				Iat:   now.Unix(),
				Exp:   now.Add(30 * time.Minute).Unix(),
			},
			expectError: true,
			errorMsg:    "CV is not valid base64url", // Error occurs during base64 validation
		},
		{
			name: "wrong version in payload",
			payload: TxnPayloadV1{
				V:     "v2",
				State: base64.RawURLEncoding.EncodeToString([]byte("test-state")),
				CV:    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
				Nonce: base64.RawURLEncoding.EncodeToString([]byte("test-nonce")),
				Iat:   now.Unix(),
				Exp:   now.Add(30 * time.Minute).Unix(),
			},
			expectError: true,
			errorMsg:    "invalid version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Manually create the encoded token to bypass EncodeTxnV1 validation
			jsonBytes, _ := json.Marshal(tt.payload)
			encodedPayload := base64.RawURLEncoding.EncodeToString(jsonBytes)

			h := hmac.New(sha256.New, key)
			h.Write(jsonBytes)
			signature := h.Sum(nil)
			encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

			encoded := encodedPayload + "." + encodedSignature

			_, err := DecodeTxnV1(encoded, key, nil, now, time.Minute)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestTxnCookieRoundTrip(t *testing.T) {
	now := time.Now()
	key := []byte("test-signing-key-32-bytes-long!!")

	// Generate valid PKCE values
	verifier, err := NewCodeVerifier(32)
	if err != nil {
		t.Fatalf("failed to generate code verifier: %v", err)
	}

	nonce, err := NewNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	state, err := NewNonce(16) // Use as state
	if err != nil {
		t.Fatalf("failed to generate state: %v", err)
	}

	// Create payload
	original := TxnPayloadV1{
		V:     TxnV1,
		State: state,
		CV:    verifier,
		Nonce: nonce,
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Minute).Unix(),
	}

	// Encode
	encoded, err := EncodeTxnV1(original, key)
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Decode
	decoded, err := DecodeTxnV1(encoded, key, nil, now, time.Minute)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	// Verify round trip
	if decoded.V != original.V {
		t.Errorf("V mismatch: expected %s, got %s", original.V, decoded.V)
	}
	if decoded.State != original.State {
		t.Errorf("State mismatch: expected %s, got %s", original.State, decoded.State)
	}
	if decoded.CV != original.CV {
		t.Errorf("CV mismatch: expected %s, got %s", original.CV, decoded.CV)
	}
	if decoded.Nonce != original.Nonce {
		t.Errorf("Nonce mismatch: expected %s, got %s", original.Nonce, decoded.Nonce)
	}
	if decoded.Iat != original.Iat {
		t.Errorf("Iat mismatch: expected %d, got %d", original.Iat, decoded.Iat)
	}
	if decoded.Exp != original.Exp {
		t.Errorf("Exp mismatch: expected %d, got %d", original.Exp, decoded.Exp)
	}
}

func TestTxnCookieKeyRotation(t *testing.T) {
	now := time.Now()
	keyOld := []byte("old-signing-key-32-bytes-long!!!")
	keyNew := []byte("new-signing-key-32-bytes-long!!!")

	// Generate valid PKCE values
	verifier, _ := NewCodeVerifier(32)
	nonce, _ := NewNonce(16)
	state, _ := NewNonce(16)

	payload := TxnPayloadV1{
		V:     TxnV1,
		State: state,
		CV:    verifier,
		Nonce: nonce,
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Minute).Unix(),
	}

	// Encode with old key
	encoded, err := EncodeTxnV1(payload, keyOld)
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Try to decode with new key only - should fail
	_, err = DecodeTxnV1(encoded, keyNew, nil, now, time.Minute)
	if err == nil {
		t.Error("expected error when decoding with wrong key")
	}

	// Decode with new key as primary, old key as secondary - should succeed
	decoded, err := DecodeTxnV1(encoded, keyNew, keyOld, now, time.Minute)
	if err != nil {
		t.Errorf("failed to decode with key rotation: %v", err)
	}

	if decoded.State != payload.State {
		t.Errorf("State mismatch after key rotation: expected %s, got %s", payload.State, decoded.State)
	}
}

func TestTxnCookieIntegrationWithPKCE(t *testing.T) {
	// This test simulates a complete PKCE flow with transaction cookies
	now := time.Now()
	key := []byte("production-signing-key-32-bytes!")

	// Step 1: Generate PKCE parameters
	codeVerifier, err := NewCodeVerifier(32)
	if err != nil {
		t.Fatalf("failed to generate code verifier: %v", err)
	}

	codeChallenge, err := CodeChallengeS256(codeVerifier)
	if err != nil {
		t.Fatalf("failed to generate code challenge: %v", err)
	}

	// Step 2: Generate state and nonce
	state, err := NewNonce(16)
	if err != nil {
		t.Fatalf("failed to generate state: %v", err)
	}

	nonce, err := NewNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	// Step 3: Create transaction cookie
	txnPayload := TxnPayloadV1{
		V:     TxnV1,
		State: state,
		CV:    codeVerifier,
		Nonce: nonce,
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Minute).Unix(),
	}

	cookieValue, err := EncodeTxnV1(txnPayload, key)
	if err != nil {
		t.Fatalf("failed to encode transaction cookie: %v", err)
	}

	// Step 4: Simulate callback - decode cookie
	decodedTxn, err := DecodeTxnV1(cookieValue, key, nil, now.Add(5*time.Minute), time.Minute)
	if err != nil {
		t.Fatalf("failed to decode transaction cookie: %v", err)
	}

	// Step 5: Verify we can use the code verifier
	if decodedTxn.CV != codeVerifier {
		t.Errorf("code verifier mismatch: expected %s, got %s", codeVerifier, decodedTxn.CV)
	}

	// Verify the code challenge matches
	challengeFromDecoded, err := CodeChallengeS256(decodedTxn.CV)
	if err != nil {
		t.Fatalf("failed to generate challenge from decoded verifier: %v", err)
	}

	if challengeFromDecoded != codeChallenge {
		t.Errorf("code challenge mismatch: expected %s, got %s", codeChallenge, challengeFromDecoded)
	}

	// Verify state matches (for CSRF protection)
	if decodedTxn.State != state {
		t.Errorf("state mismatch: expected %s, got %s", state, decodedTxn.State)
	}

	// Verify nonce matches (for ID token validation)
	if decodedTxn.Nonce != nonce {
		t.Errorf("nonce mismatch: expected %s, got %s", nonce, decodedTxn.Nonce)
	}

	t.Logf("PKCE Integration Test Successful:")
	t.Logf("  Code Verifier: %s (length: %d)", codeVerifier, len(codeVerifier))
	t.Logf("  Code Challenge: %s", codeChallenge)
	t.Logf("  State: %s", state)
	t.Logf("  Nonce: %s", nonce)
	t.Logf("  Cookie Value Length: %d", len(cookieValue))
}
