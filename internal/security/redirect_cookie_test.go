package security

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEncodeDecodeRedirectV1(t *testing.T) {
	key := []byte("test-signing-key-1234567890")
	now := time.Unix(1700000000, 0)

	validPayload := RedirectPayloadV1{
		V:     RedirectCookieV1,
		URL:   "https://example.com/path",
		Host:  "example.com",
		Ref:   "localhost",
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Minute).Unix(),
		Nonce: "abc123xyz789",
	}

	t.Run("successful encode and decode", func(t *testing.T) {
		encoded, err := encodeRedirectV1(validPayload, key)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		// Check format
		if !strings.Contains(encoded, ".") {
			t.Error("encoded value should contain a dot separator")
		}

		parts := strings.Split(encoded, ".")
		if len(parts) != 2 {
			t.Errorf("expected 2 parts, got %d", len(parts))
		}

		// Verify base64url encoding (no padding, URL-safe chars)
		for i, part := range parts {
			if strings.Contains(part, "=") {
				t.Errorf("part %d contains padding", i)
			}
			if strings.ContainsAny(part, "+/") {
				t.Errorf("part %d contains non-URL-safe characters", i)
			}
			if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
				t.Errorf("part %d is not valid base64url: %v", i, err)
			}
		}

		// Decode and verify
		decoded, err := decodeRedirectV1(encoded, key, nil, now.Add(5*time.Minute), time.Minute)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		// Compare fields
		if decoded.V != validPayload.V {
			t.Errorf("V mismatch: got %s, want %s", decoded.V, validPayload.V)
		}
		if decoded.URL != validPayload.URL {
			t.Errorf("URL mismatch: got %s, want %s", decoded.URL, validPayload.URL)
		}
		if decoded.Host != validPayload.Host {
			t.Errorf("Host mismatch: got %s, want %s", decoded.Host, validPayload.Host)
		}
		if decoded.Ref != validPayload.Ref {
			t.Errorf("Ref mismatch: got %s, want %s", decoded.Ref, validPayload.Ref)
		}
		if decoded.Iat != validPayload.Iat {
			t.Errorf("Iat mismatch: got %d, want %d", decoded.Iat, validPayload.Iat)
		}
		if decoded.Exp != validPayload.Exp {
			t.Errorf("Exp mismatch: got %d, want %d", decoded.Exp, validPayload.Exp)
		}
		if decoded.Nonce != validPayload.Nonce {
			t.Errorf("Nonce mismatch: got %s, want %s", decoded.Nonce, validPayload.Nonce)
		}
	})

	t.Run("key rotation", func(t *testing.T) {
		oldKey := []byte("old-key-1234567890")
		newKey := []byte("new-key-1234567890")

		// Encode with old key
		encoded, err := encodeRedirectV1(validPayload, oldKey)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		// Should fail with wrong key
		_, err = decodeRedirectV1(encoded, newKey, nil, now.Add(5*time.Minute), time.Minute)
		if err == nil || !strings.Contains(err.Error(), "invalid signature") {
			t.Errorf("expected signature error, got: %v", err)
		}

		// Should succeed with old key as secondary
		decoded, err := decodeRedirectV1(encoded, newKey, oldKey, now.Add(5*time.Minute), time.Minute)
		if err != nil {
			t.Fatalf("decode with key rotation failed: %v", err)
		}
		if decoded.URL != validPayload.URL {
			t.Error("decoded payload mismatch")
		}
	})

	t.Run("time validation", func(t *testing.T) {
		encoded, err := encodeRedirectV1(validPayload, key)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		// Token not yet valid (before iat - skew)
		_, err = decodeRedirectV1(encoded, key, nil, now.Add(-2*time.Minute), time.Minute)
		if err == nil || !strings.Contains(err.Error(), "not yet valid") {
			t.Errorf("expected not yet valid error, got: %v", err)
		}

		// Token expired (after exp + skew)
		_, err = decodeRedirectV1(encoded, key, nil, now.Add(32*time.Minute), time.Minute)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Errorf("expected expired error, got: %v", err)
		}

		// Valid with skew
		_, err = decodeRedirectV1(encoded, key, nil, now.Add(29*time.Minute), time.Minute)
		if err != nil {
			t.Errorf("should be valid with skew: %v", err)
		}
	})
}

func TestEncodeRedirectV1Validation(t *testing.T) {
	key := []byte("test-key")
	now := time.Unix(1700000000, 0)

	tests := []struct {
		name    string
		payload RedirectPayloadV1
		key     []byte
		wantErr string
	}{
		{
			name:    "empty key",
			payload: RedirectPayloadV1{V: RedirectCookieV1},
			key:     nil,
			wantErr: "signing key is required",
		},
		{
			name:    "wrong version",
			payload: RedirectPayloadV1{V: "v2"},
			key:     key,
			wantErr: "invalid version",
		},
		{
			name:    "missing URL",
			payload: RedirectPayloadV1{V: RedirectCookieV1},
			key:     key,
			wantErr: "URL is required",
		},
		{
			name: "missing Host",
			payload: RedirectPayloadV1{
				V:   RedirectCookieV1,
				URL: "https://example.com",
			},
			key:     key,
			wantErr: "Host is required",
		},
		{
			name: "missing Nonce",
			payload: RedirectPayloadV1{
				V:    RedirectCookieV1,
				URL:  "https://example.com",
				Host: "example.com",
			},
			key:     key,
			wantErr: "Nonce is required",
		},
		{
			name: "invalid Iat",
			payload: RedirectPayloadV1{
				V:     RedirectCookieV1,
				URL:   "https://example.com",
				Host:  "example.com",
				Nonce: "nonce",
				Iat:   0,
			},
			key:     key,
			wantErr: "Iat must be positive",
		},
		{
			name: "invalid Exp",
			payload: RedirectPayloadV1{
				V:     RedirectCookieV1,
				URL:   "https://example.com",
				Host:  "example.com",
				Nonce: "nonce",
				Iat:   now.Unix(),
				Exp:   0,
			},
			key:     key,
			wantErr: "Exp must be positive",
		},
		{
			name: "Exp before Iat",
			payload: RedirectPayloadV1{
				V:     RedirectCookieV1,
				URL:   "https://example.com",
				Host:  "example.com",
				Nonce: "nonce",
				Iat:   now.Unix(),
				Exp:   now.Unix() - 1,
			},
			key:     key,
			wantErr: "Exp must be after Iat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeRedirectV1(tt.payload, tt.key)
			if err == nil {
				t.Error("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestDecodeRedirectV1Validation(t *testing.T) {
	key := []byte("test-key")
	now := time.Unix(1700000000, 0)

	// Create a valid encoded token for manipulation
	validPayload := RedirectPayloadV1{
		V:     RedirectCookieV1,
		URL:   "https://example.com/path",
		Host:  "example.com",
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Minute).Unix(),
		Nonce: "nonce123",
	}
	validEncoded, _ := encodeRedirectV1(validPayload, key)

	tests := []struct {
		name    string
		input   string
		key     []byte
		wantErr string
	}{
		{
			name:    "empty input",
			input:   "",
			key:     key,
			wantErr: "cookie value is empty",
		},
		{
			name:    "empty key",
			input:   validEncoded,
			key:     nil,
			wantErr: "primary key is required",
		},
		{
			name:    "missing dot separator",
			input:   "nodothere",
			key:     key,
			wantErr: "invalid format",
		},
		{
			name:    "multiple dots",
			input:   "part1.part2.part3",
			key:     key,
			wantErr: "invalid format",
		},
		{
			name:    "invalid base64 payload",
			input:   "not@base64.signature",
			key:     key,
			wantErr: "failed to decode payload",
		},
		{
			name:    "invalid base64 signature",
			input:   base64.RawURLEncoding.EncodeToString([]byte("{}")) + ".not@base64",
			key:     key,
			wantErr: "failed to decode signature",
		},
		{
			name:    "invalid JSON",
			input:   base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig")),
			key:     key,
			wantErr: "invalid signature",
		},
		{
			name:    "wrong signature",
			input:   strings.Replace(validEncoded, validEncoded[len(validEncoded)-5:], "AAAAA", 1),
			key:     key,
			wantErr: "invalid signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeRedirectV1(tt.input, tt.key, nil, now, time.Minute)
			if err == nil {
				t.Error("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestDecodeRedirectV1URLValidation(t *testing.T) {
	key := []byte("test-key")
	now := time.Unix(1700000000, 0)

	tests := []struct {
		name    string
		url     string
		host    string
		wantErr string
	}{
		{
			name:    "empty URL",
			url:     "",
			host:    "example.com",
			wantErr: "URL is empty",
		},
		{
			name:    "relative URL",
			url:     "/path",
			host:    "example.com",
			wantErr: "URL is not absolute",
		},
		{
			name:    "HTTP URL",
			url:     "http://example.com",
			host:    "example.com",
			wantErr: "URL scheme must be https",
		},
		{
			name:    "host mismatch",
			url:     "https://example.com",
			host:    "other.com",
			wantErr: "Host mismatch",
		},
		{
			name:    "empty host",
			url:     "https://example.com",
			host:    "",
			wantErr: "Host is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := RedirectPayloadV1{
				V:     RedirectCookieV1,
				URL:   tt.url,
				Host:  tt.host,
				Iat:   now.Unix(),
				Exp:   now.Add(30 * time.Minute).Unix(),
				Nonce: "nonce",
			}

			// Manually create the token to bypass encode validation
			jsonBytes, _ := json.Marshal(payload)
			sig := hmacSignSHA256(key, jsonBytes)
			encoded := base64.RawURLEncoding.EncodeToString(jsonBytes) + "." + base64.RawURLEncoding.EncodeToString(sig)

			_, err := decodeRedirectV1(encoded, key, nil, now, time.Minute)
			if err == nil {
				t.Error("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestDecodeRedirectV1SkewValidation(t *testing.T) {
	key := []byte("test-key")
	now := time.Unix(1700000000, 0)

	validPayload := RedirectPayloadV1{
		V:     RedirectCookieV1,
		URL:   "https://example.com",
		Host:  "example.com",
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Minute).Unix(),
		Nonce: "nonce",
	}

	encoded, _ := encodeRedirectV1(validPayload, key)

	t.Run("negative skew", func(t *testing.T) {
		_, err := decodeRedirectV1(encoded, key, nil, now, -1*time.Second)
		if err == nil || !strings.Contains(err.Error(), "skew must be non-negative") {
			t.Errorf("expected skew error, got: %v", err)
		}
	})

	t.Run("zero skew", func(t *testing.T) {
		// Should work with zero skew if time is exact
		_, err := decodeRedirectV1(encoded, key, nil, now.Add(15*time.Minute), 0)
		if err != nil {
			t.Errorf("should work with zero skew: %v", err)
		}
	})
}

func TestRedirectV1JSONFormat(t *testing.T) {
	// Test that JSON marshaling produces compact output without extra spaces
	payload := RedirectPayloadV1{
		V:     "v1",
		URL:   "https://example.com/path?query=value",
		Host:  "example.com",
		Ref:   "referrer.com",
		Iat:   1700000000,
		Exp:   1700001800,
		Nonce: "abc123",
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	jsonStr := string(jsonBytes)

	// Check for compact JSON (no extra spaces)
	if strings.Contains(jsonStr, " ") {
		t.Error("JSON contains unnecessary spaces")
	}

	// Verify expected format
	expected := `{"v":"v1","url":"https://example.com/path?query=value","host":"example.com","ref":"referrer.com","iat":1700000000,"exp":1700001800,"n":"abc123"}`
	if jsonStr != expected {
		t.Errorf("JSON format mismatch:\ngot:  %s\nwant: %s", jsonStr, expected)
	}
}

func TestRedirectV1RefOmitempty(t *testing.T) {
	// Test that Ref is omitted when empty
	payload := RedirectPayloadV1{
		V:     "v1",
		URL:   "https://example.com",
		Host:  "example.com",
		Ref:   "", // empty
		Iat:   1700000000,
		Exp:   1700001800,
		Nonce: "abc123",
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	jsonStr := string(jsonBytes)

	// Should not contain "ref" field
	if strings.Contains(jsonStr, `"ref"`) {
		t.Error("JSON should omit empty ref field")
	}

	// Verify the field can be unmarshaled back correctly
	var decoded RedirectPayloadV1
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.Ref != "" {
		t.Errorf("expected empty Ref, got %q", decoded.Ref)
	}
}