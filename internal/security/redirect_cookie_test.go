package security

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		{
			name: "tampered value - single char flipped",
			input: func() string {
				// Flip one character in the middle of the encoded payload
				tampered := []byte(validEncoded)
				midPoint := len(validEncoded) / 3 // Pick a point in the payload part
				if tampered[midPoint] == 'A' {
					tampered[midPoint] = 'B'
				} else {
					tampered[midPoint] = 'A'
				}
				return string(tampered)
			}(),
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

func TestSetAndReadSignedRedirectCookie(t *testing.T) {
	key := []byte("test-signing-key-1234567890")
	now := time.Unix(1700000000, 0)

	t.Run("successful set and read", func(t *testing.T) {
		w := httptest.NewRecorder()
		opts := CookieOpts{
			Domain: ".example.com",
			Secure: true,
			TTL:    30 * time.Minute,
		}

		// Set cookie
		signedValue, err := SetSignedRedirectCookie(w, "https://example.com/path", "referrer.com", key, opts, now)
		if err != nil {
			t.Fatalf("SetSignedRedirectCookie failed: %v", err)
		}

		// Verify a value was returned
		if signedValue == "" {
			t.Error("expected non-empty signed value")
		}

		// Check the cookie was set
		resp := w.Result()
		cookies := resp.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("expected 1 cookie, got %d", len(cookies))
		}

		cookie := cookies[0]
		if cookie.Name != RedirectCookieName {
			t.Errorf("expected cookie name %q, got %q", RedirectCookieName, cookie.Name)
		}
		if cookie.Value != signedValue {
			t.Error("cookie value doesn't match returned signed value")
		}
		if cookie.Domain != "example.com" {
			t.Errorf("expected domain 'example.com', got %q", cookie.Domain)
		}
		if cookie.Path != "/" {
			t.Errorf("expected path '/', got %q", cookie.Path)
		}
		if !cookie.HttpOnly {
			t.Error("expected HttpOnly flag")
		}
		if !cookie.Secure {
			t.Error("expected Secure flag")
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("expected SameSite=Lax, got %v", cookie.SameSite)
		}

		// Create request with cookie
		req := httptest.NewRequest("GET", "https://example.com", nil)
		req.AddCookie(cookie)

		// Read cookie
		url, err := ReadSignedRedirectCookie(req, key, nil, now.Add(5*time.Minute), time.Minute)
		if err != nil {
			t.Fatalf("ReadSignedRedirectCookie failed: %v", err)
		}
		if url != "https://example.com/path" {
			t.Errorf("expected URL 'https://example.com/path', got %q", url)
		}
	})

	t.Run("read with key rotation", func(t *testing.T) {
		w := httptest.NewRecorder()
		oldKey := []byte("old-key-1234567890")
		newKey := []byte("new-key-1234567890")
		opts := CookieOpts{
			Domain: ".example.com",
			TTL:    30 * time.Minute,
		}

		// Set cookie with old key
		_, err := SetSignedRedirectCookie(w, "https://example.com/rotated", "", oldKey, opts, now)
		if err != nil {
			t.Fatalf("SetSignedRedirectCookie failed: %v", err)
		}

		// Get the cookie
		resp := w.Result()
		cookie := resp.Cookies()[0]

		// Try to read with new key only - should fail
		req := httptest.NewRequest("GET", "https://example.com", nil)
		req.AddCookie(cookie)
		_, err = ReadSignedRedirectCookie(req, newKey, nil, now.Add(5*time.Minute), time.Minute)
		if err == nil || !strings.Contains(err.Error(), "failed to decode") {
			t.Errorf("expected decode error, got: %v", err)
		}

		// Read with key rotation - should succeed
		url, err := ReadSignedRedirectCookie(req, newKey, oldKey, now.Add(5*time.Minute), time.Minute)
		if err != nil {
			t.Fatalf("ReadSignedRedirectCookie with rotation failed: %v", err)
		}
		if url != "https://example.com/rotated" {
			t.Errorf("expected URL 'https://example.com/rotated', got %q", url)
		}
	})

	t.Run("cookie not found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		// No cookie set
		_, err := ReadSignedRedirectCookie(req, key, nil, now, time.Minute)
		if err == nil || !strings.Contains(err.Error(), "redirect cookie not found") {
			t.Errorf("expected 'cookie not found' error, got: %v", err)
		}
	})

	t.Run("expired cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		opts := CookieOpts{
			Domain: ".example.com",
			TTL:    30 * time.Minute,
		}

		// Set cookie
		_, err := SetSignedRedirectCookie(w, "https://example.com/expired", "", key, opts, now)
		if err != nil {
			t.Fatalf("SetSignedRedirectCookie failed: %v", err)
		}

		// Get the cookie
		resp := w.Result()
		cookie := resp.Cookies()[0]

		// Try to read after expiration
		req := httptest.NewRequest("GET", "https://example.com", nil)
		req.AddCookie(cookie)
		_, err = ReadSignedRedirectCookie(req, key, nil, now.Add(32*time.Minute), time.Minute)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Errorf("expected expiration error, got: %v", err)
		}
	})
}

func TestSetSignedRedirectCookieValidation(t *testing.T) {
	key := []byte("test-key")
	now := time.Unix(1700000000, 0)
	opts := CookieOpts{TTL: 30 * time.Minute}

	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "invalid URL",
			url:     "not a url",
			wantErr: "URL must be absolute",
		},
		{
			name:    "relative URL",
			url:     "/path",
			wantErr: "URL must be absolute",
		},
		{
			name:    "HTTP URL",
			url:     "http://example.com",
			wantErr: "URL scheme must be https",
		},
		{
			name:    "URL without host",
			url:     "https://",
			wantErr: "URL has no host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, err := SetSignedRedirectCookie(w, tt.url, "", key, opts, now)
			if err == nil {
				t.Error("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}

			// Verify no cookie was set
			resp := w.Result()
			if len(resp.Cookies()) != 0 {
				t.Error("expected no cookies to be set on error")
			}
		})
	}
}

func TestClearRedirectCookie(t *testing.T) {
	w := httptest.NewRecorder()

	// Clear cookie
	ClearRedirectCookie(w, ".example.com")

	// Check the cookie
	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != RedirectCookieName {
		t.Errorf("expected cookie name %q, got %q", RedirectCookieName, cookie.Name)
	}
	if cookie.Value != "" {
		t.Errorf("expected empty value, got %q", cookie.Value)
	}
	if cookie.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", cookie.Domain)
	}
	if cookie.Path != "/" {
		t.Errorf("expected path '/', got %q", cookie.Path)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("expected MaxAge -1, got %d", cookie.MaxAge)
	}
	if !cookie.Expires.Before(time.Now()) {
		t.Error("expected cookie to be expired")
	}
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly flag")
	}
	if !cookie.Secure {
		t.Error("expected Secure flag")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite=Lax, got %v", cookie.SameSite)
	}
}

func TestGenerateNonce(t *testing.T) {
	// Test multiple nonce generations
	nonces := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce, err := generateNonce()
		if err != nil {
			t.Fatalf("generateNonce failed: %v", err)
		}

		// Check format (base64url)
		if strings.ContainsAny(nonce, "+/=") {
			t.Errorf("nonce contains non-base64url characters: %s", nonce)
		}

		// Decode to verify length
		decoded, err := base64.RawURLEncoding.DecodeString(nonce)
		if err != nil {
			t.Errorf("failed to decode nonce: %v", err)
		}
		if len(decoded) != 12 {
			t.Errorf("expected 12 bytes, got %d", len(decoded))
		}

		// Check uniqueness
		if nonces[nonce] {
			t.Errorf("duplicate nonce generated: %s", nonce)
		}
		nonces[nonce] = true
	}
}

func TestCookieOptsWithDefaults(t *testing.T) {
	t.Run("empty opts", func(t *testing.T) {
		opts := CookieOpts{}
		result := opts.WithDefaults()

		if result.Path != "/" {
			t.Errorf("expected Path '/', got %q", result.Path)
		}
		if result.SameSite != http.SameSiteLaxMode {
			t.Errorf("expected SameSite=Lax, got %v", result.SameSite)
		}
		if result.Skew != time.Minute {
			t.Errorf("expected Skew 1m, got %v", result.Skew)
		}
	})

	t.Run("preserves existing values", func(t *testing.T) {
		opts := CookieOpts{
			Path:     "/custom",
			SameSite: http.SameSiteStrictMode,
			Skew:     5 * time.Minute,
			Domain:   ".example.com",
			Secure:   true,
			TTL:      time.Hour,
		}
		result := opts.WithDefaults()

		if result.Path != "/custom" {
			t.Errorf("expected Path '/custom', got %q", result.Path)
		}
		if result.SameSite != http.SameSiteStrictMode {
			t.Errorf("expected SameSite=Strict, got %v", result.SameSite)
		}
		if result.Skew != 5*time.Minute {
			t.Errorf("expected Skew 5m, got %v", result.Skew)
		}
		if result.Domain != ".example.com" {
			t.Errorf("expected Domain '.example.com', got %q", result.Domain)
		}
		if !result.Secure {
			t.Error("expected Secure=true")
		}
		if result.TTL != time.Hour {
			t.Errorf("expected TTL 1h, got %v", result.TTL)
		}
	})
}

func TestHostManipulationAfterEncoding(t *testing.T) {
	key := []byte("test-key")
	now := time.Unix(1700000000, 0)

	// Create a valid payload
	originalPayload := RedirectPayloadV1{
		V:     RedirectCookieV1,
		URL:   "https://example.com/path",
		Host:  "example.com",
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Minute).Unix(),
		Nonce: "nonce123",
	}

	// Encode it properly
	validEncoded, err := encodeRedirectV1(originalPayload, key)
	if err != nil {
		t.Fatalf("failed to encode original payload: %v", err)
	}

	// Decode the payload part
	parts := strings.Split(validEncoded, ".")
	if len(parts) != 2 {
		t.Fatal("expected 2 parts in encoded value")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	// Parse the JSON, modify the host
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	// Change the URL to a different host
	payload["url"] = "https://evil.com/attack"
	payload["host"] = "evil.com"

	// Re-encode the modified payload
	modifiedJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal modified payload: %v", err)
	}

	// Create a new encoded value with the modified payload but original signature
	tamperedValue := base64.RawURLEncoding.EncodeToString(modifiedJSON) + "." + parts[1]

	// Try to decode - should fail due to signature mismatch
	_, err = decodeRedirectV1(tamperedValue, key, nil, now.Add(5*time.Minute), time.Minute)
	if err == nil {
		t.Error("expected error for tampered host, got nil")
	} else if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("expected 'invalid signature' error, got: %v", err)
	}

	t.Run("host mismatch after successful decode", func(t *testing.T) {
		// Create a valid payload with mismatched host
		mismatchedPayload := RedirectPayloadV1{
			V:     RedirectCookieV1,
			URL:   "https://example.com/path",
			Host:  "different.com", // Wrong host for the URL
			Iat:   now.Unix(),
			Exp:   now.Add(30 * time.Minute).Unix(),
			Nonce: "nonce456",
		}

		// Manually create the token to bypass encode validation
		jsonBytes, _ := json.Marshal(mismatchedPayload)
		sig := hmacSignSHA256(key, jsonBytes)
		encoded := base64.RawURLEncoding.EncodeToString(jsonBytes) + "." + base64.RawURLEncoding.EncodeToString(sig)

		// Try to decode - should fail due to host mismatch
		_, err := decodeRedirectV1(encoded, key, nil, now.Add(5*time.Minute), time.Minute)
		if err == nil {
			t.Error("expected error for host mismatch, got nil")
		} else if !strings.Contains(err.Error(), "Host mismatch") {
			t.Errorf("expected 'Host mismatch' error, got: %v", err)
		}
	})
}

func TestSetSignedRedirectCookieSizeLimit(t *testing.T) {
	key := []byte("test-key-32-bytes-123456789012")
	now := time.Now()

	// Create a very long URL that will result in a cookie exceeding 3500 bytes
	// We'll construct a URL with a very long query parameter
	baseURL := "https://example.com/path"
	longParam := strings.Repeat("a", 4000) // 4000 characters should be enough to exceed the limit
	longURL := baseURL + "?very_long_param=" + longParam

	opts := CookieOpts{
		Domain:   ".example.com",
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		TTL:      30 * time.Minute,
		Skew:     time.Minute,
	}

	// Create a mock response writer
	rec := httptest.NewRecorder()

	// Attempt to set the cookie - should fail due to size limit
	_, err := SetSignedRedirectCookie(rec, longURL, "example.com", key, opts, now)

	// Should get an error about cookie being too large
	if err == nil {
		t.Error("expected error for oversized cookie, got nil")
	} else if !strings.Contains(err.Error(), "cookie value too large") {
		t.Errorf("expected 'cookie value too large' error, got: %v", err)
	} else if !strings.Contains(err.Error(), "exceeds 3500 byte limit") {
		t.Errorf("expected error to mention 3500 byte limit, got: %v", err)
	}

	// Verify no cookie was set
	cookies := rec.Result().Cookies()
	if len(cookies) > 0 {
		t.Errorf("expected no cookies to be set, but got %d cookies", len(cookies))
	}

	// Test with a normal-sized URL to ensure the function still works correctly
	t.Run("normal size URL should work", func(t *testing.T) {
		normalRec := httptest.NewRecorder()
		normalURL := "https://example.com/normal/path?param=value"

		_, err := SetSignedRedirectCookie(normalRec, normalURL, "example.com", key, opts, now)
		if err != nil {
			t.Errorf("expected no error for normal-sized URL, got: %v", err)
		}

		// Verify cookie was set
		cookies := normalRec.Result().Cookies()
		if len(cookies) != 1 {
			t.Errorf("expected 1 cookie to be set, got %d", len(cookies))
		} else if cookies[0].Name != RedirectCookieName {
			t.Errorf("expected cookie name '%s', got '%s'", RedirectCookieName, cookies[0].Name)
		}
	})
}
