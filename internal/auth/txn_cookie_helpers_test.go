package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSetTxnCookie(t *testing.T) {
	tests := []struct {
		name        string
		opts        TxnOpts
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid options",
			opts: TxnOpts{
				Domain:     ".example.com",
				TTL:        10 * time.Minute,
				Skew:       1 * time.Minute,
				Secure:     true,
				SigningKey: []byte("test-signing-key-32-bytes-long!!"),
			},
			expectError: false,
		},
		{
			name: "default TTL and skew",
			opts: TxnOpts{
				Domain:     ".example.com",
				SigningKey: []byte("test-signing-key-32-bytes-long!!"),
			},
			expectError: false,
		},
		{
			name: "missing domain",
			opts: TxnOpts{
				SigningKey: []byte("test-signing-key-32-bytes-long!!"),
			},
			expectError: true,
			errorMsg:    "cookie domain is required",
		},
		{
			name: "missing signing key",
			opts: TxnOpts{
				Domain: ".example.com",
			},
			expectError: true,
			errorMsg:    "signing key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a response recorder
			w := httptest.NewRecorder()

			// Call SetTxnCookie
			state, codeChallenge, nonce, err := SetTxnCookie(w, tt.opts)

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

			// Verify returned values
			if state == "" {
				t.Error("state should not be empty")
			}
			if codeChallenge == "" {
				t.Error("codeChallenge should not be empty")
			}
			if nonce == "" {
				t.Error("nonce should not be empty")
			}

			// Verify state is valid base64url (32 bytes = 43 chars)
			if len(state) != 43 {
				t.Errorf("state length %d, expected 43 (32 bytes base64url)", len(state))
			}

			// Verify code challenge is valid SHA256 hash (32 bytes = 43 chars)
			if len(codeChallenge) != 43 {
				t.Errorf("codeChallenge length %d, expected 43 (SHA256 as base64url)", len(codeChallenge))
			}

			// Verify nonce is valid base64url (16 bytes = 22 chars)
			if len(nonce) != 22 {
				t.Errorf("nonce length %d, expected 22 (16 bytes base64url)", len(nonce))
			}

			// Check that a cookie was set
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Errorf("expected 1 cookie, got %d", len(cookies))
				return
			}

			cookie := cookies[0]
			if cookie.Name != TxnCookieName {
				t.Errorf("cookie name %s, expected %s", cookie.Name, TxnCookieName)
			}

			// Verify cookie attributes
			if !cookie.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Errorf("cookie SameSite %v, expected Lax", cookie.SameSite)
			}
			if tt.opts.Secure && !cookie.Secure {
				t.Error("cookie should be Secure when opts.Secure is true")
			}

			// Note: httptest strips the leading dot from domains
			expectedDomain := tt.opts.Domain
			if strings.HasPrefix(expectedDomain, ".") {
				expectedDomain = expectedDomain[1:]
			}
			if cookie.Domain != expectedDomain {
				t.Errorf("cookie domain %s, expected %s", cookie.Domain, expectedDomain)
			}

			// Verify cookie can be decoded
			payload, err := DecodeTxnV1(cookie.Value, tt.opts.SigningKey, nil, time.Now(), 1*time.Minute)
			if err != nil {
				t.Errorf("failed to decode cookie: %v", err)
				return
			}

			// Verify payload contains the generated values
			if payload.State != state {
				t.Errorf("payload state %s, expected %s", payload.State, state)
			}
			if payload.Nonce != nonce {
				t.Errorf("payload nonce %s, expected %s", payload.Nonce, nonce)
			}

			// Verify code verifier can produce the same challenge
			challenge, err := CodeChallengeS256(payload.CV)
			if err != nil {
				t.Errorf("failed to compute challenge from verifier: %v", err)
			}
			if challenge != codeChallenge {
				t.Errorf("computed challenge %s, expected %s", challenge, codeChallenge)
			}
		})
	}
}

func TestReadTxnCookie(t *testing.T) {
	// Setup: create a valid transaction cookie
	key := []byte("test-signing-key-32-bytes-long!!")
	// Generate valid base64url values for testing
	stateBytes := make([]byte, 32)
	for i := range stateBytes {
		stateBytes[i] = byte(i)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	codeVerifierBytes := make([]byte, 32)
	for i := range codeVerifierBytes {
		codeVerifierBytes[i] = byte(i + 32)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(codeVerifierBytes)

	nonceBytes := make([]byte, 16)
	for i := range nonceBytes {
		nonceBytes[i] = byte(i + 64)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	now := time.Now()

	payload := TxnPayloadV1{
		V:     TxnV1,
		State: state,
		CV:    codeVerifier,
		Nonce: nonce,
		Iat:   now.Unix(),
		Exp:   now.Add(10 * time.Minute).Unix(),
	}

	cookieValue, err := EncodeTxnV1(payload, key)
	if err != nil {
		t.Fatalf("failed to encode test payload: %v", err)
	}

	tests := []struct {
		name        string
		setupReq    func() *http.Request
		opts        TxnOpts
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid cookie",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.AddCookie(&http.Cookie{
					Name:  TxnCookieName,
					Value: cookieValue,
				})
				return req
			},
			opts: TxnOpts{
				SigningKey: key,
				Skew:       1 * time.Minute,
			},
			expectError: false,
		},
		{
			name: "no cookie present",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/test", nil)
			},
			opts: TxnOpts{
				SigningKey: key,
			},
			expectError: true,
			errorMsg:    "transaction cookie not found",
		},
		{
			name: "invalid signature",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.AddCookie(&http.Cookie{
					Name:  TxnCookieName,
					Value: cookieValue + "tampered",
				})
				return req
			},
			opts: TxnOpts{
				SigningKey: key,
			},
			expectError: true,
			errorMsg:    "failed to decode transaction",
		},
		{
			name: "wrong signing key",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.AddCookie(&http.Cookie{
					Name:  TxnCookieName,
					Value: cookieValue,
				})
				return req
			},
			opts: TxnOpts{
				SigningKey: []byte("wrong-key-32-bytes-long-not-same"),
			},
			expectError: true,
			errorMsg:    "invalid signature",
		},
		{
			name: "valid with secondary key",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.AddCookie(&http.Cookie{
					Name:  TxnCookieName,
					Value: cookieValue,
				})
				return req
			},
			opts: TxnOpts{
				SigningKey:   []byte("new-primary-key-32-bytes-long!!!"),
				SecondaryKey: key, // Old key as secondary
			},
			expectError: false,
		},
		{
			name: "missing signing key",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.AddCookie(&http.Cookie{
					Name:  TxnCookieName,
					Value: cookieValue,
				})
				return req
			},
			opts:        TxnOpts{},
			expectError: true,
			errorMsg:    "signing key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()

			result, err := ReadTxnCookie(req, tt.opts)

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

			// Verify the decoded payload
			if result.State != state {
				t.Errorf("state %s, expected %s", result.State, state)
			}
			if result.CV != codeVerifier {
				t.Errorf("code verifier %s, expected %s", result.CV, codeVerifier)
			}
			if result.Nonce != nonce {
				t.Errorf("nonce %s, expected %s", result.Nonce, nonce)
			}
		})
	}
}

func TestClearTxnCookie(t *testing.T) {
	tests := []struct {
		name         string
		opts         TxnOpts
		expectCookie bool
	}{
		{
			name: "with domain",
			opts: TxnOpts{
				Domain: ".example.com",
				Secure: true,
			},
			expectCookie: true,
		},
		{
			name:         "without domain",
			opts:         TxnOpts{},
			expectCookie: false, // Can't clear without domain
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			ClearTxnCookie(w, tt.opts)

			cookies := w.Result().Cookies()

			if tt.expectCookie {
				if len(cookies) != 1 {
					t.Errorf("expected 1 cookie, got %d", len(cookies))
					return
				}

				cookie := cookies[0]
				if cookie.Name != TxnCookieName {
					t.Errorf("cookie name %s, expected %s", cookie.Name, TxnCookieName)
				}
				if cookie.Value != "" {
					t.Errorf("cookie value should be empty, got %s", cookie.Value)
				}
				if cookie.MaxAge != -1 {
					t.Errorf("cookie MaxAge %d, expected -1", cookie.MaxAge)
				}
				if !cookie.HttpOnly {
					t.Error("cookie should be HttpOnly")
				}
				if cookie.SameSite != http.SameSiteLaxMode {
					t.Errorf("cookie SameSite %v, expected Lax", cookie.SameSite)
				}
				if tt.opts.Secure && !cookie.Secure {
					t.Error("cookie should be Secure when opts.Secure is true")
				}
			} else {
				if len(cookies) != 0 {
					t.Errorf("expected no cookies, got %d", len(cookies))
				}
			}
		})
	}
}

func TestTxnCookieIntegration(t *testing.T) {
	// Test the full flow: set, read, clear
	key := []byte("test-signing-key-32-bytes-long!!")
	opts := TxnOpts{
		Domain:     ".example.com",
		TTL:        10 * time.Minute,
		Secure:     true,
		SigningKey: key,
	}

	// Step 1: Set the cookie
	w := httptest.NewRecorder()
	state, codeChallenge, nonce, err := SetTxnCookie(w, opts)
	if err != nil {
		t.Fatalf("failed to set cookie: %v", err)
	}

	// Get the cookie from the response
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	cookie := cookies[0]

	// Step 2: Read the cookie from a request
	req := httptest.NewRequest("GET", "/callback", nil)
	req.AddCookie(cookie)

	payload, err := ReadTxnCookie(req, opts)
	if err != nil {
		t.Fatalf("failed to read cookie: %v", err)
	}

	// Verify the values match
	if payload.State != state {
		t.Errorf("state mismatch: got %s, expected %s", payload.State, state)
	}
	if payload.Nonce != nonce {
		t.Errorf("nonce mismatch: got %s, expected %s", payload.Nonce, nonce)
	}

	// Verify code challenge can be reproduced
	challenge, err := CodeChallengeS256(payload.CV)
	if err != nil {
		t.Fatalf("failed to compute challenge: %v", err)
	}
	if challenge != codeChallenge {
		t.Errorf("challenge mismatch: got %s, expected %s", challenge, codeChallenge)
	}

	// Step 3: Clear the cookie
	w2 := httptest.NewRecorder()
	ClearTxnCookie(w2, opts)

	clearCookies := w2.Result().Cookies()
	if len(clearCookies) != 1 {
		t.Fatalf("expected 1 clear cookie, got %d", len(clearCookies))
	}
	if clearCookies[0].MaxAge != -1 {
		t.Errorf("clear cookie MaxAge %d, expected -1", clearCookies[0].MaxAge)
	}
}

func TestSetTxnCookieUniqueness(t *testing.T) {
	// Verify that multiple calls generate unique values
	opts := TxnOpts{
		Domain:     ".example.com",
		SigningKey: []byte("test-signing-key-32-bytes-long!!"),
	}

	states := make(map[string]bool)
	challenges := make(map[string]bool)
	nonces := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		w := httptest.NewRecorder()
		state, challenge, nonce, err := SetTxnCookie(w, opts)
		if err != nil {
			t.Fatalf("failed to set cookie: %v", err)
		}

		if states[state] {
			t.Errorf("duplicate state found: %s", state)
		}
		states[state] = true

		if challenges[challenge] {
			t.Errorf("duplicate challenge found: %s", challenge)
		}
		challenges[challenge] = true

		if nonces[nonce] {
			t.Errorf("duplicate nonce found: %s", nonce)
		}
		nonces[nonce] = true
	}

	if len(states) != iterations {
		t.Errorf("expected %d unique states, got %d", iterations, len(states))
	}
	if len(challenges) != iterations {
		t.Errorf("expected %d unique challenges, got %d", iterations, len(challenges))
	}
	if len(nonces) != iterations {
		t.Errorf("expected %d unique nonces, got %d", iterations, len(nonces))
	}
}
