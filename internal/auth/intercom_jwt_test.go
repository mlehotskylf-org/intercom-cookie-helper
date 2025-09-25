package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMintIntercomJWT(t *testing.T) {
	secret := []byte("test-secret-key-for-testing-only")

	t.Run("happy path", func(t *testing.T) {
		claims := IntercomClaims{
			UserID: "user123",
			Email:  "user@example.com",
			Name:   "Test User",
			Iat:    time.Now().Unix(),
			Exp:    time.Now().Add(10 * time.Minute).Unix(),
		}

		token, err := MintIntercomJWT(secret, claims)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify JWT structure
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3 parts, got %d", len(parts))
		}

		// Verify header
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("failed to decode header: %v", err)
		}

		var header map[string]interface{}
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			t.Fatalf("failed to unmarshal header: %v", err)
		}

		if header["alg"] != "HS256" {
			t.Errorf("expected alg=HS256, got %v", header["alg"])
		}
		if header["typ"] != "JWT" {
			t.Errorf("expected typ=JWT, got %v", header["typ"])
		}

		// Verify payload
		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}

		if payload["user_id"] != claims.UserID {
			t.Errorf("expected user_id=%s, got %v", claims.UserID, payload["user_id"])
		}
		if payload["email"] != claims.Email {
			t.Errorf("expected email=%s, got %v", claims.Email, payload["email"])
		}
		if payload["name"] != claims.Name {
			t.Errorf("expected name=%s, got %v", claims.Name, payload["name"])
		}

		// Verify signature by decoding the token
		decoded, err := VerifyIntercomJWT(secret, token)
		if err != nil {
			t.Fatalf("failed to verify token: %v", err)
		}

		if decoded.UserID != claims.UserID {
			t.Errorf("expected UserID=%s, got %s", claims.UserID, decoded.UserID)
		}
		if decoded.Email != claims.Email {
			t.Errorf("expected Email=%s, got %s", claims.Email, decoded.Email)
		}
		if decoded.Name != claims.Name {
			t.Errorf("expected Name=%s, got %s", claims.Name, decoded.Name)
		}
	})

	t.Run("missing user_id", func(t *testing.T) {
		claims := IntercomClaims{
			UserID: "",
			Email:  "user@example.com",
			Iat:    time.Now().Unix(),
			Exp:    time.Now().Add(10 * time.Minute).Unix(),
		}

		_, err := MintIntercomJWT(secret, claims)
		if err == nil {
			t.Fatal("expected error for missing user_id")
		}
		if !strings.Contains(err.Error(), "user_id is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		claims := IntercomClaims{
			UserID: "user123",
			Iat:    time.Now().Unix(),
			Exp:    time.Now().Unix() - 1, // Already expired
		}

		_, err := MintIntercomJWT(secret, claims)
		if err == nil {
			t.Fatal("expected error for expired token")
		}
		if !strings.Contains(err.Error(), "exp must be greater than iat") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("minimal claims", func(t *testing.T) {
		claims := IntercomClaims{
			UserID: "user123",
			Iat:    time.Now().Unix(),
			Exp:    time.Now().Add(10 * time.Minute).Unix(),
			// No Email or Name
		}

		token, err := MintIntercomJWT(secret, claims)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify payload doesn't include empty fields
		parts := strings.Split(token, ".")
		payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])

		var payload map[string]interface{}
		json.Unmarshal(payloadJSON, &payload)

		if payload["user_id"] != claims.UserID {
			t.Errorf("expected user_id=%s, got %v", claims.UserID, payload["user_id"])
		}

		// Email and name should be omitted when empty
		if _, exists := payload["email"]; exists && payload["email"] == "" {
			t.Error("empty email should be omitted from payload")
		}
		if _, exists := payload["name"]; exists && payload["name"] == "" {
			t.Error("empty name should be omitted from payload")
		}
	})

	t.Run("known test vector", func(t *testing.T) {
		// Fixed test vector for regression testing
		testSecret := []byte("intercom-test-secret")
		claims := IntercomClaims{
			UserID: "auth0|123456",
			Email:  "test@example.com",
			Name:   "Test User",
			Iat:    1700000000,
			Exp:    1700000600,
		}

		token, err := MintIntercomJWT(testSecret, claims)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify the token can be decoded
		decoded, err := VerifyIntercomJWT(testSecret, token)
		if err != nil {
			t.Fatalf("failed to verify known vector token: %v", err)
		}

		if decoded.UserID != claims.UserID {
			t.Errorf("UserID mismatch: expected %s, got %s", claims.UserID, decoded.UserID)
		}
		if decoded.Email != claims.Email {
			t.Errorf("Email mismatch: expected %s, got %s", claims.Email, decoded.Email)
		}
		if decoded.Name != claims.Name {
			t.Errorf("Name mismatch: expected %s, got %s", claims.Name, decoded.Name)
		}
		if decoded.Iat != claims.Iat {
			t.Errorf("Iat mismatch: expected %d, got %d", claims.Iat, decoded.Iat)
		}
		if decoded.Exp != claims.Exp {
			t.Errorf("Exp mismatch: expected %d, got %d", claims.Exp, decoded.Exp)
		}
	})

	t.Run("signature verification", func(t *testing.T) {
		claims := IntercomClaims{
			UserID: "user123",
			Iat:    time.Now().Unix(),
			Exp:    time.Now().Add(10 * time.Minute).Unix(),
		}

		token, err := MintIntercomJWT(secret, claims)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Try to verify with wrong secret
		wrongSecret := []byte("wrong-secret")
		_, err = VerifyIntercomJWT(wrongSecret, token)
		if err == nil {
			t.Fatal("expected error with wrong secret")
		}
		if !strings.Contains(err.Error(), "invalid signature") {
			t.Errorf("unexpected error message: %v", err)
		}

		// Tamper with the token
		parts := strings.Split(token, ".")
		tamperedToken := parts[0] + "." + parts[1] + ".tampered-signature"
		_, err = VerifyIntercomJWT(secret, tamperedToken)
		if err == nil {
			t.Fatal("expected error with tampered token")
		}
		if !strings.Contains(err.Error(), "invalid signature") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("no padding in base64url", func(t *testing.T) {
		claims := IntercomClaims{
			UserID: "u", // Short to potentially need padding
			Iat:    1,
			Exp:    2,
		}

		token, err := MintIntercomJWT(secret, claims)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check that no padding characters are present
		if strings.Contains(token, "=") {
			t.Error("JWT should not contain padding characters")
		}

		// Verify it still works
		_, err = VerifyIntercomJWT(secret, token)
		if err != nil {
			t.Fatalf("failed to verify token without padding: %v", err)
		}
	})
}
