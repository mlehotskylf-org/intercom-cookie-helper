package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIntercomRenderer_Render(t *testing.T) {
	validSecret := []byte("test-secret-key-32-bytes-minimum!")
	validAppID := "ic_test123"

	t.Run("successful render with redirect", func(t *testing.T) {
		renderer := &IntercomRenderer{
			AppID:  validAppID,
			Secret: validSecret,
			TTL:    5 * time.Minute,
		}

		payload := IdentifyPayload{
			ReturnTo: "https://app.example.com/complete-login",
			Subject:  "auth0|12345",
			Email:    "user@example.com",
			Name:     "Test User",
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check redirect status
		if w.Code != http.StatusFound {
			t.Errorf("expected status %d, got %d", http.StatusFound, w.Code)
		}

		// Check Location header
		location := w.Header().Get("Location")
		if location == "" {
			t.Fatal("expected Location header")
		}

		// Parse and verify the redirect URL
		redirectURL, err := url.Parse(location)
		if err != nil {
			t.Fatalf("invalid redirect URL: %v", err)
		}

		if redirectURL.Scheme != "https" {
			t.Errorf("expected https scheme, got %s", redirectURL.Scheme)
		}
		if redirectURL.Host != "app.example.com" {
			t.Errorf("expected host app.example.com, got %s", redirectURL.Host)
		}
		if redirectURL.Path != "/complete-login" {
			t.Errorf("expected path /complete-login, got %s", redirectURL.Path)
		}

		// Check for intercom_token parameter
		token := redirectURL.Query().Get("intercom_token")
		if token == "" {
			t.Fatal("expected intercom_token in query parameters")
		}

		// Verify the token is valid
		claims, err := VerifyIntercomJWT(validSecret, token)
		if err != nil {
			t.Fatalf("failed to verify token: %v", err)
		}

		if claims.UserID != payload.Subject {
			t.Errorf("expected UserID %s, got %s", payload.Subject, claims.UserID)
		}
		if claims.Email != payload.Email {
			t.Errorf("expected Email %s, got %s", payload.Email, claims.Email)
		}
		if claims.Name != payload.Name {
			t.Errorf("expected Name %s, got %s", payload.Name, claims.Name)
		}
	})

	t.Run("minimal payload", func(t *testing.T) {
		renderer := &IntercomRenderer{
			AppID:  validAppID,
			Secret: validSecret,
			// No TTL specified, should use default
		}

		payload := IdentifyPayload{
			ReturnTo: "https://app.example.com/",
			Subject:  "user123",
			// No Email or Name
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		location := w.Header().Get("Location")
		redirectURL, _ := url.Parse(location)
		token := redirectURL.Query().Get("intercom_token")

		claims, err := VerifyIntercomJWT(validSecret, token)
		if err != nil {
			t.Fatalf("failed to verify token: %v", err)
		}

		if claims.UserID != payload.Subject {
			t.Errorf("expected UserID %s, got %s", payload.Subject, claims.UserID)
		}
		if claims.Email != "" {
			t.Errorf("expected empty Email, got %s", claims.Email)
		}
		if claims.Name != "" {
			t.Errorf("expected empty Name, got %s", claims.Name)
		}

		// Check default TTL (10 minutes)
		expectedExp := claims.Iat + 600 // 10 minutes in seconds
		if claims.Exp != expectedExp {
			t.Errorf("expected Exp %d, got %d", expectedExp, claims.Exp)
		}
	})

	t.Run("missing app ID", func(t *testing.T) {
		renderer := &IntercomRenderer{
			AppID:  "", // Missing
			Secret: validSecret,
			TTL:    5 * time.Minute,
		}

		payload := IdentifyPayload{
			ReturnTo: "https://app.example.com/",
			Subject:  "user123",
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err == nil {
			t.Fatal("expected error for missing app ID")
		}
		if !strings.Contains(err.Error(), "app ID is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("missing secret", func(t *testing.T) {
		renderer := &IntercomRenderer{
			AppID:  validAppID,
			Secret: nil, // Missing
			TTL:    5 * time.Minute,
		}

		payload := IdentifyPayload{
			ReturnTo: "https://app.example.com/",
			Subject:  "user123",
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err == nil {
			t.Fatal("expected error for missing secret")
		}
		if !strings.Contains(err.Error(), "secret is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("missing subject", func(t *testing.T) {
		renderer := &IntercomRenderer{
			AppID:  validAppID,
			Secret: validSecret,
			TTL:    5 * time.Minute,
		}

		payload := IdentifyPayload{
			ReturnTo: "https://app.example.com/",
			Subject:  "", // Missing
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err == nil {
			t.Fatal("expected error for missing subject")
		}
		if !strings.Contains(err.Error(), "subject is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("missing return URL", func(t *testing.T) {
		renderer := &IntercomRenderer{
			AppID:  validAppID,
			Secret: validSecret,
			TTL:    5 * time.Minute,
		}

		payload := IdentifyPayload{
			ReturnTo: "", // Missing
			Subject:  "user123",
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err == nil {
			t.Fatal("expected error for missing return URL")
		}
		if !strings.Contains(err.Error(), "return URL is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("invalid return URL", func(t *testing.T) {
		renderer := &IntercomRenderer{
			AppID:  validAppID,
			Secret: validSecret,
			TTL:    5 * time.Minute,
		}

		payload := IdentifyPayload{
			ReturnTo: "://invalid-url",
			Subject:  "user123",
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err == nil {
			t.Fatal("expected error for invalid return URL")
		}
		if !strings.Contains(err.Error(), "invalid return URL") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("preserves existing query parameters", func(t *testing.T) {
		renderer := &IntercomRenderer{
			AppID:  validAppID,
			Secret: validSecret,
			TTL:    5 * time.Minute,
		}

		payload := IdentifyPayload{
			ReturnTo: "https://app.example.com/login?source=email&campaign=welcome",
			Subject:  "user123",
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		location := w.Header().Get("Location")
		redirectURL, _ := url.Parse(location)

		// Check that original parameters are preserved
		if redirectURL.Query().Get("source") != "email" {
			t.Error("expected source=email parameter to be preserved")
		}
		if redirectURL.Query().Get("campaign") != "welcome" {
			t.Error("expected campaign=welcome parameter to be preserved")
		}
		// And the token is added
		if redirectURL.Query().Get("intercom_token") == "" {
			t.Error("expected intercom_token to be added")
		}
	})
}

// TestIdentifyRendererInterface verifies the interface is properly implemented
func TestIdentifyRendererInterface(t *testing.T) {
	// This test ensures IntercomRenderer implements IdentifyRenderer
	var _ IdentifyRenderer = (*IntercomRenderer)(nil)

	// Test that we can use it through the interface
	var renderer IdentifyRenderer = &IntercomRenderer{
		AppID:  "test",
		Secret: []byte("secret"),
		TTL:    5 * time.Minute,
	}

	w := httptest.NewRecorder()
	err := renderer.Render(w, IdentifyPayload{
		ReturnTo: "https://example.com",
		Subject:  "user123",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
