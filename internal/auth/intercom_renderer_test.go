package auth

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIntercomRenderer_Render(t *testing.T) {
	validSecret := []byte("test-secret-key-32-bytes-minimum!")
	validAppID := "ic_test123"

	// Helper to generate mock JWT (simulating Auth0 Action)
	generateMockJWT := func(userID, email, name string) string {
		jwt, err := MintIntercomJWT(validSecret, IntercomClaims{
			UserID: userID,
			Email:  email,
			Name:   name,
			Iat:    time.Now().Unix(),
			Exp:    time.Now().Add(10 * time.Minute).Unix(),
		})
		if err != nil{
			t.Fatalf("failed to mint mock JWT: %v", err)
		}
		return jwt
	}

	t.Run("successful HTML render", func(t *testing.T) {
		mockJWT := generateMockJWT("auth0|12345", "user@example.com", "Test User")

		renderer := &IntercomRenderer{
			AppID: validAppID,
		}

		payload := IdentifyPayload{
			ReturnTo:    "https://app.example.com/complete-login",
			Subject:     "auth0|12345",
			Email:       "user@example.com",
			Name:        "Test User",
			IntercomJWT: mockJWT, // JWT from Auth0 Action
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check content type
		contentType := w.Header().Get("Content-Type")
		if contentType != "text/html; charset=utf-8" {
			t.Errorf("expected HTML content type, got %s", contentType)
		}

		// Check response body contains expected elements
		body := w.Body.String()

		// Check for app_id in intercomSettings
		if !strings.Contains(body, `app_id: "`+validAppID+`"`) {
			t.Error("expected app_id in intercomSettings")
		}

		// Check for JWT in intercomSettings
		if !strings.Contains(body, `intercom_user_jwt: "`) {
			t.Error("expected intercom_user_jwt in intercomSettings")
		}

		// Check for user_id in intercomSettings
		if !strings.Contains(body, `user_id: "auth0|12345"`) {
			t.Error("expected user_id in intercomSettings")
		}

		// Check for email in intercomSettings
		if !strings.Contains(body, `email: "user@example.com"`) {
			t.Error("expected email in intercomSettings")
		}

		// Check for name in intercomSettings
		if !strings.Contains(body, `name: "Test User"`) {
			t.Error("expected name in intercomSettings")
		}

		// Check for Intercom widget script
		if !strings.Contains(body, `https://widget.intercom.io/widget/`+validAppID) {
			t.Error("expected Intercom widget script")
		}

		// Check for return URL (JavaScript escaped with backslashes)
		if !strings.Contains(body, `https:\/\/app.example.com\/complete-login`) {
			t.Error("expected return URL in redirect script")
		}

		// Extract and verify the JWT from the HTML
		jwtStart := strings.Index(body, `intercom_user_jwt: "`) + len(`intercom_user_jwt: "`)
		jwtEnd := strings.Index(body[jwtStart:], `"`)
		if jwtEnd == -1 {
			t.Fatal("could not extract JWT from HTML")
		}
		jwt := body[jwtStart : jwtStart+jwtEnd]

		// Verify the JWT matches what we provided
		claims, err := VerifyIntercomJWT(validSecret, jwt)
		if err != nil {
			t.Fatalf("failed to verify JWT from HTML: %v", err)
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

	t.Run("minimal payload HTML", func(t *testing.T) {
		mockJWT := generateMockJWT("user123", "", "")

		renderer := &IntercomRenderer{
			AppID: validAppID,
		}

		payload := IdentifyPayload{
			ReturnTo:    "https://app.example.com/",
			Subject:     "user123",
			IntercomJWT: mockJWT,
			// No Email or Name
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body := w.Body.String()

		// Check for user_id in intercomSettings (should be present even without email/name)
		if !strings.Contains(body, `user_id: "user123"`) {
			t.Error("expected user_id in intercomSettings")
		}

		// Email and name should not be present in payload fields
		if strings.Contains(body, `email:`) {
			t.Error("email should not be present when not provided")
		}
		if strings.Contains(body, `name:`) {
			t.Error("name should not be present when not provided")
		}

		// Extract JWT
		jwtStart := strings.Index(body, `intercom_user_jwt: "`) + len(`intercom_user_jwt: "`)
		jwtEnd := strings.Index(body[jwtStart:], `"`)
		jwt := body[jwtStart : jwtStart+jwtEnd]

		claims, err := VerifyIntercomJWT(validSecret, jwt)
		if err != nil {
			t.Fatalf("failed to verify JWT: %v", err)
		}

		if claims.UserID != payload.Subject {
			t.Errorf("expected UserID %s, got %s", payload.Subject, claims.UserID)
		}
	})

	t.Run("missing app ID", func(t *testing.T) {
		mockJWT := generateMockJWT("user123", "", "")

		renderer := &IntercomRenderer{
			AppID: "", // Missing
		}

		payload := IdentifyPayload{
			ReturnTo:    "https://app.example.com/",
			Subject:     "user123",
			IntercomJWT: mockJWT,
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

	t.Run("missing JWT", func(t *testing.T) {
		renderer := &IntercomRenderer{
			AppID: validAppID,
		}

		payload := IdentifyPayload{
			ReturnTo:    "https://app.example.com/",
			Subject:     "user123",
			IntercomJWT: "", // Missing - should error
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err == nil {
			t.Fatal("expected error for missing JWT")
		}
		if !strings.Contains(err.Error(), "JWT is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("missing subject", func(t *testing.T) {
		mockJWT := generateMockJWT("user123", "", "")

		renderer := &IntercomRenderer{
			AppID: validAppID,
		}

		payload := IdentifyPayload{
			ReturnTo:    "https://app.example.com/",
			Subject:     "", // Missing
			IntercomJWT: mockJWT,
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
		mockJWT := generateMockJWT("user123", "", "")

		renderer := &IntercomRenderer{
			AppID: validAppID,
		}

		payload := IdentifyPayload{
			ReturnTo:    "", // Missing
			Subject:     "user123",
			IntercomJWT: mockJWT,
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

	t.Run("HTML escaping", func(t *testing.T) {
		mockJWT := generateMockJWT("user123", "", "<script>alert('name')</script>")

		renderer := &IntercomRenderer{
			AppID: validAppID,
		}

		// Test with potentially malicious return URL
		payload := IdentifyPayload{
			ReturnTo:    `https://example.com/"></script><script>alert('xss')</script>`,
			Subject:     "user123",
			Name:        `<script>alert('name')</script>`,
			IntercomJWT: mockJWT,
		}

		w := httptest.NewRecorder()
		err := renderer.Render(w, payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body := w.Body.String()

		// Check that dangerous content is escaped
		if strings.Contains(body, `<script>alert('xss')</script>`) {
			t.Error("XSS not properly escaped in return URL")
		}
		if strings.Contains(body, `<script>alert('name')</script>`) {
			t.Error("XSS not properly escaped in name field")
		}

		// The template should escape these automatically
		if !strings.Contains(body, `&#34;`) || !strings.Contains(body, `&lt;`) {
			// Should contain HTML entities for escaped content
			t.Log("Warning: Expected HTML escaping might be handled differently")
		}
	})
}
