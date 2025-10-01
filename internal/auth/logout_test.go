package auth

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildAuth0LogoutURL(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		clientID       string
		returnTo       string
		expectContains []string
		checkParsing   func(t *testing.T, parsedURL *url.URL)
	}{
		{
			name:     "basic logout URL",
			domain:   "example.auth0.com",
			clientID: "test-client-id",
			returnTo: "https://example.com/",
			expectContains: []string{
				"https://example.auth0.com/v2/logout",
				"client_id=test-client-id",
			},
			checkParsing: func(t *testing.T, parsedURL *url.URL) {
				if parsedURL.Scheme != "https" {
					t.Error("Expected HTTPS scheme")
				}
				if parsedURL.Host != "example.auth0.com" {
					t.Errorf("Expected host example.auth0.com, got %s", parsedURL.Host)
				}
				if parsedURL.Path != "/v2/logout" {
					t.Errorf("Expected path /v2/logout, got %s", parsedURL.Path)
				}

				query := parsedURL.Query()
				if query.Get("client_id") != "test-client-id" {
					t.Errorf("Expected client_id=test-client-id, got %s", query.Get("client_id"))
				}
				if query.Get("returnTo") != "https://example.com/" {
					t.Errorf("Expected returnTo=https://example.com/, got %s", query.Get("returnTo"))
				}
			},
		},
		{
			name:     "returnTo with query parameters",
			domain:   "dev.auth0.com",
			clientID: "client123",
			returnTo: "https://app.example.com/logout?source=helper&session=abc123",
			expectContains: []string{
				"https://dev.auth0.com/v2/logout",
				"client_id=client123",
			},
			checkParsing: func(t *testing.T, parsedURL *url.URL) {
				query := parsedURL.Query()
				returnTo := query.Get("returnTo")
				if returnTo != "https://app.example.com/logout?source=helper&session=abc123" {
					t.Errorf("returnTo parameter not properly encoded, got: %s", returnTo)
				}
			},
		},
		{
			name:     "returnTo with special characters",
			domain:   "test.auth0.com",
			clientID: "test-client",
			returnTo: "https://example.com/path?foo=bar&baz=qux#anchor",
			checkParsing: func(t *testing.T, parsedURL *url.URL) {
				query := parsedURL.Query()
				returnTo := query.Get("returnTo")
				// The returnTo parameter should be properly URL encoded
				if returnTo != "https://example.com/path?foo=bar&baz=qux#anchor" {
					t.Errorf("returnTo with special characters not properly handled, got: %s", returnTo)
				}
			},
		},
		{
			name:     "empty returnTo",
			domain:   "example.auth0.com",
			clientID: "client-id",
			returnTo: "",
			checkParsing: func(t *testing.T, parsedURL *url.URL) {
				query := parsedURL.Query()
				if query.Get("client_id") != "client-id" {
					t.Error("client_id should be present")
				}
				// returnTo should not be in query if empty
				if query.Has("returnTo") {
					t.Error("returnTo should not be present when empty")
				}
			},
		},
		{
			name:     "returnTo with URL encoded characters",
			domain:   "auth.example.com",
			clientID: "my-client",
			returnTo: "https://example.com/path?name=John+Doe&email=john%40example.com",
			checkParsing: func(t *testing.T, parsedURL *url.URL) {
				query := parsedURL.Query()
				returnTo := query.Get("returnTo")
				// Should preserve the encoding in the returnTo parameter
				if !strings.Contains(returnTo, "John+Doe") && !strings.Contains(returnTo, "John Doe") {
					t.Errorf("returnTo encoding not preserved correctly, got: %s", returnTo)
				}
			},
		},
		{
			name:     "client ID with special characters",
			domain:   "example.auth0.com",
			clientID: "client-id_123.test",
			returnTo: "https://example.com/",
			checkParsing: func(t *testing.T, parsedURL *url.URL) {
				query := parsedURL.Query()
				clientID := query.Get("client_id")
				if clientID != "client-id_123.test" {
					t.Errorf("client_id not properly encoded, got: %s", clientID)
				}
			},
		},
		{
			name:     "domain without protocol",
			domain:   "my-tenant.us.auth0.com",
			clientID: "test",
			returnTo: "https://example.com/",
			expectContains: []string{
				"https://my-tenant.us.auth0.com/v2/logout",
			},
			checkParsing: func(t *testing.T, parsedURL *url.URL) {
				if parsedURL.Host != "my-tenant.us.auth0.com" {
					t.Errorf("Expected host my-tenant.us.auth0.com, got %s", parsedURL.Host)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the logout URL
			logoutURL := BuildAuth0LogoutURL(tt.domain, tt.clientID, tt.returnTo)

			// Check that URL starts with https://
			if !strings.HasPrefix(logoutURL, "https://") {
				t.Errorf("Logout URL should start with https://, got: %s", logoutURL)
			}

			// Check expected substrings
			for _, expected := range tt.expectContains {
				if !strings.Contains(logoutURL, expected) {
					t.Errorf("Expected URL to contain %q, but it didn't. URL: %s", expected, logoutURL)
				}
			}

			// Parse the URL to validate structure and encoding
			parsedURL, err := url.Parse(logoutURL)
			if err != nil {
				t.Fatalf("Failed to parse logout URL: %v", err)
			}

			// Run custom parsing checks if provided
			if tt.checkParsing != nil {
				tt.checkParsing(t, parsedURL)
			}
		})
	}
}

func TestBuildAuth0LogoutURL_ParameterEncoding(t *testing.T) {
	// Test that special characters are properly URL encoded
	domain := "example.auth0.com"
	clientID := "test-client"
	returnTo := "https://example.com/logout?message=Hello World&token=abc+123"

	logoutURL := BuildAuth0LogoutURL(domain, clientID, returnTo)

	// Parse the URL
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	// Extract the returnTo parameter
	returnToParam := parsedURL.Query().Get("returnTo")

	// The returnTo parameter should match the original (url.Values handles encoding/decoding)
	if returnToParam != returnTo {
		t.Errorf("Parameter encoding/decoding failed.\nExpected: %s\nGot: %s", returnTo, returnToParam)
	}

	// The raw query string should have properly encoded the parameters
	rawQuery := parsedURL.RawQuery
	if !strings.Contains(rawQuery, "client_id=test-client") {
		t.Errorf("Raw query should contain encoded client_id, got: %s", rawQuery)
	}
}

func TestBuildAuth0LogoutURL_AlwaysHTTPS(t *testing.T) {
	// Ensure the URL always uses HTTPS, even if domain has http://
	tests := []struct {
		domain string
	}{
		{"example.auth0.com"},
		{"http://example.auth0.com"}, // Should still result in https://
		{"dev.auth0.com"},
		{"custom-domain.com"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			logoutURL := BuildAuth0LogoutURL(tt.domain, "client", "https://example.com/")

			if !strings.HasPrefix(logoutURL, "https://") {
				t.Errorf("URL should always start with https://, got: %s", logoutURL)
			}

			// Should not have http:// (non-secure)
			if strings.Contains(logoutURL, "http://") && !strings.Contains(logoutURL, "https://") {
				t.Errorf("URL should not use HTTP, got: %s", logoutURL)
			}
		})
	}
}
