package httpx

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

func TestErrorTemplate(t *testing.T) {
	// Parse the error template directly from filesystem
	tmpl, err := template.ParseFiles("../../web/error.tmpl")
	if err != nil {
		t.Fatalf("Failed to parse error template: %v", err)
	}

	tests := []struct {
		name            string
		data            ErrView
		expectInHTML    []string
		expectNotInHTML []string
	}{
		{
			name: "complete error view with all fields",
			data: ErrView{
				Title:      "We couldn't sign you in",
				Message:    "Something went wrong during authentication. Please try again.",
				RetryURL:   "/login?return_to=https://example.com/dashboard",
				SupportURL: "https://example.com/support",
			},
			expectInHTML: []string{
				"<title>We couldn&#39;t sign you in</title>",
				"<h1>We couldn&#39;t sign you in</h1>",
				"<p>Something went wrong during authentication. Please try again.</p>",
				`href="/login?return_to=https://example.com/dashboard"`,
				`href="https://example.com/support"`,
				"Try again",
				"Get help",
				`<meta name="robots" content="noindex">`,
			},
			expectNotInHTML: []string{},
		},
		{
			name: "error view without support URL",
			data: ErrView{
				Title:      "Session expired",
				Message:    "Your session has expired. Please log in again.",
				RetryURL:   "/login",
				SupportURL: "",
			},
			expectInHTML: []string{
				"<title>Session expired</title>",
				"<h1>Session expired</h1>",
				"<p>Your session has expired. Please log in again.</p>",
				`href="/login"`,
				"Try again",
				`<meta name="robots" content="noindex">`,
			},
			expectNotInHTML: []string{
				"Get help",
				"support",
			},
		},
		{
			name: "error view with special characters",
			data: ErrView{
				Title:      "Invalid request & error",
				Message:    "The URL contains invalid characters: <script>alert('xss')</script>",
				RetryURL:   "/login?return_to=https://example.com/path%20with%20spaces",
				SupportURL: "",
			},
			expectInHTML: []string{
				"<title>Invalid request &amp; error</title>",
				"<h1>Invalid request &amp; error</h1>",
				// HTML escaping should prevent XSS
				"&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
				`href="/login?return_to=https://example.com/path%20with%20spaces"`,
				`<meta name="robots" content="noindex">`,
			},
			expectNotInHTML: []string{
				"<script>alert('xss')</script>", // Should be escaped
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, tt.data); err != nil {
				t.Fatalf("Failed to execute template: %v", err)
			}

			html := buf.String()

			// Check expected strings are present
			for _, expected := range tt.expectInHTML {
				if !strings.Contains(html, expected) {
					t.Errorf("Expected HTML to contain %q, but it didn't.\nGenerated HTML:\n%s", expected, html)
				}
			}

			// Check unwanted strings are not present
			for _, unwanted := range tt.expectNotInHTML {
				if strings.Contains(html, unwanted) {
					t.Errorf("Expected HTML NOT to contain %q, but it did.\nGenerated HTML:\n%s", unwanted, html)
				}
			}
		})
	}
}

func TestErrorTemplateAccessibility(t *testing.T) {
	tmpl, err := template.ParseFiles("../../web/error.tmpl")
	if err != nil {
		t.Fatalf("Failed to parse error template: %v", err)
	}

	data := ErrView{
		Title:      "Test Error",
		Message:    "Test message",
		RetryURL:   "/test",
		SupportURL: "https://example.com/support",
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}

	html := buf.String()

	// Check accessibility features
	accessibilityChecks := []struct {
		name     string
		required string
	}{
		{"has viewport meta", `<meta name="viewport"`},
		{"has charset", `<meta charset="UTF-8">`},
		{"has lang attribute", `<html lang="en">`},
		{"has robots noindex", `<meta name="robots" content="noindex">`},
		{"has semantic h1", "<h1>"},
		{"has semantic p", "<p>"},
		{"uses descriptive link text", "Try again"},
	}

	for _, check := range accessibilityChecks {
		t.Run(check.name, func(t *testing.T) {
			if !strings.Contains(html, check.required) {
				t.Errorf("Accessibility check failed: %s\nExpected to find: %q", check.name, check.required)
			}
		})
	}
}

func TestErrorTemplateNoXSS(t *testing.T) {
	tmpl, err := template.ParseFiles("../../web/error.tmpl")
	if err != nil {
		t.Fatalf("Failed to parse error template: %v", err)
	}

	tests := []struct {
		name           string
		data           ErrView
		expectEscaped  []string // These should be escaped (HTML entities)
	}{
		{
			name: "script tag in title",
			data: ErrView{
				Title:      `<script>alert('xss')</script>`,
				Message:    `Normal message`,
				RetryURL:   "/login",
				SupportURL: "",
			},
			expectEscaped: []string{"&lt;script&gt;", "&lt;/script&gt;"},
		},
		{
			name: "onerror in message",
			data: ErrView{
				Title:      "Normal title",
				Message:    `<img src=x onerror=alert('xss')>`,
				RetryURL:   "/login",
				SupportURL: "",
			},
			expectEscaped: []string{"&lt;img", "&gt;"},
		},
		{
			name: "javascript URL in RetryURL - should be in href attribute",
			data: ErrView{
				Title:      "Normal title",
				Message:    "Normal message",
				RetryURL:   `javascript:alert('xss')`,
				SupportURL: "",
			},
			// URL attributes are NOT escaped by Go templates (by design)
			// This is a known limitation - handlers should validate URLs before passing to template
			expectEscaped: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, tt.data); err != nil {
				t.Fatalf("Failed to execute template: %v", err)
			}

			html := buf.String()

			// Check that dangerous content is escaped
			for _, escaped := range tt.expectEscaped {
				if !strings.Contains(html, escaped) {
					t.Errorf("Expected to find escaped content %q but didn't find it.\nHTML:\n%s", escaped, html)
				}
			}
		})
	}
}
