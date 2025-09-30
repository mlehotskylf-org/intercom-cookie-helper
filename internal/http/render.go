package httpx

import (
	"html/template"
	"log"
	"net/http"
)

// errorTemplate is the parsed error page template, loaded at init time.
var errorTemplate *template.Template

func init() {
	var err error
	// Try relative path from project root (for production/running server)
	errorTemplate, err = template.ParseFiles("web/error.tmpl")
	if err != nil {
		// Try relative path from internal/http (for tests)
		errorTemplate, err = template.ParseFiles("../../web/error.tmpl")
		if err != nil {
			log.Printf("WARNING: Failed to parse error template: %v", err)
			// Don't panic - allow server to start even if template is missing during development
			// Production deployments should ensure templates are present
		}
	}
}

// renderErrorHTML renders an error page with proper headers and template execution.
// This centralizes error page rendering to ensure consistent behavior across all error scenarios.
//
// Sets the following headers:
//   - Content-Type: text/html; charset=utf-8
//   - Cache-Control: no-store (prevents caching of error pages)
//
// Parameters:
//   - w: ResponseWriter to write the error page to
//   - status: HTTP status code (e.g., 400, 500)
//   - v: ErrView containing the error details to display
func renderErrorHTML(w http.ResponseWriter, status int, v ErrView) {
	// Set headers before writing status
	w.Header().Set(HeaderContentType, ContentTypeHTML)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	// If template failed to load, write a basic error message
	if errorTemplate == nil {
		fallbackHTML := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<h1>` + v.Title + `</h1>
<p>` + v.Message + `</p>
<a href="` + v.RetryURL + `">Try again</a>
</body>
</html>`
		w.Write([]byte(fallbackHTML))
		log.Printf("ERROR: Error template not loaded, using fallback HTML")
		return
	}

	// Execute the template
	if err := errorTemplate.Execute(w, v); err != nil {
		log.Printf("ERROR: Failed to execute error template: %v", err)
		// At this point headers and status are already written, can't recover
	}
}
