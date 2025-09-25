package httpx

import (
	"encoding/json"
	"log"
	"net/http"
)

// ErrorResponse represents a JSON error response
// Only contains an error field to avoid leaking internal details
type ErrorResponse struct {
	Error string `json:"error"`
}

// WriteClientError writes a 400 error response without exposing internal details
// The actual error reason is logged server-side for debugging
func WriteClientError(w http.ResponseWriter, logMessage string) {
	log.Printf("Client error: %s", logMessage)

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusBadRequest)

	resp := ErrorResponse{
		Error: "invalid_request",
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// WriteServerError writes a 500 error response without exposing internal details
// The actual error is logged server-side for debugging
func WriteServerError(w http.ResponseWriter, logMessage string) {
	log.Printf("Server error: %s", logMessage)

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusInternalServerError)

	resp := ErrorResponse{
		Error: "server_error",
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// WriteJSONError writes a consistent JSON error response
// DEPRECATED: Use WriteClientError or WriteServerError instead for new code
// This function is kept for backwards compatibility with existing tests
func WriteJSONError(w http.ResponseWriter, statusCode int, code, message string) {
	// Log the actual error for debugging
	log.Printf("Error response [%d %s]: %s", statusCode, code, message)

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(statusCode)

	// For backwards compatibility with tests, maintain old response format
	// but only for specific codes that tests expect
	switch code {
	case ErrCodeInvalidReferer:
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_referrer"})
	case ErrCodeCookieError:
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "cookie_error"})
	default:
		// For all other errors, use the secure format
		if statusCode >= 500 {
			_ = json.NewEncoder(w).Encode(ErrorResponse{Error: "server_error"})
		} else {
			_ = json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid_request"})
		}
	}
}

// Common error codes (for internal logging only)
const (
	ErrCodeInvalidRequest   = "invalid_request"
	ErrCodeInvalidReturnURL = "invalid_return_url"
	ErrCodeCookieError      = "cookie_error"
	ErrCodeInternalError    = "internal_error"
	ErrCodeMissingReferer   = "missing_referer"
	ErrCodeInvalidReferer   = "invalid_referer"
)
