package httpx

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse represents a JSON error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

// WriteJSONError writes a consistent JSON error response
func WriteJSONError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    code,
	}

	// Ignore encoding errors for error responses
	_ = json.NewEncoder(w).Encode(resp)
}

// Common error codes
const (
	ErrCodeInvalidRequest   = "invalid_request"
	ErrCodeInvalidReturnURL = "invalid_return_url"
	ErrCodeCookieError      = "cookie_error"
	ErrCodeInternalError    = "internal_error"
	ErrCodeMissingReferer   = "missing_referer"
	ErrCodeInvalidReferer   = "invalid_referer"
)
