package auth

import (
	"net/http"
)

// IdentifyPayload contains user identity information and redirect URL.
type IdentifyPayload struct {
	ReturnTo string
	Subject  string
	Email    string
	Name     string
}

// IdentifyRenderer handles rendering the authentication response.
// This interface allows for vendor-neutral identity management.
type IdentifyRenderer interface {
	Render(w http.ResponseWriter, p IdentifyPayload) error
}
