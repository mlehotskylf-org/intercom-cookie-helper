package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
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

// IntercomRenderer implements IdentifyRenderer for Intercom authentication.
type IntercomRenderer struct {
	AppID  string
	Secret []byte
	TTL    time.Duration
}

// Render creates an Intercom JWT and redirects to the return URL with the token.
func (r *IntercomRenderer) Render(w http.ResponseWriter, p IdentifyPayload) error {
	// Validate required fields
	if r.AppID == "" {
		return fmt.Errorf("intercom app ID is required")
	}
	if len(r.Secret) == 0 {
		return fmt.Errorf("intercom secret is required")
	}
	if p.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	if p.ReturnTo == "" {
		return fmt.Errorf("return URL is required")
	}

	// Create JWT claims
	now := time.Now()
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute // Default TTL
	}

	claims := IntercomClaims{
		UserID: p.Subject,
		Email:  p.Email,
		Name:   p.Name,
		Iat:    now.Unix(),
		Exp:    now.Add(ttl).Unix(),
	}

	// Mint the JWT
	token, err := MintIntercomJWT(r.Secret, claims)
	if err != nil {
		return fmt.Errorf("failed to mint JWT: %w", err)
	}

	// Parse return URL to add token
	returnURL, err := url.Parse(p.ReturnTo)
	if err != nil {
		return fmt.Errorf("invalid return URL: %w", err)
	}

	// Add token to query parameters
	q := returnURL.Query()
	q.Set("intercom_token", token)
	returnURL.RawQuery = q.Encode()

	// Redirect to the return URL with token
	w.Header().Set("Location", returnURL.String())
	w.WriteHeader(http.StatusFound)

	return nil
}
