package auth

import (
	"net/url"
)

// BuildAuth0LogoutURL constructs the Auth0 logout URL for IdP logout.
// This logs the user out from Auth0 (the Identity Provider) and redirects them back.
//
// Parameters:
//   - domain: Auth0 domain (e.g., "example.auth0.com")
//   - clientID: Auth0 client ID
//   - returnTo: Absolute HTTPS URL where to redirect after logout
//
// Returns: Full Auth0 logout URL with properly encoded parameters
//
// Note: This function only builds the URL - it does not perform the redirect.
// The caller should present this as a link to the user, not auto-redirect.
//
// Reference: https://auth0.com/docs/api/authentication#logout
func BuildAuth0LogoutURL(domain, clientID, returnTo string) string {
	// Build base URL
	baseURL := "https://" + domain + "/v2/logout"

	// Build query parameters with proper encoding
	params := url.Values{}
	params.Set("client_id", clientID)
	if returnTo != "" {
		params.Set("returnTo", returnTo)
	}

	// Construct full URL with encoded query string
	return baseURL + "?" + params.Encode()
}
