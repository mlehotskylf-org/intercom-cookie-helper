// Package httpx provides HTTP handlers and middleware for the authentication flow.
package httpx

// HTTP Routes
const (
	// RouteLogin is the endpoint for initiating OAuth2 login flow
	RouteLogin = "/login"
	// RouteCallback is the endpoint for OAuth2 callback handling
	RouteCallback = "/callback"
	// RouteHealth is the endpoint for health checks
	RouteHealth = "/health"
)

// Content Types
const (
	// ContentTypeJSON is the MIME type for JSON responses with UTF-8 charset
	ContentTypeJSON = "application/json; charset=utf-8"
	// ContentTypeHTML is the MIME type for HTML responses
	ContentTypeHTML = "text/html; charset=utf-8"
	// ContentTypeFormURLEncoded is the MIME type for URL-encoded form data
	ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"
)

// HTTP Headers
const (
	// HeaderContentType is the Content-Type header name
	HeaderContentType = "Content-Type"
	// HeaderLocation is the Location header name for redirects
	HeaderLocation = "Location"
	// HeaderReferer is the Referer header name
	HeaderReferer = "Referer"
)

// Template Paths
const (
	// TemplateCallbackSuccess is the path to the success callback template
	TemplateCallbackSuccess = "web/callback-ok.tmpl"
	// TemplateError is the path to the error page template
	TemplateError = "web/error.tmpl"
	// TemplateCallbackSuccessAbs is the absolute path for Docker containers
	TemplateCallbackSuccessAbs = "/web/callback-ok.tmpl"
	// TemplateErrorAbs is the absolute path for Docker containers
	TemplateErrorAbs = "/web/error.tmpl"
)

// OAuth2/OIDC Endpoints
const (
	// OAuth2TokenPath is the token exchange endpoint path
	OAuth2TokenPath = "/oauth/token"
	// OAuth2UserInfoPath is the userinfo endpoint path
	OAuth2UserInfoPath = "/userinfo"
	// OAuth2AuthorizePath is the authorization endpoint path
	OAuth2AuthorizePath = "/authorize"
)

// Error Messages (for user-facing errors)
const (
	// ErrorMsgSessionExpired is shown when the transaction cookie is invalid/expired
	ErrorMsgSessionExpired = "Your session has expired. Please try again."
	// ErrorMsgAuthFailed is shown when authentication fails
	ErrorMsgAuthFailed = "Authentication failed. Please try again."
	// ErrorMsgSecurityValidation is shown when security checks fail
	ErrorMsgSecurityValidation = "Security validation failed. Please try again."
	// ErrorMsgMissingParams is shown when required parameters are missing
	ErrorMsgMissingParams = "Missing required authentication parameters."
	// ErrorMsgServerConfig is shown when there's a server configuration error
	ErrorMsgServerConfig = "Server configuration error."
	// ErrorMsgTokenValidation is shown when token validation fails
	ErrorMsgTokenValidation = "Token validation failed. Please try again."
	// ErrorMsgUserInfoFetch is shown when fetching user info fails
	ErrorMsgUserInfoFetch = "Unable to fetch user information. Please try again."
	// ErrorMsgUserInfoIncomplete is shown when user info is incomplete
	ErrorMsgUserInfoIncomplete = "User information incomplete. Please try again."
	// ErrorMsgLoadTemplate is shown when template loading fails
	ErrorMsgLoadTemplate = "Failed to load success page."
	// ErrorMsgConfigUnavailable is shown when configuration is not available
	ErrorMsgConfigUnavailable = "Configuration not available."
)
