package httpx

import "net/http"

// WithIdentifyCSP adds Content Security Policy header for the Intercom identify page.
// This CSP is specific to the identify page which loads Intercom's widget.
// It allows Intercom assets while maintaining tight security policy.
//
// NOTE: This is route-specific CSP that must stay in the application because it
// requires knowledge of Intercom's domain requirements. Generic CSP policies
// should be set at API Gateway/Load Balancer level.
func WithIdentifyCSP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Content Security Policy - Allow Intercom assets
		// default-src 'self' - Only load resources from same origin by default
		// script-src - Allow scripts from self, inline scripts (for identify page logic), Intercom widget, and Intercom CDN
		//   NOTE: 'unsafe-inline' is required for the inline scripts in identify_intercom.tmpl
		//   TODO(Security): Consider nonce-based CSP in future for better security
		// connect-src - Allow connections to self and all Intercom APIs/websockets
		// img-src - Allow images from self, data URIs, and Intercom CDN
		// style-src - Allow styles from self and inline styles (required by Intercom)
		// frame-ancestors 'none' - Prevent this page from being framed (clickjacking protection)
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' https://widget.intercom.io https://js.intercomcdn.com; " +
			"connect-src 'self' https://*.intercom.io https://api-iam.intercom.io; " +
			"img-src 'self' data: https://*.intercomcdn.com; " +
			"style-src 'self' 'unsafe-inline'; " +
			"frame-ancestors 'none'"

		w.Header().Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}
