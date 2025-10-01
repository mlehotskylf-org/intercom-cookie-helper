package httpx

import (
	"net/http"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/auth"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/security"
)

// logoutHandler handles the logout endpoint.
// Clears the helper cookies (transaction and redirect) and returns the user to a safe page.
// Does not perform IdP logout - only clears local session cookies.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get config from context
	cfg, ok := GetConfigFromContext(r.Context())
	if !ok {
		ServerError(w, r)
		return
	}

	// Check if logout is enabled
	if !cfg.EnableLogout {
		http.NotFound(w, r)
		return
	}

	// Clear transaction cookie (even if not present)
	txnOpts := auth.TxnOpts{
		Domain:     cfg.CookieDomain,
		TTL:        cfg.TxnTTL,
		Skew:       cfg.TxnSkew,
		Secure:     cfg.Env == "prod",
		SigningKey: cfg.CookieSigningKey,
	}
	auth.ClearTxnCookie(w, txnOpts)

	// Clear redirect cookie (even if not present)
	security.ClearRedirectCookie(w, cfg.CookieDomain)

	// Prevent caching of auth pages
	noStore(w)

	// Check if HTML is accepted
	if acceptsHTML(r) {
		// Render HTML logout page
		renderLogoutHTML(w, r, cfg)
	} else {
		// Return 204 No Content for API clients
		w.WriteHeader(http.StatusNoContent)
	}
}

// renderLogoutHTML renders a simple logout confirmation page.
func renderLogoutHTML(w http.ResponseWriter, r *http.Request, cfg config.Config) {
	w.Header().Set(HeaderContentType, ContentTypeHTML)
	w.WriteHeader(http.StatusOK)

	// Try to get return URL from Referer header, fall back to safe default
	returnURL := r.Header.Get("Referer")
	if returnURL == "" {
		returnURL = safeDefaultURL(cfg)
	} else {
		// Validate and sanitize the referer URL
		sanitizer, err := cfg.BuildSanitizer()
		if err != nil {
			// If sanitizer can't be built, use safe default
			returnURL = safeDefaultURL(cfg)
		} else {
			// Try to sanitize the referer - if it fails, use safe default
			sanitized, err := sanitizer.SanitizeReturnURL(returnURL)
			if err != nil {
				returnURL = safeDefaultURL(cfg)
			} else {
				returnURL = sanitized
			}
		}
	}

	// Build Auth0 IdP logout link section (only if enabled)
	auth0LinkSection := ""
	if cfg.EnableAuth0Logout {
		auth0LogoutURL := auth.BuildAuth0LogoutURL(cfg.Auth0Domain, cfg.Auth0ClientID, returnURL)
		auth0LinkSection = `
        <div class="link">
            <a href="` + auth0LogoutURL + `">Sign out of your account</a>
        </div>`
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <title>Signed Out</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .container {
            text-align: center;
            padding: 2rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            max-width: 400px;
        }
        h1 {
            color: #333;
            font-size: 24px;
            margin-bottom: 1rem;
        }
        p {
            color: #666;
            margin-bottom: 2rem;
        }
        .button {
            display: inline-block;
            padding: 12px 24px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-weight: 500;
            margin: 0.5rem;
        }
        .button:hover {
            background-color: #0056b3;
        }
        .button-secondary {
            background-color: #6c757d;
        }
        .button-secondary:hover {
            background-color: #5a6268;
        }
        .buttons {
            margin-top: 1rem;
        }
        .link {
            display: block;
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid #e0e0e0;
        }
        .link a {
            color: #007bff;
            text-decoration: none;
            font-size: 14px;
        }
        .link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Signed out</h1>
        <p>You have been signed out.</p>
        <div class="buttons">
            <a href="` + returnURL + `" class="button">Return</a>
        </div>` + auth0LinkSection + `
    </div>
</body>
</html>`

	w.Write([]byte(html))
}
