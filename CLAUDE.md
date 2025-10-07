# Claude Code Context

## Project Overview
Authentication bridge service between Auth0 and Intercom with secure cookie-based sessions.

## Architecture
```
cmd/server/          - Main entry point
internal/
  auth/             - OAuth2/OIDC, token exchange, PKCE, userinfo
    constants.go    - Package constants to avoid circular deps
  config/           - Environment configuration, validation
  http/             - HTTP handlers, routing, middleware
    constants.go    - HTTP constants (routes, headers, errors)
  security/         - Cookie signing, URL sanitization, HMAC
```

## Key Commands
```bash
make start          # Start server (requires .env)
make test           # Run all tests (sequential with -p=1)
make test-security  # Run security package tests
make test-http      # Run HTTP package tests
make build          # Build binary to bin/server
make restart        # Stop and restart server
make env-print      # Show config (secrets redacted)
make env-check      # Validate configuration
make fmt            # Format code with gofmt
make fmt-strict     # Format with gofumpt + gofmt
```

## Development Workflow
1. `cp .env.example .env` and configure
2. `source .env && make start`
3. Test changes: `make test`
4. Format: `make fmt-strict`

## Current Implementation Status

**Core Features:**
- OAuth2/PKCE flow with Auth0 (`/login`, `/callback`, `/logout`)
- Intercom Identity Verification (JWT from Auth0 Action, not self-generated)
- Query parameter priority: `return_to` > Referer header
- Localhost detection: HTTP for localhost, HTTPS for deployed environments
- Content negotiation: HTML error pages for browsers, JSON for APIs

**Security:**
- Referer validation (HTTPS-only, IP rejection, host allowlist)
- Fail-closed validation (validates before state changes)
- PII redaction in logs (no emails/tokens, host-only URLs)
- Fuzz testing for security-critical parsers
- Global security headers (CSP, HSTS, Referrer-Policy, Cache-Control)
- Constant-time comparisons for secrets

**Production Ready:**
- 85%+ test coverage (unit + integration + fuzz tests)
- In-memory metrics with atomic counters
- Embedded templates for deployment
- Health checks (basic + deep validation)
- Structured logging with error codes

## Testing
```bash
# Run all tests (with sequential execution to avoid conflicts)
make test

# Run specific package tests
go test ./internal/auth -v
go test ./internal/http -v
go test ./internal/security -v

# Test specific function
go test ./internal/auth -run TestExtractNonceFromIDToken

# Run integration tests
go test ./internal/http -run TestCallbackIntegration -v
```

### Test Parallelism Note
Tests run with `-p=1` flag to prevent parallel execution conflicts.
Tests complete in ~10-12s on modern hardware.

### Fuzz Testing
```bash
# Run fuzz tests for referer parsing (5 seconds)
go test -run Fuzz -fuzz=FuzzRefererParsing -fuzztime=5s ./internal/http

# Run fuzz tests for URL parsing (5 seconds)
go test -run Fuzz -fuzz=FuzzReturnURLParsing -fuzztime=5s ./internal/http
```

## Code Patterns

### Error Handling
- Use centralized error helpers: `BadRequest()`, `TooManyRequests()`, `ServerError()`
- Return generic errors to clients: `{"error": "invalid_request"}`
- Content negotiation: HTML error pages for browsers (`Accept: text/html`), JSON for APIs
- All JSON responses include `Content-Type: application/json; charset=utf-8`
- Log detailed errors server-side with structured logging
- Never expose sensitive data in responses

### Security
- Use `crypto/subtle` for constant-time comparisons
- HMAC-SHA256 for cookie signing
- Validate all inputs before processing (fail-closed)
- 1MB body size limits with `io.LimitReader`
- HTTP timeouts: 3s connect, 5s total
- Redact sensitive values in logs ([REDACTED])
- Proper OAuth2 error mapping
- CSP headers for Intercom integration ('unsafe-inline' for identify template)
- Referer validation: HTTPS-only, IP literal rejection, host allowlist
- Port normalization: only HTTPS port 443 allowed
- Global security headers: Referrer-Policy, X-Content-Type-Options, Permissions-Policy, HSTS
- Cache-Control headers: `no-store, max-age=0` + `Pragma: no-cache` on all auth pages
- PII redaction: log booleans (has_email), not actual values
- Log return_host only, not full returnTo URLs
- Fuzz tested parsing functions to prevent panics

### Configuration
- Required fields validated at startup
- Secrets redacted in logs
- Environment-specific defaults (dev vs prod)

## Important Files
- `internal/http/callback.go` - OAuth2 callback handler with logging
- `internal/http/callback_integration_test.go` - Integration tests
- `internal/http/callback_identify_test.go` - Renderer path tests
- `internal/http/callback_error_test.go` - Error scenario tests for callback
- `internal/http/router.go` - HTTP routing and security middleware
- `internal/http/logout.go` - Logout handler with cookie clearing
- `internal/http/logout_test.go` - Logout tests with cookie verification
- `internal/http/middleware.go` - Referer validation middleware
- `internal/http/errors.go` - Centralized error response helpers with noStore()
- `internal/http/errors_test.go` - Error helper tests
- `internal/http/errors_integration_test.go` - Content negotiation tests
- `internal/http/render.go` - Error page HTML rendering
- `internal/http/render_test.go` - Render tests
- `internal/http/metrics.go` - Lightweight in-memory metrics
- `internal/http/csp.go` - Route-specific CSP for Intercom identify page
- `internal/http/middleware_fuzz_test.go` - Fuzz tests for security-critical parsing
- `internal/http/login_integration_test.go` - Login flow integration tests
- `internal/http/login_cache_test.go` - Login cache header tests
- `internal/http/callback_cache_test.go` - Callback cache header tests
- `internal/http/localhost_test.go` - Localhost HTTP vs HTTPS behavior tests
- `internal/http/constants.go` - HTTP package constants
- `internal/auth/token.go` - Token exchange with Auth0
- `internal/auth/userinfo.go` - User info fetching
- `internal/auth/intercom_renderer.go` - Intercom identify page renderer
- `internal/auth/intercom_renderer_test.go` - Renderer tests
- `internal/auth/templates/identify_intercom.tmpl` - Identify page template with fallback
- `internal/auth/constants.go` - Auth package constants
- `internal/security/cookie.go` - Cookie signing/validation
- `internal/security/redirects.go` - URL sanitization and validation
- `internal/config/config.go` - Configuration management
- `internal/config/helpers.go` - IsLocalhost() and other config helpers
- `internal/config/helpers_test.go` - Config helper tests
- `docs/GATEWAY_HEADERS.md` - API Gateway/LB configuration guide
- `web/error.tmpl` - Error page template
- `web/logout.tmpl` - Logout page template

## Notes
- Keep code simple and readable
- Add comments to exported functions
- All tests must pass before commit (`make test`)
- Follow existing patterns in codebase
- Use constants from constants.go files
- Run `make fmt-strict` before committing
- Check logs are not exposing secrets

## Known Issues
- **Content negotiation in middleware**: The `BadRequest()` function in `internal/http/errors.go` always returns JSON, even when `Accept: text/html` is present. This affects middleware errors (like referer validation). See `internal/http/errors_integration_test.go:TestErrorContentNegotiation_LoginWithReferer` for details. The login and callback handlers properly support content negotiation.