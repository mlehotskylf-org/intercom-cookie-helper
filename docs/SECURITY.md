# Security Features

## OAuth2/OIDC Security

### PKCE (Proof Key for Code Exchange)
Prevents authorization code interception attacks:
- Generates cryptographically random `code_verifier` (43-128 chars)
- Sends SHA256 hash as `code_challenge` in authorization request
- Validates with `code_verifier` during token exchange

### Nonce Verification
Prevents replay attacks:
- Random nonce generated for each authentication request
- Embedded in ID token by Auth0
- Verified using constant-time comparison after token exchange

### State Parameter
Prevents CSRF attacks:
- Cryptographically random state for each auth request
- Stored in signed transaction cookie
- Validated with constant-time comparison in callback

## Cookie Security

### HMAC-SHA256 Signing
All cookies are cryptographically signed:
- Prevents tampering
- Supports key rotation with secondary key
- 3500-byte size limit per cookie

### Security Flags
```
HttpOnly: true      // No JavaScript access
SameSite: Lax      // CSRF protection
Secure: true       // HTTPS only (production)
Domain: .example   // Scoped to domain
```

### Transaction Cookie (`ic_oidc_txn`)
Stores OAuth2 flow parameters:
- PKCE code_verifier
- State parameter
- Nonce for ID token validation
- 10-minute TTL with clock skew tolerance

### Redirect Cookie (`ic_redirect`)
Stores sanitized return URL:
- HMAC signed but not encrypted
- 30-minute TTL
- Host validation before use

## URL Security

### Host Allowlisting
- Configured via `ALLOWED_RETURN_HOSTS`
- Supports wildcards (`*.example.com`)
- Case-insensitive matching
- Rejects unallowed hosts

### URL Sanitization
- HTTPS-only enforcement
- Strips unauthorized query parameters
- Removes fragments
- Validates against open redirects
- Rejects non-standard ports
- Prevents JavaScript/data URIs

### Referrer Validation
For `/login` endpoint:
- HTTPS-only enforcement (rejects http://, ftp://, etc.)
- IP literal rejection (no IPv4/IPv6 addresses)
- Host allowlist validation (with wildcard support)
- Empty referrer allowed (Intercom widgets, privacy policies)
- Invalid referrer returns 400 with JSON error
- Structured logging: `event=ref_check ok=true/false reason=...`

## Error Handling

### Centralized Error Responses
- `BadRequest(w, r, reason)` - 400 with generic `invalid_request` error
- `TooManyRequests(w, r)` - 429 with `rate_limited` error
- `ServerError(w, r)` - 500 with `server_error` error
- All JSON responses: `Content-Type: application/json; charset=utf-8`

### Information Leak Prevention
- Generic client errors: `{"error": "invalid_request"}`
- Detailed server-side logging only with structured format
- Never echo user input in errors
- No stack traces in responses
- Host-only logging for URLs (prevents PII leakage)

### Timing Attack Prevention
- Constant-time string comparisons for:
  - State parameter validation
  - Nonce verification
  - Cookie signature validation

### Fail-Closed Validation
- `return_to` URL validated before setting any cookies
- Invalid input returns 400 with no state changes
- Prevents cookie pollution attacks

## Transport Security

### HSTS (HTTP Strict Transport Security)
When `ENABLE_HSTS=true`:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### HTTPS Enforcement
- All redirect URLs must be HTTPS
- Cookies marked `Secure` in production
- Referrer must be HTTPS

## Configuration Security

### Secret Management
- Secrets redacted in logs/output
- Production requires secret manager (not env vars)
- Minimum 32-byte signing keys

### Validation
- Startup validation of all required fields
- Actionable error messages
- Environment-specific requirements

## Best Practices

### Defense in Depth
Multiple layers of security:
1. OAuth2 with PKCE
2. Signed cookies
3. Host allowlisting
4. CSRF tokens (state/nonce)
5. Timing attack prevention

### Secure Defaults
- HSTS enabled in production
- Strict cookie flags
- Conservative TTLs
- Minimal error disclosure

### Auditability
- Structured logging with observability
- PII redaction (email logged as boolean `has_email`)
- URL redaction (full paths logged as `return_host` only)
- Token/JWT redaction (never logged)
- Request IDs for tracing
- Redacted sensitive values ([REDACTED])

## HTTP Security

### Request Limits
- 1MB body size limit with `io.LimitReader`
- Prevents DoS via large payloads
- Applied to Auth0 API responses

### Timeouts
- 3-second connection timeout
- 5-second total request timeout
- Applied to all external HTTP calls
- Prevents hanging connections

### OAuth2 Error Mapping
- Proper handling of Auth0 error codes
- Maps `invalid_grant`, `invalid_client`, etc.
- User-friendly error messages
- Detailed server-side logging

## Content Security Policy

### Intercom Widget CSP
Route-specific CSP for `/callback` endpoint:
- `script-src`: Allows Intercom widget scripts with `'unsafe-inline'`
- `connect-src`: Allows Intercom API and WebSocket connections (`wss://`)
- `img-src`: Allows Intercom CDN images
- `style-src`: Allows inline styles for widget
- `frame-ancestors 'none'`: Prevents clickjacking

### CSP Directives
```
default-src 'self';
script-src 'self' 'unsafe-inline' https://widget.intercom.io https://js.intercomcdn.com;
connect-src 'self' https://*.intercom.io https://api-iam.intercom.io wss://*.intercom.io;
img-src 'self' data: https://*.intercomcdn.com;
style-src 'self' 'unsafe-inline';
frame-ancestors 'none'
```

Note: `'unsafe-inline'` is required for Intercom widget functionality. Generic security headers should be moved to API Gateway/LB (see [GATEWAY_HEADERS.md](GATEWAY_HEADERS.md)).

## Global Security Headers

Applied to all responses via `securityHeadersMiddleware`:
- `Referrer-Policy: strict-origin-when-cross-origin` - Controls referrer information
- `X-Content-Type-Options: nosniff` - Prevents MIME type sniffing
- `Permissions-Policy: geolocation=(), microphone=(), camera=()` - Disables unnecessary features
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` - HSTS (when enabled)

Note: These headers are currently set in the application but should be migrated to API Gateway/Load Balancer for centralized security policy.

## Observability & Metrics

### In-Memory Metrics
Lightweight atomic counters for monitoring:
- Login flow: `start`, `bad_referer`, `bad_return`, `cookie_fail`, `ok`
- Callback flow: `start`, `state_mismatch`, `exchange_fail`, `nonce_fail`, `userinfo_fail`, `cookie_fail`, `ok`
- Endpoint: `GET /metrics/dev` (non-prod only)
- Thread-safe with `sync/atomic`

### Structured Logging
- Event-based format: `event=ref_check ok=true referer_host=example.com`
- Key-value pairs for easy parsing
- No PII in logs (host-only, boolean flags)
- Request IDs for tracing

## Testing

### Fuzz Testing
Security-critical parsing functions are fuzz tested:
- `FuzzRefererParsing` - Tests referer middleware against malicious inputs
- `FuzzReturnURLParsing` - Tests URL sanitization against attacks
- Seed corpus includes: null bytes, control characters, IP literals, scheme attacks, port overflows
- Validates no panics occur with malformed input

### Integration Testing
- Negative test cases for bad referer (400, no cookies)
- Negative test cases for bad return_to (400, no cookies)
- Mixed-case host and trailing dot normalization
- Key rotation validation
- Metrics counter increments