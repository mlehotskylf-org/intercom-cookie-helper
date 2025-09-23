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
- Requires HTTPS referrer from allowed hosts
- Empty referrer allowed (direct navigation)
- Invalid referrer returns 403

## Error Handling

### Information Leak Prevention
- Generic client errors: `{"error": "invalid_request"}`
- Detailed server-side logging only
- Never echo user input in errors
- No stack traces in responses

### Timing Attack Prevention
- Constant-time string comparisons for:
  - State parameter validation
  - Nonce verification
  - Cookie signature validation

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
- Structured logging
- No sensitive data in logs
- Request IDs for tracing