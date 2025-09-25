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
- ✅ `/login` - OAuth2 flow initiation with PKCE
- ✅ `/callback` - Token exchange with nonce verification
- ✅ User info fetching from Auth0
- ✅ Integration tests with mock Auth0 server
- ✅ Security hardening (timeouts, body limits, log redaction)
- ✅ Constants refactoring (no magic strings)
- ✅ Intercom JWT generation (`internal/auth/intercom_jwt.go`)
- ✅ Vendor-neutral adapter (`internal/auth/adapter.go`)
- ✅ IntercomRenderer with HTML template (`internal/auth/intercom_renderer.go`)
- ✅ Embedded templates for production deployment
- ✅ Server logging to `server.log`
- 🚧 Wire up IntercomRenderer in callback handler
- 🚧 End-to-end testing with real Intercom

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

## Code Patterns

### Error Handling
- Return generic errors to clients: `{"error": "invalid_request"}`
- Log detailed errors server-side
- Never expose sensitive data in responses

### Security
- Use `crypto/subtle` for constant-time comparisons
- HMAC-SHA256 for cookie signing
- Validate all inputs before processing
- 1MB body size limits with `io.LimitReader`
- HTTP timeouts: 3s connect, 5s total
- Redact sensitive values in logs ([REDACTED])
- Proper OAuth2 error mapping

### Configuration
- Required fields validated at startup
- Secrets redacted in logs
- Environment-specific defaults (dev vs prod)

## Important Files
- `internal/http/callback.go` - OAuth2 callback handler
- `internal/http/callback_integration_test.go` - Integration tests
- `internal/http/router.go` - HTTP routing and middleware
- `internal/http/constants.go` - HTTP package constants
- `internal/auth/token.go` - Token exchange with Auth0
- `internal/auth/userinfo.go` - User info fetching
- `internal/auth/constants.go` - Auth package constants
- `internal/security/cookie.go` - Cookie signing/validation
- `internal/config/config.go` - Configuration management

## Notes
- Keep code simple and readable
- Add comments to exported functions
- All tests must pass before commit (`make test`)
- Follow existing patterns in codebase
- Use constants from constants.go files
- Run `make fmt-strict` before committing
- Check logs are not exposing secrets