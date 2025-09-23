# Claude Code Context

## Project Overview
Authentication bridge service between Auth0 and Intercom with secure cookie-based sessions.

## Architecture
```
cmd/server/          - Main entry point
internal/
  auth/             - OAuth2/OIDC, token exchange, PKCE
  config/           - Environment configuration
  http/             - HTTP handlers (/login, /callback)
  security/         - Cookie signing, URL sanitization
```

## Key Commands
```bash
make start          # Start server (requires .env)
make test           # Run all tests
make build          # Build binary to bin/server
make restart        # Restart server
make env-print      # Show config (secrets redacted)
```

## Development Workflow
1. `cp .env.example .env` and configure
2. `source .env && make start`
3. Test changes: `make test`
4. Format: `make fmt-strict`

## Current Implementation Status
- ✅ `/login` - OAuth2 flow initiation with PKCE
- ✅ `/callback` - Token exchange with nonce verification
- 🚧 User info fetching from Auth0
- 🚧 Intercom JWT generation
- 🚧 Final redirect to Intercom

## Testing
```bash
# Run specific package tests
go test ./internal/auth -v
go test ./internal/http -v

# Test specific function
go test ./internal/auth -run TestExtractNonceFromIDToken
```

## Code Patterns

### Error Handling
- Return generic errors to clients: `{"error": "invalid_request"}`
- Log detailed errors server-side
- Never expose sensitive data in responses

### Security
- Use `crypto/subtle` for constant-time comparisons
- HMAC-SHA256 for cookie signing
- Validate all inputs before processing

### Configuration
- Required fields validated at startup
- Secrets redacted in logs
- Environment-specific defaults (dev vs prod)

## Important Files
- `internal/http/callback.go` - OAuth2 callback handler
- `internal/auth/token.go` - Token exchange client
- `internal/security/cookie.go` - Cookie signing/validation
- `internal/config/config.go` - Configuration management

## Notes
- Keep code simple and readable
- Add comments to exported functions
- All tests must pass before commit
- Follow existing patterns in codebase