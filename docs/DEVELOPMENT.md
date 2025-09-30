# Development Guide

## Getting Started

### Prerequisites
- Go 1.23 or later
- Make
- Auth0 account
- Intercom account

### Initial Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/intercom-cookie-helper.git
   cd intercom-cookie-helper
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

3. Start the server:
   ```bash
   source .env && make start
   ```

## Testing

### Run All Tests
```bash
make test
```

### Package-Specific Tests
```bash
# Auth package (token exchange, PKCE, JWT, renderer)
go test ./internal/auth -v

# HTTP handlers (login, callback, integration tests)
go test ./internal/http -v

# Security (cookies, sanitization)
go test ./internal/security -v

# Configuration
go test ./internal/config -v
```

### Test Specific Functions
```bash
# Test callback integration (full OAuth2 flow)
go test ./internal/http -run TestCallbackIntegration

# Test callback renderer path
go test ./internal/http -run TestCallbackRenderer

# Test nonce extraction
go test ./internal/auth -run TestExtractNonceFromIDToken

# Test user info parsing
go test ./internal/auth -run TestParseUserInfoFromIDToken
```

### Coverage
```bash
go test ./... -cover
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Debugging

### Configuration Issues
```bash
# Validate configuration
./bin/server --check-config

# Print configuration (secrets redacted)
make env-print
```

### URL Sanitization Testing
```bash
# Test URL sanitization
make sanitize URL="https://example.com/path?utm_source=test"
```

### Cookie Debugging (Dev Only)
```bash
# Debug redirect cookie
curl -H "Cookie: ic_redirect=<cookie-value>" \
     http://localhost:8080/debug/redirect-cookie
```

### Server Logs
```bash
# Start with debug logging
LOG_LEVEL=debug make start

# Follow logs
tail -f server.log  # If logging to file
```

## Making Changes

### Code Organization
```
internal/
  auth/       - OAuth2/OIDC logic, JWT, Intercom renderer
  config/     - Configuration management
  http/       - HTTP handlers, router, middleware, CSP
  security/   - Cookie signing, URL sanitization
```

### Adding a New Endpoint

1. Add handler in `internal/http/`:
   ```go
   func handleNewEndpoint(w http.ResponseWriter, r *http.Request) {
       // Implementation
   }
   ```

2. Register in `internal/http/router.go`:
   ```go
   r.Get("/new-endpoint", handleNewEndpoint)
   ```

3. Add tests in `internal/http/`:
   ```go
   func TestHandleNewEndpoint(t *testing.T) {
       // Test cases
   }
   ```

### Security Checklist

Before implementing new features:
- [ ] Validate all inputs
- [ ] Use constant-time comparisons for secrets
- [ ] Return generic errors to clients
- [ ] Log detailed errors server-side (with PII redaction)
- [ ] Never log email addresses, tokens, or JWTs
- [ ] Add comprehensive tests (unit + integration)
- [ ] Update documentation
- [ ] Review CSP headers if rendering HTML

## Common Tasks

### Update Dependencies
```bash
go mod tidy
go mod verify
```

### Format Code
```bash
make fmt         # Basic formatting
make fmt-strict  # Strict formatting with gofumpt
```

### Build Binary
```bash
make build       # Builds to bin/server
```

### Docker
```bash
make docker      # Build Docker image
docker run -p 8080:8080 --env-file .env intercom-cookie-helper:dev
```

## Troubleshooting

### Port Already in Use
```bash
make stop        # Stop existing server
make restart     # Or restart
```

### Invalid Configuration
Check error messages - they include specific guidance:
```
APP_HOSTNAME is required (set to your domain, e.g., auth.example.com)
COOKIE_DOMAIN must start with '.' (got "example.com", use ".example.com")
```

### Cookie Issues
- Ensure `COOKIE_DOMAIN` matches your domain
- Check cookie flags in browser DevTools
- Verify signing keys are consistent

### OAuth2 Flow Issues
- Verify Auth0 callback URL matches configuration
- Check Auth0 application settings
- Ensure PKCE is enabled in Auth0
- Review server logs for detailed errors

## Contributing

### Before Submitting

1. Run tests: `make test`
2. Format code: `make fmt-strict`
3. Update documentation if needed
4. Ensure all tests pass

### Commit Messages

Follow conventional commits:
```
feat: add user info endpoint
fix: correct nonce validation
docs: update configuration guide
test: add callback handler tests
```