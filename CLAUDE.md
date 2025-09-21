# Claude Code Context

## Project Overview
This is an Intercom cookie helper service that provides authentication flow between Auth0 and Intercom, managing secure cookie-based sessions.

## Architecture
- **Language**: Go 1.23
- **Router**: Chi v5 (github.com/go-chi/chi/v5)
- **Structure**:
  - `cmd/server/` - Main application entry point
  - `internal/config/` - Configuration management with env vars
  - `internal/http/` - HTTP router and handlers (package httpx)
  - `internal/security/` - Security-related functionality
  - `web/` - Static web assets

## Key Commands
```bash
make start       # Start the server (requires env vars)
make stop        # Stop the running server
make restart     # Restart the server
make build       # Build binary to bin/server
make test        # Run all tests
make fmt         # Format with gofmt
make fmt-strict  # Format with gofumpt then gofmt
make docker      # Build Docker image (intercom-cookie-helper:dev)
make env-print   # Print current configuration (secrets redacted)
```

## Required Environment Variables
For development (`ENV=dev`):
- `APP_HOSTNAME` - Application hostname (e.g., intercom-auth.example.com)
- `COOKIE_DOMAIN` - Cookie domain eTLD+1 (e.g., .example.com)
- `INTERCOM_APP_ID` - Intercom application ID
- `INTERCOM_JWT_SECRET` - Intercom JWT secret (dev only)
- `AUTH0_DOMAIN` - Auth0 domain
- `AUTH0_CLIENT_ID` - Auth0 client ID
- `AUTH0_CLIENT_SECRET` - Auth0 client secret (dev only)
- `COOKIE_SIGNING_KEY` - Hex or base64 encoded key for cookie signing

Optional:
- `PORT` - Server port (default: 8080)
- `ENV` - Environment: dev/staging/prod (default: dev)
- `ALLOWED_RETURN_HOSTS` - CSV list of allowed redirect hosts
- `ALLOWED_QUERY_PARAMS` - CSV list of params to preserve (default: utm_campaign,utm_source)
- `AUTH0_REDIRECT_PATH` - Auth0 callback path (default: /callback)
- `REDIRECT_TTL` - Redirect URL validity (default: 30m)
- `SESSION_TTL` - Session cookie lifetime (default: 24h)
- `LOG_LEVEL` - info/debug/warn/error (default: info)
- `ENABLE_HSTS` - Enable HSTS header (default: false in dev, true in prod)

## Configuration Notes
- In production (`ENV=prod`), secrets (INTERCOM_JWT_SECRET, AUTH0_CLIENT_SECRET) must come from secret manager, not env vars
- The config validation runs in dev mode but is relaxed in prod to allow secret manager integration
- CSV values are trimmed, lowercased, and deduplicated automatically
- Cookie signing key accepts hex or base64 encoding
- **Automatic normalization**: Hostnames lowercased, wildcard patterns preprocessed for fast matching
- **Secret redaction**: Configuration output automatically masks sensitive values as "***"

## Testing
- Unit tests exist for config helpers and health endpoint
- Run specific test: `go test ./internal/config -run TestParseCSV`
- All tests: `make test`

## Docker
- Multi-stage build with distroless final image
- Runs as non-root user
- Build: `make docker`
- Run: `docker run -p 8081:8080 -e APP_HOSTNAME=... intercom-cookie-helper:dev`

## Development Workflow
1. Set required environment variables (consider using `.env` file with direnv)
2. `make start` to run the server
3. `make test` before committing
4. `make fmt-strict` to format code consistently

## Current Endpoints
- `GET /healthz` - Health check, returns `{"status":"ok"}`

## Logging
Custom key-value logging with RFC3339 timestamps and log level filtering. Example:
```
2025-09-20T12:00:00Z event:start env:dev port:8080 hostname:localhost cookie_domain:.localhost
```
- **Log levels**: debug, info, warn, error with threshold-based filtering
- **Startup logs**: Configuration displayed with automatic secret redaction
- **Structured format**: All logs use consistent key:value format for easy parsing

## Configuration Management

### Debug Commands
```bash
# Validate configuration and exit
./bin/server --check-config

# Print current configuration with secrets redacted
make env-print
./bin/server --env-print
```

### Key Features
- **Actionable validation errors**: Error messages include specific examples and guidance
- **Hostname normalization**: APP_HOSTNAME validates as host-only (no scheme/port)
- **Wildcard preprocessing**: ALLOWED_RETURN_HOSTS supports `*.example.com` patterns
- **Safe configuration output**: Secrets automatically redacted in logs and debug output
- **Structured logs**: All configuration logged at startup with redacted secrets

### Error Examples
```
APP_HOSTNAME is required (set to your domain, e.g., intercom-auth.example.com)
COOKIE_DOMAIN must start with '.' for subdomain sharing (got "example.com", use ".example.com")
PORT must be 1-65535 (got "99999")
```

## Exit Codes
- 0 - Normal shutdown
- 1 - Fatal server error (e.g., port binding failed)
- 2 - Configuration/validation error