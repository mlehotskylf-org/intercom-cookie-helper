# intercom-cookie-helper

A simple Go HTTP server with health check endpoint.

## Quick Start

1. Copy and configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```

2. Start the server:
   ```bash
   source .env && make start
   ```

The server will start on port 8080 (or PORT environment variable if set).

## Available Commands

```bash
make start       # Start the server
make build       # Build the server binary to bin/server
make test        # Run all tests
make fmt         # Format code with gofmt
make fmt-strict  # Format code with gofumpt and gofmt
make stop        # Stop the running server
make restart     # Stop and restart the server
make env-print   # Print current configuration (with secrets redacted)
make sanitize URL="https://example.com/path?param=value"  # Test URL sanitization
```

## API Endpoints

- `GET /healthz` - Health check endpoint
  - Returns: `200 OK` with `{"status":"ok"}`

- `GET /login?return_to=<url>` - Login endpoint with URL sanitization
  - **Referrer Guard**: Must have valid HTTPS referrer from allowed hosts
  - **URL Sanitization**: Filters query parameters and ensures HTTPS
  - Returns: `200 OK` with `{"sanitized": "https://..."}`
  - Errors: `400 Bad Request` for invalid URLs or referrers

## Configuration

Copy `.env.example` to `.env` and update with your values:

```bash
cp .env.example .env
```

### Environment Variables

#### Core Settings

- **`ENV`** - Environment mode: `dev`, `staging`, or `prod` (default: `dev`)
  - In `prod`, secrets must come from secret manager, not env vars
  - Validation is stricter in `dev` mode

- **`APP_HOSTNAME`** - Application hostname (required)
  - Example: `intercom-auth.riscv.org`
  - Used for generating absolute URLs

- **`PORT`** - Server port (default: `8080`)

- **`COOKIE_DOMAIN`** - Cookie domain for session management (required)
  - Must be eTLD+1 format (e.g., `.riscv.org`)
  - Allows cookies to be shared across subdomains

#### Security Settings

- **`ALLOWED_RETURN_HOSTS`** - CSV list of allowed redirect hosts
  - Example: `riscv.org,*.riscv.org`
  - Values are trimmed, lowercased, and deduplicated
  - Prevents open redirect vulnerabilities

- **`ALLOWED_QUERY_PARAMS`** - Query parameters to preserve during redirects
  - Default: `utm_campaign,utm_source`
  - CSV format, automatically processed

- **`COOKIE_SIGNING_KEY`** - Key for signing secure cookies (required)
  - Accepts hex or base64 encoding
  - Minimum 32 bytes recommended
  - Example hex: `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`

- **`ENABLE_HSTS`** - Enable HTTP Strict Transport Security header
  - Default: `false` in dev, `true` in prod
  - Forces HTTPS connections when enabled

#### Intercom Integration

- **`INTERCOM_APP_ID`** - Your Intercom application ID (required)
- **`INTERCOM_JWT_SECRET`** - JWT secret for Intercom authentication
  - **Dev/Staging only** - In production, use secret manager
  - Required in dev/staging environments

#### Auth0 Integration

- **`AUTH0_DOMAIN`** - Your Auth0 tenant domain (required)
  - Example: `your-tenant.auth0.com`

- **`AUTH0_CLIENT_ID`** - Auth0 application client ID (required)

- **`AUTH0_CLIENT_SECRET`** - Auth0 application client secret
  - **Dev/Staging only** - In production, use secret manager
  - Required in dev/staging environments

- **`AUTH0_REDIRECT_PATH`** - Callback path for Auth0 (default: `/callback`)

#### Timeout Settings

- **`REDIRECT_TTL`** - How long redirect URLs remain valid
  - Default: `30m`
  - Format: Go duration string (e.g., `30m`, `1h`, `24h`)

- **`SESSION_TTL`** - OIDC transaction cookie lifetime
  - Default: `24h`
  - Controls session duration

#### Observability

- **`LOG_LEVEL`** - Application log level
  - Options: `debug`, `info`, `warn`, `error`
  - Default: `info`
  - Controls which log messages are displayed at startup and runtime

### Development vs Production

| Setting | Development | Production |
|---------|------------|------------|
| `ENV` | `dev` | `prod` |
| `INTERCOM_JWT_SECRET` | Set via env var | Use secret manager |
| `AUTH0_CLIENT_SECRET` | Set via env var | Use secret manager |
| `ENABLE_HSTS` | `false` (default) | `true` (default) |
| Validation | Strict (all fields required) | Relaxed (allows secret manager) |

### Example Development Setup

For local development, create a `.env` file:

```bash
ENV=dev
APP_HOSTNAME=localhost
PORT=8080
COOKIE_DOMAIN=.localhost
ALLOWED_RETURN_HOSTS=localhost,*.localhost
INTERCOM_APP_ID=ic_abc123
INTERCOM_JWT_SECRET=your-dev-secret
AUTH0_DOMAIN=dev-tenant.auth0.com
AUTH0_CLIENT_ID=dev-client-id
AUTH0_CLIENT_SECRET=dev-client-secret
COOKIE_SIGNING_KEY=devsigningkey0123456789abcdefdevsigningkey0123456789abcdefabcd
LOG_LEVEL=debug
```

## Configuration Management

### Validation and Debugging

The server includes comprehensive configuration validation with actionable error messages:

```bash
# Check configuration validity
./bin/server --check-config

# Print current configuration (secrets redacted)
make env-print
# or
./bin/server --env-print
```

### Configuration Features

- **Automatic normalization**: Hostnames are lowercased, wildcard patterns preprocessed
- **Security validation**: Prevents common misconfigurations like missing leading dots in cookie domains
- **Actionable errors**: Error messages include specific examples and guidance
- **Secret redaction**: Configuration output automatically hides sensitive values
- **Environment-aware**: Different validation rules for dev vs production

### Example Configuration Output

```json
{
  "env": "dev",
  "app_hostname": "localhost",
  "port": "8080",
  "cookie_domain": ".example.com",
  "allowed_return_hosts": ["localhost", "*.example.com"],
  "intercom_jwt_secret": "***",
  "auth0_client_secret": "***",
  "cookie_signing_key": "*** (32 bytes)",
  "log_level": "info"
}
```

Note: All sensitive fields are automatically redacted as `"***"` in configuration output.

## URL Sanitization

### Testing URL Sanitization

The server includes a built-in URL sanitization tool for testing:

```bash
# Test URL sanitization with the sanitize command
make sanitize URL="https://riscv.org/members/resources/?utm_source=x&x=y#frag"
# Output: https://riscv.org/members/resources/?utm_source=x

# Test with a malicious URL
make sanitize URL="javascript:alert('xss')"
# Output: Error: scheme not allowed: javascript

# Test with an unallowed host
make sanitize URL="https://malicious.com/path"
# Output: Error: host not allowed: malicious.com
```

### API Testing with curl

Test the `/login` endpoint with proper referrer validation:

```bash
# Valid request with allowed referrer
curl -H "Referer: https://localhost/" \
     "http://localhost:8080/login?return_to=https://riscv.org/path?utm_source=test&other=filtered"
# Response: {"sanitized": "https://riscv.org/path?utm_source=test"}

# Request without referrer (allowed - some clients strip referrers)
curl "http://localhost:8080/login?return_to=https://riscv.org/path"
# Response: {"sanitized": "https://riscv.org/path"}

# Request with invalid referrer (blocked)
curl -H "Referer: https://malicious.com/" \
     "http://localhost:8080/login?return_to=https://riscv.org/path"
# Response: {"error": "invalid_referrer"}

# Request with malicious URL (blocked)
curl -H "Referer: https://localhost/" \
     "http://localhost:8080/login?return_to=javascript:alert('xss')"
# Response: {"error": "invalid_return_url", "message": "scheme not allowed: javascript"}
```

### Security Features

- **Open Redirect Prevention**: Only allows URLs to configured trusted hosts
- **HTTPS Enforcement**: Automatically upgrades HTTP URLs to HTTPS
- **Query Parameter Filtering**: Only preserves allowed parameters (e.g., UTM tracking)
- **Fragment Stripping**: Removes URL fragments for security
- **Referrer Validation**: Ensures requests come from trusted sources
- **Input Sanitization**: Validates and normalizes all input URLs