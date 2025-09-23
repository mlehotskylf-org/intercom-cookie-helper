# Intercom Cookie Helper

A secure authentication bridge service for Intercom and Auth0, providing OAuth2/OIDC flows with PKCE, secure cookie management, and comprehensive security features.

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

### `GET /healthz`
Health check endpoint
- Returns: `200 OK` with `{"status":"ok"}`

### `GET /login?return_to=<url>`
Initiates OAuth2/OIDC authentication flow with Auth0
- **Security Features**:
  - Referrer validation (HTTPS from allowed hosts)
  - URL sanitization and host allowlisting
  - PKCE (Proof Key for Code Exchange) implementation
- **Cookies Set**:
  - `ic_redirect`: Signed cookie with sanitized return URL (30min TTL)
  - `ic_oidc_txn`: Transaction cookie with PKCE verifier and nonce (10min TTL)
- **Response**: `302 Redirect` to Auth0 authorize endpoint
- **Errors**: Generic `{"error": "invalid_request"}` (no sensitive data exposed)

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
# Valid request with allowed referrer (redirects to Auth0)
curl -i -H "Referer: https://localhost/" \
     "http://localhost:8080/login?return_to=https://localhost/dashboard"
# Response: 302 Found with Location: https://auth0.com/authorize?...
# Sets ic_redirect and ic_oidc_txn cookies

# Request without referrer (allowed)
curl -i "http://localhost:8080/login?return_to=https://localhost/dashboard"
# Response: 302 Found (redirects to Auth0)

# Request with invalid referrer (blocked)
curl -H "Referer: https://malicious.com/" \
     "http://localhost:8080/login?return_to=https://localhost/dashboard"
# Response: {"error": "invalid_referrer"}

# Request with malicious URL (blocked)
curl -H "Referer: https://localhost/" \
     "http://localhost:8080/login?return_to=javascript:alert('xss')"
# Response: {"error": "invalid_request"}
```

## Security Features

### Authentication & Authorization
- **OAuth2/OIDC with PKCE**: Enhanced OAuth2 security with Proof Key for Code Exchange
- **Referrer Validation**: Requires HTTPS referrer from allowed hosts
- **Host Allowlisting**: Strict validation against configured trusted hosts
- **URL Sanitization**:
  - HTTPS-only enforcement
  - Query parameter filtering (preserves only allowed params)
  - Fragment stripping for security
  - Port validation (rejects non-standard ports)

### Cookie Security
- **HMAC-SHA256 Signing**: Cryptographic signing for tamper detection
- **Key Rotation Support**: Secondary key for seamless rotation
- **Size Limits**: 3500-byte limit to prevent overflow attacks
- **Security Flags**:
  - `HttpOnly`: Prevents JavaScript access
  - `SameSite=Lax`: CSRF protection
  - `Secure`: HTTPS-only in production
- **TTL Enforcement**: Configurable expiry with clock skew tolerance

### Error Handling
- **Information Leak Prevention**: Generic error responses
- **Server-Side Logging**: Detailed errors logged internally only
- **No Sensitive Data Exposure**: URLs and hosts never echoed in errors

### Transport Security
- **HSTS Support**: Configurable HTTP Strict Transport Security
- **HTTPS Enforcement**: All sensitive operations require HTTPS

## Redirect Cookie (Stateless Round-Trip)

The server uses signed redirect cookies to maintain user's intended destination URL during OAuth/OIDC authentication flows without server-side session storage.

### What It Stores

The redirect cookie contains:
- **URL**: Sanitized HTTPS destination URL
- **Host**: Extracted hostname for validation
- **Ref**: Optional referrer hostname (not full URL)
- **Iat/Exp**: Issued-at and expiration timestamps
- **Nonce**: Random value for uniqueness

**Security**: Cookies are signed with HMAC-SHA256 for tamper detection but are NOT encrypted - contents are readable by clients as base64-encoded JSON.

### Cookie Format

Structure: `base64url(JSON-payload) + "." + base64url(HMAC-signature)`

Example:
```
eyJ2IjoidjEiLCJ1cmwiOiJodHRwczovL3Jpc2N2Lm9yZy90ZXN0IiwiaG9zdCI6InJpc2N2Lm9yZyJ9.h7HwVSheXOBIxSYwAwSvJbpEZIVrUVfGfEis8PRHs94
```

### Testing Locally

1. **Create a redirect cookie** by calling `/login` with valid parameters:
   ```bash
   curl -H "Referer: https://localhost/" \
        "http://localhost:8080/login?return_to=https://riscv.org/test"
   ```

2. **Inspect the cookie** using the debug endpoint (non-production only):
   ```bash
   # Copy the ic_redirect cookie from the Set-Cookie header above, then:
   curl -H "Cookie: ic_redirect=eyJ2IjoidjEi..." \
        "http://localhost:8080/debug/redirect-cookie"
   ```

The debug endpoint shows:
- Whether the cookie is valid
- The decoded destination URL
- Validation status and any errors

### Cookie Security Flags

- **HttpOnly**: `true` - Prevents JavaScript access
- **SameSite**: `Lax` - Provides CSRF protection while allowing cross-site navigation
- **Secure**: `true` in production, `false` in development
- **Domain**: Set to `COOKIE_DOMAIN` environment variable (e.g., `.riscv.org`)
- **Path**: `/` - Available site-wide

### TTL Configuration

Control cookie lifetime with environment variables:

- **`REDIRECT_TTL`** - How long redirect cookies remain valid
  - Default: `30m` (30 minutes)
  - Format: Go duration string (e.g., `1h`, `24h`, `2h30m`)
  - Used for cookie `Max-Age` and expiration validation

- **`REDIRECT_SKEW`** - Clock skew tolerance for distributed systems
  - Default: `1m` (1 minute)
  - Allows for small time differences between servers

Example configuration:
```bash
REDIRECT_TTL=1h        # Cookies valid for 1 hour
REDIRECT_SKEW=5m       # Allow 5 minutes clock skew
```

### Key Rotation

The system supports seamless key rotation using primary and secondary signing keys:

- **`COOKIE_SIGNING_KEY`** - Primary key for signing new cookies
- **`SECONDARY_COOKIE_SIGNING_KEY`** - Secondary key for validating old cookies during rotation

During key rotation:
1. Deploy new servers with rotated keys (old primary becomes secondary)
2. Cookies signed with either key are accepted
3. Zero-downtime key updates possible