# Intercom Cookie Helper

A secure authentication bridge service for Intercom and Auth0, providing OAuth2/OIDC flows with PKCE and secure cookie management.

## Quick Start

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your Auth0 and Intercom credentials

# 2. Start the server
source .env && make start
```

The server starts on port 8080 (or `PORT` if set).

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Health check |
| `GET /login?return_to=<url>` | Initiates OAuth2 authentication with Auth0 |
| `GET /callback?code=<code>&state=<state>` | Handles OAuth2 callback from Auth0 |

## Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `APP_HOSTNAME` | Your application hostname | `auth.example.com` |
| `COOKIE_DOMAIN` | Cookie domain (with leading dot) | `.example.com` |
| `INTERCOM_APP_ID` | Intercom application ID | `ic_abc123` |
| `INTERCOM_JWT_SECRET` | Intercom JWT secret (dev only) | `your-secret` |
| `AUTH0_DOMAIN` | Auth0 tenant domain | `tenant.auth0.com` |
| `AUTH0_CLIENT_ID` | Auth0 application client ID | `client-id` |
| `AUTH0_CLIENT_SECRET` | Auth0 client secret (dev only) | `client-secret` |
| `COOKIE_SIGNING_KEY` | 32+ byte hex/base64 key | `0123456789abcdef...` |

### Optional Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `ENV` | `dev` | Environment: dev/staging/prod |
| `ALLOWED_RETURN_HOSTS` | - | CSV list of allowed redirect hosts |
| `LOG_LEVEL` | `info` | Log verbosity: debug/info/warn/error |

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for complete configuration guide.

## Implementation Status

### ✅ Completed
- OAuth2/OIDC authentication flow with Auth0
- PKCE (Proof Key for Code Exchange) implementation
- Nonce validation for security
- User info retrieval from Auth0
- Secure cookie management with HMAC signing
- URL sanitization and validation
- HSTS header support for production
- Intercom JWT generation with HS256 signing
- Intercom Identity Verification integration
- HTML template for Intercom Messenger boot
- Server logging with PII redaction
- Complete end-to-end authentication bridge
- Content Security Policy headers for Intercom widget
- Comprehensive test coverage (integration + renderer tests)

### Current Flow
1. User visits protected resource
2. Redirected to `/login` with return URL
3. OAuth2 authentication via Auth0
4. Token exchange and user info retrieval
5. Intercom JWT generation with user data
6. Render Intercom identify page
7. Automatic redirect to original URL

The authentication bridge is fully functional and validates correctly with Intercom's Identity Verification.

## Development

```bash
make build    # Build binary
make test     # Run tests
make fmt      # Format code
make restart  # Restart server
```

## Security Features

- **OAuth2/OIDC with PKCE** - Enhanced authorization code flow
- **HMAC-signed cookies** - Tamper-proof session management
- **Host allowlisting** - Prevents open redirects
- **Nonce verification** - Replay attack prevention
- **Constant-time comparisons** - Timing attack prevention
- **Request body limits** - DoS prevention (1MB max)
- **HTTP timeouts** - Connection (3s) and total (5s) timeouts
- **Content Security Policy** - Controlled resource loading for Intercom widget
- **PII redaction** - Email addresses and tokens never logged
- **Rate limiting** - API Gateway/LB level protection (see docs)

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/GATEWAY_HEADERS.md](docs/GATEWAY_HEADERS.md) for details.

## Documentation

- [Configuration Guide](docs/CONFIGURATION.md) - All environment variables and examples
- [Security Features](docs/SECURITY.md) - Detailed security implementation
- [Development Guide](docs/DEVELOPMENT.md) - Testing, debugging, and contributing
- [Gateway Headers](docs/GATEWAY_HEADERS.md) - API Gateway/LB configuration for headers and rate limiting

## License

[Your License Here]