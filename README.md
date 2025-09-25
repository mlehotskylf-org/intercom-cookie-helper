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
- Intercom JWT generation (`MintIntercomJWT`)
- Vendor-neutral adapter pattern (`IdentifyRenderer`)
- HTML template for Intercom Messenger integration
- Server logging to `server.log` file

### 🚧 TODO - Final Integration
The authentication flow works but needs the final step to complete Intercom integration:

1. **Wire up IntercomRenderer in callback handler** (`internal/http/callback.go`)
   - Replace the success template with `IntercomRenderer`
   - Pass user info to generate JWT
   - Render HTML that loads Intercom Messenger and redirects

2. **Configure Intercom settings**
   - Ensure `INTERCOM_APP_ID` is set correctly in production
   - Ensure `INTERCOM_JWT_SECRET` is properly configured

3. **Test end-to-end flow**
   - Verify JWT is generated with correct user data
   - Confirm Intercom Messenger loads with user context
   - Validate automatic redirect to `return_to` URL

Once these steps are complete, the flow will be:
1. User clicks login → 2. Auth0 authentication → 3. Generate Intercom JWT → 4. Load Messenger → 5. Redirect to app

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
- **Log redaction** - Sensitive data never logged

See [docs/SECURITY.md](docs/SECURITY.md) for details.

## Documentation

- [Configuration Guide](docs/CONFIGURATION.md) - All environment variables and examples
- [Security Features](docs/SECURITY.md) - Detailed security implementation
- [Development Guide](docs/DEVELOPMENT.md) - Testing, debugging, and contributing

## License

[Your License Here]