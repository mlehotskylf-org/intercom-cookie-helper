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

## Deployment Requirements

**This service must run behind a reverse proxy or API gateway that handles SSL/TLS termination.** The Go application provides the authentication logic only.

### Infrastructure Requirements

Your load balancer or reverse proxy must provide:

1. **SSL/TLS Termination** - HTTPS on port 443 with valid certificates
2. **HTTP Forwarding** - Forward requests to this service on port 8080
3. **Host Header Preservation** - Pass the original `Host` header to the application
4. **Domain Routing** - Route `intercom-auth.{project-domain}` subdomains to this service

### Example Infrastructure Setup

```
Internet (HTTPS:443)
    ↓
Load Balancer / API Gateway
    ↓ (SSL terminated, forwards HTTP)
Intercom Cookie Helper (HTTP:8080)
```

### Required for Production

- Set `ENV=prod` to enable HSTS and production security settings
- Configure `ALLOWED_RETURN_HOSTS` with your project domains
- Ensure `APP_HOSTNAME` matches your `intercom-auth.*` subdomain
- Set `COOKIE_DOMAIN` to your eTLD+1 (e.g., `.riscv.org`)

See [docs/GATEWAY_HEADERS.md](docs/GATEWAY_HEADERS.md) for load balancer configuration details including rate limiting and security headers.

### Local Development (No Proxy Required)

For local development, the service runs standalone on HTTP:

```bash
ENV=dev APP_HOSTNAME=localhost PORT=8080 make start
# Access at http://localhost:8080
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Basic health check - returns `{"status":"ok"}` |
| `GET /healthz?check=deep` | Deep health check - validates Auth0 connectivity, config completeness, and dependencies |
| `GET /login?return_to=<url>` | Initiates OAuth2 authentication with Auth0 |
| `GET /callback?code=<code>&state=<state>` | Handles OAuth2 callback from Auth0 |
| `GET /logout` | Clears session cookies and shows logout page (configurable) |
| `GET /metrics/dev` | Metrics endpoint (non-prod only) |

### Health Check Details

**Basic Health Check** (`GET /healthz`)
- Returns 200 OK if service is running
- Suitable for liveness probes in Kubernetes/Docker

**Deep Health Check** (`GET /healthz?check=deep`)
- Returns 200 OK if all checks pass, 503 if any fail
- Validates:
  - Configuration completeness (Auth0, Intercom, cookie settings)
  - Auth0 domain reachability (HTTPS connectivity)
  - Cookie signing key validity (minimum 32 bytes)
- Suitable for readiness probes and deployment validation
- Example response:
  ```json
  {
    "status": "ok",
    "checks": {
      "auth0": "ok",
      "config": "ok",
      "cookie_key": "ok"
    }
  }
  ```

## Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `APP_HOSTNAME` | Your application hostname | `auth.example.com` |
| `COOKIE_DOMAIN` | Cookie domain (with leading dot) | `.example.com` |
| `INTERCOM_APP_ID` | Intercom application ID | `ic_abc123` |
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
- HTML template for Intercom Messenger boot with fallback link
- Server logging with PII redaction
- Complete end-to-end authentication bridge
- Content Security Policy headers for Intercom widget
- Comprehensive test coverage (85% average, integration + renderer tests)
- Centralized error response system with content negotiation (HTML/JSON)
- Referer validation middleware with structured logging
- Global security headers (Referrer-Policy, X-Content-Type, Permissions-Policy)
- Lightweight in-memory metrics with atomic counters
- Fuzz testing for security-critical parsing functions
- Logout endpoint with cookie clearing and optional Auth0 logout
- Cache-Control headers on all auth pages (prevents back/forward cache)
- Error page content negotiation tests

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
- **Referer validation** - HTTPS-only, IP literal rejection, host allowlist enforcement
- **Fail-closed validation** - return_to validated before setting any cookies
- **Port normalization** - Only HTTPS port 443 allowed
- **Security headers** - Referrer-Policy, X-Content-Type-Options, Permissions-Policy, HSTS
- **Cache-Control headers** - no-store, max-age=0 on all auth pages (prevents bfcache)
- **PII redaction** - Email addresses and tokens never logged, host-only logging for URLs
- **Fuzz tested** - Security-critical parsing functions tested against malicious inputs
- **Metrics observability** - Atomic counters for monitoring authentication flow health
- **Rate limiting** - API Gateway/LB level protection (see docs)
- **Content negotiation** - HTML error pages for browsers, JSON for APIs

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/GATEWAY_HEADERS.md](docs/GATEWAY_HEADERS.md) for details.

## Documentation

- [Configuration Guide](docs/CONFIGURATION.md) - All environment variables and examples
- [Security Features](docs/SECURITY.md) - Detailed security implementation
- [Development Guide](docs/DEVELOPMENT.md) - Testing, debugging, and contributing
- [Gateway Headers](docs/GATEWAY_HEADERS.md) - API Gateway/LB configuration for headers and rate limiting

## License

[Your License Here]