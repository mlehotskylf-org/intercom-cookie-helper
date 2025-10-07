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

For local development, the service runs standalone on HTTP. The service automatically detects localhost addresses (`localhost`, `127.0.0.1`, `::1`) and uses HTTP instead of HTTPS:

```bash
ENV=dev APP_HOSTNAME=localhost PORT=8080 make start
# Access at http://localhost:8080
```

**Note:** All non-localhost environments (including deployed dev/staging) use HTTPS. This ensures proper Referer header behavior in production while maintaining convenience for local development.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Basic health check - returns `{"status":"ok"}` |
| `GET /healthz?check=deep` | Deep health check - validates Auth0 connectivity, config completeness, and dependencies |
| `GET /login?return_to=<url>` | Initiates OAuth2 authentication with Auth0. The `return_to` parameter takes priority over the Referer header. |
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

## Features

**Authentication & Authorization:**
- OAuth2/OIDC flow with Auth0 using PKCE
- Intercom Identity Verification (JWT from Auth0 Action)
- Nonce and state parameter validation
- Secure session management with HMAC-signed cookies

**Security Hardening:**
- Host allowlisting and URL sanitization
- Content Security Policy headers
- PII redaction in logs
- Fuzz-tested parsing functions
- Constant-time comparisons for secrets

**Production Ready:**
- Comprehensive test coverage (85%+ across packages)
- In-memory metrics with atomic counters
- Content negotiation (HTML/JSON error responses)
- Health checks (basic + deep validation)
- Cache-Control headers (prevents bfcache issues)

### Authentication Flow

```
User → /login → Auth0 (OAuth2/PKCE) → /callback → Intercom Identify → Return URL
```

1. User redirected to `/login` with return URL (`return_to` param or Referer header)
2. OAuth2 authentication via Auth0 with PKCE
3. Token exchange validates nonce and extracts user info + Intercom JWT
4. Intercom identify page rendered with JWT (generated by Auth0 Action)
5. Auto-redirect to return URL after 1.5s

**Note:** `return_to` query parameter takes priority over Referer header for explicit redirect control.

## Development

```bash
make build    # Build binary
make test     # Run tests
make fmt      # Format code
make restart  # Restart server
```

## Security Features

**Authentication Protection:**
- OAuth2/OIDC with PKCE (prevents code interception)
- Nonce verification (prevents replay attacks)
- State parameter validation (prevents CSRF)
- Constant-time comparisons (prevents timing attacks)

**Input Validation:**
- Host allowlisting with wildcard support
- HTTPS-only enforcement (rejects HTTP, IP literals)
- Port normalization (only 443 allowed)
- Fail-closed validation (validates before state changes)
- Fuzz-tested parsers (prevents crashes on malicious input)

**HTTP Security:**
- HMAC-signed cookies (tamper-proof sessions)
- Security headers (CSP, HSTS, Referrer-Policy, X-Content-Type-Options)
- Cache-Control headers (prevents bfcache)
- Request limits (1MB body, 3s connect, 5s total timeouts)
- Content negotiation (HTML/JSON error responses)

**Operational Security:**
- PII redaction (no emails/tokens in logs, host-only URLs)
- Metrics observability (atomic counters)
- Rate limiting (API Gateway/LB level - see [Gateway docs](docs/GATEWAY_HEADERS.md))

See [docs/SECURITY.md](docs/SECURITY.md) for detailed security implementation.

## Documentation

- [Configuration Guide](docs/CONFIGURATION.md) - All environment variables and examples
- [Security Features](docs/SECURITY.md) - Detailed security implementation
- [Development Guide](docs/DEVELOPMENT.md) - Testing, debugging, and contributing
- [Gateway Headers](docs/GATEWAY_HEADERS.md) - API Gateway/LB configuration for headers and rate limiting

## License

[Your License Here]