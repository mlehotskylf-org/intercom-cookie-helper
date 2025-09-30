# Security Headers for API Gateway / Load Balancer

This document outlines security headers that should be configured at the API Gateway or Load Balancer level for centralized security policy management.

## Headers to Add at Gateway/LB

### 1. Strict-Transport-Security (HSTS)
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
- Forces HTTPS for 1 year
- Applies to all subdomains
- **Currently set in**: `internal/http/router.go` (hstsMiddleware)
- **Should move to**: Gateway/LB for all services

### 2. Referrer-Policy
```
Referrer-Policy: strict-origin-when-cross-origin
```
- Controls referrer information sent in requests
- **Currently set in**: `internal/http/router.go` (intercomSecurityHeadersMiddleware)
- **Should move to**: Gateway/LB for all services

### 3. X-Content-Type-Options
```
X-Content-Type-Options: nosniff
```
- Prevents MIME type sniffing
- **Currently set in**: `internal/http/router.go` (intercomSecurityHeadersMiddleware)
- **Should move to**: Gateway/LB for all services

## Headers to Keep in Application

### Content-Security-Policy (Route-Specific)
The `/callback` route has a specific CSP for Intercom integration:
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://widget.intercom.io https://js.intercomcdn.com; connect-src 'self' https://*.intercom.io https://api-iam.intercom.io wss://*.intercom.io; img-src 'self' data: https://*.intercomcdn.com; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'
```

**Keep in application** because:
- Route-specific policy
- Requires knowledge of Intercom dependencies
- May differ from other routes

## Migration Plan

1. **Phase 1**: Configure generic headers at Gateway/LB
   - Add HSTS, Referrer-Policy, X-Content-Type-Options
   - Test all routes receive headers

2. **Phase 2**: Remove redundant headers from application
   - Remove `hstsMiddleware` if Gateway/LB sets HSTS
   - Remove generic headers from `intercomSecurityHeadersMiddleware`
   - Keep route-specific CSP in application

3. **Phase 3**: Verify
   - Check response headers in production
   - Ensure no duplicate headers
   - Validate CSP still works for Intercom

## Testing Headers

### Check Current Headers (Application)
```bash
curl -I https://intercom-auth.lehotsky.net/callback
```

### Check After Gateway/LB Migration
```bash
curl -I https://intercom-auth.lehotsky.net/healthz
# Should show HSTS, Referrer-Policy, X-Content-Type-Options from gateway

curl -I https://intercom-auth.lehotsky.net/callback
# Should show gateway headers + CSP from application
```

## Rate Limiting (Gateway/LB)

**IMPORTANT**: API Gateway or Load Balancer should implement rate limiting to protect against abuse and DoS attacks.

Recommended rate limits:
- **Per IP**: 100 requests per minute for /login endpoint
- **Per IP**: 50 requests per minute for /callback endpoint
- **Global**: Monitor and set appropriate thresholds based on expected traffic

Rate limiting should be handled at the gateway/LB level rather than in the application for:
- Better performance (reject requests before they reach the application)
- Centralized policy management across all services
- Protection against volumetric attacks

## Additional Recommended Headers (Gateway/LB)

Consider adding these at the gateway level:

### X-Frame-Options
```
X-Frame-Options: DENY
```
- Prevents clickjacking
- Modern alternative: CSP `frame-ancestors 'none'` (already in app)

### X-XSS-Protection
```
X-XSS-Protection: 1; mode=block
```
- Legacy XSS protection (mostly obsolete with CSP)
- Still good for older browsers

### Permissions-Policy
```
Permissions-Policy: geolocation=(), microphone=(), camera=()
```
- Controls browser feature access
- Deny unnecessary permissions

## Notes

- All `TODO(DevOps)` markers in code indicate headers that should move to gateway
- Application-level headers are currently working for testing
- No rush to migrate - current setup is functional and secure