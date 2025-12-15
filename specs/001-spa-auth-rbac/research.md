# Research: SPA Authentication with Role-Based Access Control

**Feature Branch**: `001-spa-auth-rbac`  
**Date**: 2024-12-15  
**Status**: Complete

## Research Tasks

### 1. CloudFront/S3 Authentication Architecture

**Question**: How to protect S3-hosted SPA with authentication when CloudFront is in front?

**Decision**: Standalone authentication API service with JWT tokens

**Rationale**:
- Lambda@Edge has cold start latency and 1MB code size limit
- Standalone service provides more flexibility and easier debugging
- JWT tokens can be validated at CloudFront via Lambda@Edge for protected routes
- Auth service handles login/logout, CloudFront validates tokens

**Architecture**:
```
User → CloudFront → Lambda@Edge (token validation) → S3 (SPA assets)
                 ↘ Auth API (login/logout/user management)
```

**Alternatives Considered**:
- **Lambda@Edge only**: Rejected due to cold starts, size limits, and complexity
- **Cognito**: Rejected - overkill for invite-only model, less control over user management
- **CloudFront signed cookies**: Considered but JWT provides more flexibility for RBAC

---

### 2. Session Management Strategy

**Question**: How to manage sessions securely for SPA?

**Decision**: JWT tokens stored in HTTP-only secure cookies

**Rationale**:
- HTTP-only cookies prevent XSS token theft
- Secure flag ensures HTTPS-only transmission
- SameSite=Strict prevents CSRF
- JWT contains user ID and roles for stateless validation
- Short-lived access tokens (15 min) + refresh tokens (7 days) for security

**Token Structure**:
```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "roles": ["viewer", "editor"],
  "exp": 1702656000,
  "iat": 1702655100
}
```

**Alternatives Considered**:
- **LocalStorage**: Rejected - vulnerable to XSS
- **Session IDs with server lookup**: More secure but adds latency and state
- **Opaque tokens**: Requires database lookup on every request

---

### 3. Google OAuth 2.0 Integration

**Question**: How to integrate Google OAuth for pre-registered users only?

**Decision**: Standard OAuth 2.0 Authorization Code flow with email verification

**Rationale**:
- Authorization Code flow is most secure for server-side apps
- After Google callback, verify email exists in database before issuing session
- Link Google account to existing user record for future logins
- Deny access if email not pre-registered by super admin

**Flow**:
1. User clicks "Sign in with Google"
2. Redirect to Google OAuth consent screen
3. Google redirects back with authorization code
4. Exchange code for tokens, get user email from ID token
5. Check if email exists in database
6. If exists: link Google account, issue session token
7. If not exists: deny access with clear message

**Alternatives Considered**:
- **Implicit flow**: Deprecated, less secure
- **Auto-create accounts**: Rejected - violates invite-only model

---

### 4. Password Hashing Strategy

**Question**: How to securely hash and verify passwords?

**Decision**: bcrypt with cost factor 12

**Rationale**:
- bcrypt is industry standard, resistant to GPU attacks
- Cost factor 12 provides good security/performance balance (~250ms hash time)
- Built-in salt prevents rainbow table attacks
- Go's `golang.org/x/crypto/bcrypt` is well-maintained

**Alternatives Considered**:
- **Argon2**: More modern but bcrypt is sufficient and simpler
- **scrypt**: Good but bcrypt has better library support in Go
- **PBKDF2**: Weaker against GPU attacks

---

### 5. Rate Limiting Strategy

**Question**: How to implement rate limiting for login attempts?

**Decision**: Token bucket algorithm with Redis or in-memory store

**Rationale**:
- 5 attempts per 15 minutes per email/IP combination (FR-027)
- Token bucket allows burst while limiting sustained abuse
- Redis for distributed deployments, in-memory for single instance
- Exponential backoff for repeated violations

**Implementation**:
- Key: `ratelimit:login:{email}:{ip}`
- Tokens: 5
- Refill: 1 token per 3 minutes
- Block duration: 15 minutes after exhaustion

**Alternatives Considered**:
- **Fixed window**: Allows burst at window boundaries
- **Sliding window**: More complex, marginal benefit
- **Per-IP only**: Doesn't prevent credential stuffing

---

### 6. Role-Based Access Control Design

**Question**: How to implement flexible RBAC for SPA routes?

**Decision**: Permission-based roles with route mapping

**Rationale**:
- Roles: `super_admin`, `admin`, `editor`, `viewer`
- Each role has a set of permissions (e.g., `users:read`, `users:write`)
- Routes map to required permissions
- JWT contains roles, SPA checks permissions client-side
- API validates permissions server-side for all protected endpoints

**Role Hierarchy**:
```
super_admin → all permissions + user management
admin       → all content permissions
editor      → read + write content
viewer      → read only
```

**Alternatives Considered**:
- **Simple role check**: Less flexible for future expansion
- **ACL per resource**: Overkill for this use case
- **Attribute-based (ABAC)**: Too complex

---

### 7. Super Admin Seeding

**Question**: How to seed the initial super admin account?

**Decision**: Environment variable configuration on first startup

**Rationale**:
- `SUPER_ADMIN_EMAIL` and `SUPER_ADMIN_PASSWORD` env vars
- On startup, check if super admin exists
- If not, create with provided credentials
- Log warning if env vars not set and no super admin exists
- Password must meet minimum requirements (8 chars)

**Alternatives Considered**:
- **CLI command**: Requires manual intervention
- **Database migration**: Less flexible for different environments
- **Config file**: Less secure than env vars

---

### 8. Email Service for Password Reset

**Question**: How to send password reset emails?

**Decision**: Pluggable email interface with SES default

**Rationale**:
- Interface allows swapping providers (SES, SendGrid, SMTP)
- AWS SES is cost-effective and integrates well with AWS stack
- Reset tokens: 32-byte random, URL-safe base64 encoded
- Token expiry: 24 hours (FR-015)
- One active token per user (new request invalidates old)

**Interface**:
```go
type EmailService interface {
    SendPasswordReset(ctx context.Context, email, token string) error
}
```

**Alternatives Considered**:
- **Hardcoded SES**: Less flexible
- **No email, admin resets only**: Poor UX

---

## Technology Decisions Summary

| Component | Decision | Package/Service |
|-----------|----------|-----------------|
| Password hashing | bcrypt cost 12 | `golang.org/x/crypto/bcrypt` |
| JWT tokens | HS256 signing | `github.com/golang-jwt/jwt/v5` |
| OAuth 2.0 | Google provider | `golang.org/x/oauth2/google` |
| Rate limiting | Token bucket | `golang.org/x/time/rate` or Redis |
| Email | AWS SES | `github.com/aws/aws-sdk-go-v2/service/ses` |
| Session storage | HTTP-only cookies | Standard library |
| Database | PostgreSQL + GORM | `gorm.io/gorm` |

## Dependencies

```go
require (
    github.com/golang-jwt/jwt/v5
    golang.org/x/crypto
    golang.org/x/oauth2
    golang.org/x/time
    github.com/aws/aws-sdk-go-v2/service/ses
    gorm.io/gorm
    gorm.io/driver/postgres
    google.golang.org/protobuf
)
```

## Configuration Requirements

```yaml
# Environment variables
AUTH_JWT_SECRET: "32+ byte secret for HS256"
AUTH_JWT_ACCESS_TTL: "15m"
AUTH_JWT_REFRESH_TTL: "168h"  # 7 days

GOOGLE_CLIENT_ID: "xxx.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET: "xxx"
GOOGLE_REDIRECT_URL: "https://auth.example.com/oauth/google/callback"

SUPER_ADMIN_EMAIL: "admin@example.com"
SUPER_ADMIN_PASSWORD: "initial-secure-password"

DATABASE_URL: "postgres://user:pass@host:5432/dbname"

AWS_REGION: "us-east-1"
SES_FROM_EMAIL: "noreply@example.com"

RATE_LIMIT_ENABLED: "true"
RATE_LIMIT_STORE: "memory"  # or "redis"
REDIS_URL: "redis://localhost:6379"  # if using redis
```

## Security Considerations

1. **JWT Secret**: Must be at least 32 bytes, stored securely (AWS Secrets Manager recommended)
2. **HTTPS Only**: All auth endpoints must use HTTPS
3. **CORS**: Restrict to SPA domain only
4. **Cookie Settings**: `Secure=true`, `HttpOnly=true`, `SameSite=Strict`
5. **Password Requirements**: Minimum 8 characters, validated server-side
6. **Token Rotation**: Refresh tokens rotated on use
7. **Audit Logging**: Log all auth events (login, logout, password reset, user changes)
