# Quickstart: SPA Authentication with Role-Based Access Control

**Feature Branch**: `001-spa-auth-rbac`  
**Date**: 2024-12-15

## Prerequisites

- Go 1.22+
- Docker (for testcontainers and local PostgreSQL)
- Google Cloud Console project (for OAuth)
- AWS account (for SES email, optional)

## Quick Setup

### 1. Clone and Setup

```bash
git checkout 001-spa-auth-rbac
go mod tidy
```

### 2. Environment Configuration

Create `.env` file:

```bash
# Database
DATABASE_URL=postgres://postgres:postgres@localhost:5432/spa_auth?sslmode=disable

# JWT Configuration
AUTH_JWT_SECRET=your-32-byte-secret-key-here-min
AUTH_JWT_ACCESS_TTL=15m
AUTH_JWT_REFRESH_TTL=168h

# Google OAuth (get from Google Cloud Console)
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URL=http://localhost:8080/api/v1/oauth/google/callback

# Super Admin (created on first startup)
SUPER_ADMIN_EMAIL=admin@example.com
SUPER_ADMIN_PASSWORD=SecurePassword123!

# Email (optional - uses console output if not set)
AWS_REGION=us-east-1
SES_FROM_EMAIL=noreply@example.com

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_STORE=memory

# Error Details (set to true in production)
HIDE_ERROR_DETAILS=false
```

### 3. Start Database

```bash
# Using Docker
docker run -d \
  --name spa_auth_db \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=spa_auth \
  -p 5432:5432 \
  postgres:15-alpine

# Wait for database to be ready
sleep 3
```

### 4. Run Migrations

```bash
go run cmd/api/main.go migrate
```

### 5. Start Server

```bash
go run cmd/api/main.go serve
# Server starts on http://localhost:8080
```

## API Quick Reference

### Authentication

```bash
# Login with email/password
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "SecurePassword123!"}'

# Response:
# {
#   "user": {"id": "...", "email": "admin@example.com", "roles": ["super_admin"]},
#   "access_token": "eyJ...",
#   "refresh_token": "...",
#   "expires_at": "2024-12-15T08:30:00Z"
# }

# Get current user
curl http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer <access_token>"

# Logout
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer <access_token>"

# Refresh token
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'
```

### User Management (Super Admin Only)

```bash
# Create new user
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "UserPassword123!",
    "roles": ["viewer"]
  }'

# List users
curl http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer <admin_token>"

# Update user roles
curl -X PATCH http://localhost:8080/api/v1/users/<user_id> \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"roles": ["editor"]}'

# Deactivate user
curl -X POST http://localhost:8080/api/v1/users/<user_id>/deactivate \
  -H "Authorization: Bearer <admin_token>"

# Admin reset password
curl -X POST http://localhost:8080/api/v1/users/<user_id>/password \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"new_password": "NewPassword123!"}'
```

### Google OAuth

```bash
# Start OAuth flow (redirect user to this URL)
curl http://localhost:8080/api/v1/oauth/google/start
# Response: {"authorization_url": "https://accounts.google.com/...", "state": "..."}

# Callback handled automatically - redirects to SPA with tokens
```

### Password Reset

```bash
# Request password reset
curl -X POST http://localhost:8080/api/v1/password/reset/request \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Reset password with token (from email link)
curl -X POST http://localhost:8080/api/v1/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token": "<reset_token>", "new_password": "NewPassword123!"}'
```

### Permission Check

```bash
# Check if user has permission
curl -X POST http://localhost:8080/api/v1/permissions/check \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"resource": "content", "action": "write"}'
# Response: {"allowed": true}
```

## Running Tests

```bash
# Run all tests (requires Docker for testcontainers)
go test -v ./...

# Run with race detector
go test -v -race ./...

# Run specific test
go test -v ./handlers -run TestLogin

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Project Structure

```
spa_auth/
├── api/
│   ├── proto/auth/v1/     # Protobuf definitions
│   └── gen/auth/v1/       # Generated Go code
├── services/              # Business logic (public)
├── handlers/              # HTTP handlers (public)
├── internal/
│   ├── models/            # GORM models
│   └── config/            # Configuration
├── cmd/api/               # Main entry point
└── testutil/              # Test helpers
```

## Integration with SPA

### CloudFront + Lambda@Edge Setup

1. Deploy auth service to AWS (ECS, Lambda, or EC2)
2. Create Lambda@Edge function for token validation
3. Configure CloudFront behavior:
   - `/api/*` → Auth service origin
   - `/*` → S3 bucket (SPA assets)
   - Lambda@Edge on viewer request for protected paths

### SPA Integration

```javascript
// Login
const response = await fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
  credentials: 'include', // Include cookies
});
const { user, access_token } = await response.json();

// Store token and use for API calls
localStorage.setItem('access_token', access_token);

// API calls with token
const data = await fetch('/api/v1/some-endpoint', {
  headers: { 'Authorization': `Bearer ${access_token}` },
});

// Check permissions client-side
const hasPermission = user.roles.some(role => 
  ['admin', 'super_admin', 'editor'].includes(role)
);
```

## Common Issues

### "Database connection failed"
- Ensure PostgreSQL is running: `docker ps`
- Check DATABASE_URL in .env

### "Invalid JWT secret"
- AUTH_JWT_SECRET must be at least 32 bytes

### "Google OAuth error"
- Verify GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET
- Check redirect URL matches Google Console configuration

### "Rate limit exceeded"
- Wait 15 minutes or disable rate limiting for development

## Next Steps

1. Run `/speckit.tasks` to generate implementation tasks
2. Implement services following TDD workflow
3. Deploy to AWS with CloudFront integration
4. Configure production environment variables
