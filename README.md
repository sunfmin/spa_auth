# SPA Authentication with Role-Based Access Control

A Go microservice providing authentication and role-based access control (RBAC) for Single Page Applications.

## How Lambda@Edge Authentication Works

This system uses **AWS Lambda@Edge** to validate JWT tokens at the CloudFront edge, providing low-latency authentication before requests reach your origin servers.

### Architecture Overview

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌──────────────┐
│   Browser   │────▶│   CloudFront     │────▶│  Lambda@Edge    │────▶│   Origin     │
│   (SPA)     │     │   Distribution   │     │  (auth-validator)│     │   Server     │
└─────────────┘     └──────────────────┘     └─────────────────┘     └──────────────┘
                                                      │
                                                      ▼
                                              ┌───────────────┐
                                              │  JWT Claims   │
                                              │  - user_id    │
                                              │  - email      │
                                              │  - roles[]    │
                                              │  - sections[] │
                                              └───────────────┘
```

### How Roles Are Embedded in JWT

When a user logs in via `/api/v1/auth/login`, the auth service:

1. **Validates credentials** against the database
2. **Loads user roles** with their associated SPA section permissions
3. **Generates a JWT** containing:
   - `user_id` - User's UUID
   - `email` - User's email address
   - `roles[]` - Array of role names (e.g., `["admin", "editor"]`)
   - `sections[]` - Array of permitted SPA section keys (e.g., `["dashboard", "reports"]`)
   - Special: `super_admin` role gets `sections: ["*"]` (wildcard access)

```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "roles": ["editor", "viewer"],
  "sections": ["dashboard", "reports", "analytics"],
  "exp": 1702656000
}
```

### Lambda@Edge Request Flow

1. **Request arrives** at CloudFront with `Authorization: Bearer <token>` header
2. **Lambda@Edge intercepts** the viewer-request event
3. **JWT is validated** using HS256 signature verification
4. **If valid**: Request continues to origin with added headers:
   - `X-User-ID` - User's UUID
   - `X-User-Email` - User's email
   - `X-User-Roles` - Comma-separated role names
   - `X-User-Sections` - Comma-separated section keys
5. **If invalid**: Returns `401 Unauthorized` immediately at the edge

### Integrating with Other Systems

#### Backend Services
Your origin servers receive pre-validated requests with user context in headers:

```go
// Example: Reading user info from headers in your backend
userID := r.Header.Get("X-User-ID")
roles := strings.Split(r.Header.Get("X-User-Roles"), ",")
sections := strings.Split(r.Header.Get("X-User-Sections"), ",")

// Check if user has access to a section
func hasAccess(sections []string, requiredSection string) bool {
    for _, s := range sections {
        if s == "*" || s == requiredSection {
            return true
        }
    }
    return false
}
```

#### SPA Frontend
Your frontend can decode the JWT to show/hide UI sections:

```javascript
// Decode JWT payload (without verification - just for UI)
const payload = JSON.parse(atob(token.split('.')[1]));
const userSections = payload.sections;

// Conditionally render components
if (userSections.includes('*') || userSections.includes('admin-panel')) {
    showAdminPanel();
}
```

#### Microservices
Other services can trust the `X-User-*` headers when requests come through CloudFront:

```yaml
# Example: API Gateway policy
paths:
  /admin/*:
    x-required-roles: ["admin", "super_admin"]
  /reports/*:
    x-required-sections: ["reports"]
```

## Building an Admin UI for Users and Roles

Use the REST API endpoints to build a complete admin interface:

### User Management Admin

```javascript
// List all users with pagination
GET /api/v1/users?page=1&per_page=20

// Create a new user
POST /api/v1/users
{
  "email": "newuser@example.com",
  "password": "securePassword123",
  "role_ids": ["role-uuid-1", "role-uuid-2"]
}

// Update user roles
PATCH /api/v1/users/{id}
{
  "role_ids": ["new-role-uuid"]
}

// Deactivate user (soft disable)
POST /api/v1/users/{id}/deactivate

// Reactivate user
POST /api/v1/users/{id}/reactivate

// Admin password reset
POST /api/v1/users/{id}/password
{
  "new_password": "newSecurePassword123"
}
```

### Role Management Admin

```javascript
// List all roles
GET /api/v1/roles

// Create a new role with section permissions
POST /api/v1/roles
{
  "name": "content_editor",
  "description": "Can edit content in dashboard and blog sections",
  "section_ids": ["section-uuid-1", "section-uuid-2"]
}

// Update role permissions
PATCH /api/v1/roles/{id}
{
  "name": "content_editor",
  "description": "Updated description",
  "section_ids": ["section-uuid-1", "section-uuid-2", "section-uuid-3"]
}

// Delete role (fails if users are assigned)
DELETE /api/v1/roles/{id}
```

### SPA Section Management

```javascript
// List all available sections
GET /api/v1/spa-sections

// Create a new SPA section
POST /api/v1/spa-sections
{
  "key": "analytics-dashboard",
  "display_name": "Analytics Dashboard",
  "description": "Access to analytics and reporting features"
}
```

## Configuring Roles and Permissions

### Role Configuration Model

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    User     │────▶│    UserRole     │────▶│      Role       │
│             │     │  (join table)   │     │                 │
└─────────────┘     └─────────────────┘     └────────┬────────┘
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │ RolePermission  │
                                            │  (join table)   │
                                            └────────┬────────┘
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │   SpaSection    │
                                            │  (e.g., "dashboard")
                                            └─────────────────┘
```

### Step-by-Step Role Configuration

#### 1. Define SPA Sections (what areas exist in your app)

```bash
# Create sections for your SPA
curl -X POST http://localhost:8080/api/v1/spa-sections \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "dashboard", "display_name": "Dashboard"}'

curl -X POST http://localhost:8080/api/v1/spa-sections \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "user-management", "display_name": "User Management"}'

curl -X POST http://localhost:8080/api/v1/spa-sections \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "reports", "display_name": "Reports"}'

curl -X POST http://localhost:8080/api/v1/spa-sections \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "settings", "display_name": "Settings"}'
```

#### 2. Create Roles with Section Permissions

```bash
# Create a "viewer" role - can only see dashboard and reports
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "viewer",
    "description": "Read-only access to dashboard and reports",
    "section_ids": ["<dashboard-uuid>", "<reports-uuid>"]
  }'

# Create an "admin" role - can access everything except super admin features
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "admin",
    "description": "Full access to all sections",
    "section_ids": ["<dashboard-uuid>", "<user-management-uuid>", "<reports-uuid>", "<settings-uuid>"]
  }'
```

#### 3. Assign Roles to Users

```bash
# Create user with roles
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "viewer@example.com",
    "password": "securePassword123",
    "role_ids": ["<viewer-role-uuid>"]
  }'

# Update existing user's roles
curl -X PATCH http://localhost:8080/api/v1/users/<user-uuid> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_ids": ["<admin-role-uuid>"]
  }'
```

### Built-in System Roles

| Role | Description | Sections |
|------|-------------|----------|
| `super_admin` | Full system access | `*` (wildcard - all sections) |

The `super_admin` role is a system role that cannot be deleted and grants access to all sections via the wildcard `*` permission.

### Lambda@Edge Configuration

Configure protected paths in `lambda/auth-validator/index.js`:

```javascript
// Paths that require authentication
const PROTECTED_PATHS = [
  '/api/v1/users',
  '/api/v1/roles',
  '/api/v1/spa-sections',
  '/api/v1/permissions',
  '/admin',           // Add your SPA admin routes
  '/dashboard',       // Add your SPA dashboard routes
];

// Paths that are always public (no auth required)
const PUBLIC_PATHS = [
  '/api/v1/auth/login',
  '/api/v1/auth/refresh',
  '/api/v1/oauth/google/start',
  '/api/v1/oauth/google/callback',
  '/health',
  '/',                // Public landing page
  '/login',           // Login page
];
```

### CloudFront Deployment

1. **Package the Lambda function**:
   ```bash
   cd lambda/auth-validator
   npm install
   zip -r auth-validator.zip .
   ```

2. **Deploy to Lambda@Edge** (must be in us-east-1):
   ```bash
   aws lambda create-function \
     --function-name spa-auth-validator \
     --runtime nodejs18.x \
     --handler index.handler \
     --zip-file fileb://auth-validator.zip \
     --role arn:aws:iam::ACCOUNT:role/lambda-edge-role \
     --region us-east-1
   ```

3. **Associate with CloudFront**:
   - Add Lambda function to viewer-request event
   - Set `JWT_SECRET` via custom origin headers or environment

## Features

- **Email/Password Authentication** (US1)
- **Google OAuth Login** (US2 - TODO)
- **User Management** (US3) - Create, update, deactivate users
- **Role Configuration** (US4) - Create and manage custom roles with SPA section permissions
- **Role-Based Access Enforcement** (US5) - Check user access to SPA sections
- **Password Reset** (US6)
- **Session Management** (US7) - Token refresh, validation

## Quick Start

### Prerequisites

- Go 1.22+
- PostgreSQL 15+
- Docker (for running tests)

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
PORT=8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/spa_auth?sslmode=disable

# JWT Configuration
AUTH_JWT_SECRET=your-secret-key-at-least-32-bytes
AUTH_JWT_ACCESS_TTL=15m
AUTH_JWT_REFRESH_TTL=168h

# Super Admin (for seeding)
SUPER_ADMIN_EMAIL=admin@example.com
SUPER_ADMIN_PASSWORD=your-secure-password

# Google OAuth (optional)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URL=http://localhost:8080/api/v1/oauth/google/callback
```

### Running the Server

```bash
# Run migrations and start server
go run ./cmd/api

# Seed super admin user
SUPER_ADMIN_EMAIL=admin@example.com SUPER_ADMIN_PASSWORD=securepass123 go run ./cmd/seed
```

### Running Tests

```bash
# Run all tests
go test -v ./...

# Run with race detector
go test -race ./...

# Run with coverage
go test -cover ./...
```

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login with email/password |
| POST | `/api/v1/auth/logout` | Logout (invalidate session) |
| GET | `/api/v1/auth/me` | Get current user info |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/validate` | Validate token (for Lambda@Edge) |
| POST | `/api/v1/password/reset/request` | Request password reset |
| POST | `/api/v1/password/reset` | Reset password with token |

### User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/users` | Create user |
| GET | `/api/v1/users` | List users |
| GET | `/api/v1/users/{id}` | Get user by ID |
| PATCH | `/api/v1/users/{id}` | Update user |
| POST | `/api/v1/users/{id}/deactivate` | Deactivate user |
| POST | `/api/v1/users/{id}/reactivate` | Reactivate user |
| POST | `/api/v1/users/{id}/password` | Admin reset password |
| DELETE | `/api/v1/users/{id}` | Delete user |

### Role Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/roles` | Create role |
| GET | `/api/v1/roles` | List roles |
| GET | `/api/v1/roles/{id}` | Get role by ID |
| PATCH | `/api/v1/roles/{id}` | Update role |
| DELETE | `/api/v1/roles/{id}` | Delete role |
| POST | `/api/v1/spa-sections` | Create SPA section |
| GET | `/api/v1/spa-sections` | List SPA sections |
| POST | `/api/v1/permissions/check-section` | Check section access |

## Architecture

```
├── api/
│   ├── proto/auth/v1/     # Protobuf definitions
│   └── gen/auth/v1/       # Generated Go code
├── cmd/
│   ├── api/               # Main server entry point
│   └── seed/              # Database seeding tool
├── handlers/              # HTTP handlers (thin wrappers)
├── services/              # Business logic layer
├── internal/
│   ├── config/            # Configuration loading
│   └── models/            # GORM models
└── testutil/              # Test fixtures and helpers
```

## Testing

Tests follow TDD principles with:
- Real PostgreSQL via testcontainers (no mocking)
- Table-driven test design
- Protobuf structs with `cmp.Diff` + `protocmp.Transform()`
- ServeHTTP endpoint testing through root mux

## License

MIT
