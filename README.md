# SPA Authentication with Role-Based Access Control

A Go microservice providing authentication and role-based access control (RBAC) for Single Page Applications.

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
