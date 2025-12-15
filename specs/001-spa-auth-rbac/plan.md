# Implementation Plan: SPA Authentication with Role-Based Access Control

**Branch**: `001-spa-auth-rbac` | **Date**: 2024-12-15 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-spa-auth-rbac/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

Authentication package for S3/CloudFront-deployed SPA with:
- **Email/password login** for admin-created users (no self-registration)
- **Google OAuth 2.0** for pre-registered emails only
- **Role-based access control** (viewer, editor, admin, super_admin)
- **Super admin user management** (create users, assign roles, deactivate accounts)
- **Session management** with secure HTTP-only cookies
- **Password reset** via email with 24-hour expiry

Technical approach: Lambda@Edge or standalone auth service fronting CloudFront, JWT tokens for session management, PostgreSQL for user/role storage.

## Key Technical Decisions

| Component | Decision | Rationale |
|-----------|----------|----------|
| **Architecture** | Standalone Auth API + Lambda@Edge token validator | Auth API handles login/OAuth/user management; Lambda@Edge validates JWT on every CloudFront request |
| **Session Management** | JWT in HTTP-only secure cookies | Prevents XSS token theft; SameSite=Strict prevents CSRF |
| **Token Strategy** | Access (15min) + Refresh (7 days) | Short-lived access limits exposure; refresh enables seamless UX |
| **Password Hashing** | bcrypt cost 12 | Industry standard, GPU-resistant, ~250ms hash time |
| **OAuth** | Google Authorization Code flow | Most secure for server-side; only for pre-registered emails |
| **Rate Limiting** | Token bucket (5/15min per email+IP) | Prevents brute force while allowing legitimate retries |
| **RBAC** | Dynamic configurable roles | Super admin creates/configures roles with CRUD; roles map to SPA sections; super_admin role is system-protected |
| **Email** | AWS SES with pluggable interface | Cost-effective, integrates with AWS stack |

## Lambda@Edge Integration

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CloudFront                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐     ┌──────────────────┐     ┌──────────────────────┐   │
│   │   Viewer     │     │   Lambda@Edge    │     │      Origins         │   │
│   │   Request    │────▶│  (JWT Validator) │────▶│                      │   │
│   └──────────────┘     └──────────────────┘     │  ┌────────────────┐  │   │
│                               │                  │  │   S3 Bucket    │  │   │
│                               │ Invalid/Missing  │  │   (SPA Assets) │  │   │
│                               │ Token            │  └────────────────┘  │   │
│                               ▼                  │                      │   │
│                        ┌──────────────┐         │  ┌────────────────┐  │   │
│                        │  Redirect to │         │  │   Auth API     │  │   │
│                        │  /login      │         │  │   (ECS/Lambda) │  │   │
│                        └──────────────┘         │  └────────────────┘  │   │
│                                                  └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Request Flow

1. **Unauthenticated User** → CloudFront → Lambda@Edge detects no token → Redirect to `/login`
2. **Login Request** → CloudFront → Auth API origin → Returns JWT in cookie
3. **Authenticated Request** → CloudFront → Lambda@Edge validates JWT → S3 origin serves SPA
4. **API Request** → CloudFront → Auth API origin (for `/api/*` paths)

### Lambda@Edge Function Responsibilities

| Trigger | Function | Purpose |
|---------|----------|----------|
| **Viewer Request** | `auth-validator` | Validate JWT, check expiry, extract user/roles |
| **Viewer Response** | (optional) | Add security headers (CSP, HSTS) |

### CloudFront Behavior Configuration

| Path Pattern | Origin | Lambda@Edge | Cache |
|--------------|--------|-------------|-------|
| `/api/*` | Auth API (ALB/API Gateway) | None | No cache |
| `/login` | S3 (login page) | None | Cache |
| `/oauth/*` | Auth API | None | No cache |
| `/*` (default) | S3 (SPA assets) | `auth-validator` on Viewer Request | Cache with cookie |

### JWT Validation in Lambda@Edge

```javascript
// Lambda@Edge runs in Node.js (Go not supported)
// Validates JWT signature and expiry, extracts claims
// Returns 302 redirect to /login if invalid
// Passes request through if valid
```

**Constraints**:
- Lambda@Edge max 1MB code size (use minimal dependencies)
- No environment variables (embed public key or fetch from Parameter Store at cold start)
- Max 5 second timeout for viewer request triggers
- Must be deployed to us-east-1

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AWS Account                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  us-east-1 (required for Lambda@Edge)                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Lambda@Edge: auth-validator                             │    │
│  │  - JWT validation (HS256 or RS256)                       │    │
│  │  - Role extraction for downstream                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Any Region (e.g., ap-northeast-1)                              │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Auth API (ECS Fargate or Lambda + API Gateway)          │    │
│  │  - Login/logout endpoints                                │    │
│  │  - Google OAuth flow                                     │    │
│  │  - User management (super admin)                         │    │
│  │  - Password reset                                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  PostgreSQL (RDS)                                        │    │
│  │  - Users, roles, sessions, password reset tokens         │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  S3 Bucket                                               │    │
│  │  - SPA static assets (HTML, JS, CSS)                     │    │
│  │  - Login page                                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Technical Context

**Stack**: Go 1.22+, PostgreSQL 15+, GORM, Protobuf, OpenTracing, testcontainers-go  
**Project Type**: Authentication service (API + Lambda@Edge integration)  
**Target**: AWS Lambda@Edge or containerized service behind CloudFront  
**Performance**: 100 concurrent auth requests without degradation (SC-007)  
**Scale**: Configurable, designed for small-to-medium teams with invite-only access

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Testing Principles (I-IX)
- [ ] **I. Integration Testing (No Mocking)**: Real PostgreSQL via testcontainers, test isolation with table truncation, fixtures via GORM, NO mocks in implementation code, mocking ONLY in `*_test.go` for external systems with justification
- [ ] **II. Table-Driven Design**: Test cases as slices of structs with descriptive `name` fields, execute using `t.Run(testCase.name, func(t *testing.T) {...})`
- [ ] **III. Comprehensive Edge Case Coverage**: Input validation (empty/nil, invalid formats, SQL injection, XSS), boundaries (zero/negative/max), auth (missing/expired/invalid tokens), data state (404s, conflicts), database (constraint violations, foreign key failures), HTTP (wrong methods, missing headers, invalid content-types, malformed JSON)
- [ ] **IV. ServeHTTP Endpoint Testing**: Call root mux ServeHTTP (NOT individual handlers) using `httptest.ResponseRecorder`, identical routing configuration, HTTP path patterns, `r.PathValue()` for parameters
- [ ] **V. Protobuf Data Structures**: API contracts in `.proto` files, tests use protobuf structs (NO `map[string]interface{}`), compare using `cmp.Diff()` with `protocmp.Transform()`, derive expected from TEST FIXTURES (NOT response except truly random: UUIDs, timestamps, crypto-rand tokens)
- [ ] **VI. Continuous Test Verification**: Run `go test -v ./...` after every change, pass before commit, fix failures immediately, run with `-race` for concurrency safety
- [ ] **VII. Root Cause Tracing**: Trace backward through call chain, distinguish symptoms from root causes, fix source NOT symptoms, NEVER remove/weaken tests, use debuggers/logging
- [ ] **VIII. Acceptance Scenario Coverage**: Every user scenario (US#-AS#) in spec.md has corresponding test, test case names reference scenarios, validate complete "Then" clause
- [ ] **IX. Test Coverage & Gap Analysis**: Run `go test -coverprofile=coverage.out ./...`, analyze with `go tool cover -func=coverage.out`, target >80%, remove dead code if unreachable

### System Architecture (X)
- [ ] **X. Service Layer Architecture**: Business logic in Go interfaces (service layer), services MUST NOT depend on HTTP types (only `context.Context` allowed), handlers thin wrappers
- [ ] **Package Structure**: Services/handlers in public packages (NOT `internal/`) for reusability, external dependencies injected via builder pattern
- [ ] **Builder Pattern**: Services use `NewService(db).WithLogger(log).Build()` (required params in constructor, optional via `With*()` methods)
- [ ] **Service Method Parameters**: MUST use protobuf structs for ALL parameters and return types (NO primitives, NO maps)
- [ ] **Main Entry Point**: `cmd/main.go` MUST ONLY call handlers or services (NEVER `internal/` packages directly). If needs `internal/` functionality, promote to public service
- [ ] **Data Flow**: HTTP → Handler (thin) → Service (protobuf) → GORM Model → Database

### Distributed Tracing (XI)
- [ ] **XI. Distributed Tracing (OpenTracing)**: HTTP endpoints MUST create OpenTracing spans with operation name (e.g., "POST /api/products")
- [ ] **Service Spans**: Service methods SHOULD create child spans (e.g., "ProductService.Create")
- [ ] **Database Operations**: ONE span per transaction (NOT per SQL query - too much overhead)
- [ ] **External Calls**: HTTP/gRPC MUST propagate trace context
- [ ] **Error Tagging**: Errors MUST set `span.SetTag("error", true)`
- [ ] **Span Tags**: MUST include `http.method`, `http.url`, `http.status_code`
- [ ] **Setup**: Development/Tests use `opentracing.NoopTracer{}`, Production configured from env vars (Jaeger, Zipkin, Datadog)

### Context-Aware Operations (XII)
- [ ] **XII. Context-Aware Operations**: Service methods MUST accept `context.Context` as first parameter
- [ ] **HTTP Handlers**: MUST use `r.Context()`
- [ ] **Database Operations**: MUST use `db.WithContext(ctx)`
- [ ] **External HTTP Calls**: MUST use `http.NewRequestWithContext(ctx, ...)`
- [ ] **Long-Running Operations**: MUST check context cancellation periodically (`select { case <-ctx.Done(): return ctx.Err() }`)
- [ ] **Tests**: MUST verify context cancellation behavior

### Error Handling Strategy (XIII)
- [ ] **XIII. Comprehensive Error Handling**: Two-layer strategy (service + HTTP) with environment-aware details
- [ ] **Service Layer**: Sentinel errors (package-level vars in `services/errors.go`) with `fmt.Errorf("%w")` wrapping for breadcrumb trail
- [ ] **HTTP Layer**: Singleton error code struct in `handlers/error_codes.go` with `ServiceErr` field for automatic mapping via `HandleServiceError()`
- [ ] **Environment-Aware Details**: ErrorResponse includes `details` field with full error chain by default; hidden when `HIDE_ERROR_DETAILS=true`
- [ ] **RespondWithError Signature**: `RespondWithError(w, errCode, err)` - always pass original error for details
- [ ] **Startup Config**: Call `handlers.SetHideErrorDetails(true)` in `main.go` when env var set
- [ ] **Testing**: ALL errors (sentinel + HTTP codes) MUST have test cases
- [ ] **Error Assertions**: Tests use error code definitions (NOT literal strings)
- [ ] **Context Errors**: `HandleServiceError()` checks `context.Canceled` and `context.DeadlineExceeded` first

## Project Structure

### Documentation (this feature)

```text
specs/001-spa-auth-rbac/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
api/
├── proto/                  # Protobuf definitions (.proto files)
│   └── auth/v1/           # Auth service API versioning
│       ├── auth.proto     # Login, logout, OAuth endpoints
│       ├── user.proto     # User management (admin only)
│       ├── role.proto     # Role definitions and permissions
│       └── session.proto  # Session management
└── gen/                    # Protobuf generated code (PUBLIC - must be importable)
    └── auth/v1/
        ├── *.pb.go
        └── *.pb.validate.go

services/                   # PUBLIC package - business logic (reusable by external apps)
├── auth_service.go        # Login, logout, token validation
├── user_service.go        # User CRUD (super admin only)
├── role_service.go        # Role management
├── session_service.go     # Session management
├── oauth_service.go       # Google OAuth integration
├── password_service.go    # Password hashing, reset tokens
├── jwt_service.go         # JWT generation and validation (shared with Lambda@Edge)
├── errors.go              # Sentinel errors (ErrInvalidCredentials, ErrUserNotFound, etc.)
└── migrations.go          # AutoMigrate() function for external apps

handlers/                   # PUBLIC package - HTTP handlers (reusable)
├── auth_handler.go        # POST /login, POST /logout, GET /oauth/google/*
├── user_handler.go        # Admin user management endpoints
├── auth_handler_test.go
├── user_handler_test.go
├── error_codes.go         # HTTP error code singleton with ServiceErr mapping
├── middleware.go          # Auth middleware, rate limiting
└── routes.go              # Shared routing configuration

internal/                   # INTERNAL - implementation details only
├── models/                # GORM models (internal - services return protobuf)
│   ├── user.go
│   ├── role.go
│   ├── session.go
│   └── password_reset_token.go
└── config/                # Configuration loading
    └── config.go

cmd/
├── api/                   # Main Auth API application
│   └── main.go
└── seed/                  # Super admin seeding utility
    └── main.go

lambda/                     # Lambda@Edge functions (Node.js - Go not supported)
├── auth-validator/        # JWT validation function
│   ├── index.js           # Lambda handler
│   ├── jwt.js             # JWT verification logic
│   ├── package.json
│   └── README.md          # Deployment instructions
└── security-headers/      # Optional: Add security headers
    ├── index.js
    └── package.json

infra/                      # Infrastructure as Code
├── terraform/             # Terraform modules
│   ├── cloudfront.tf      # CloudFront distribution
│   ├── lambda-edge.tf     # Lambda@Edge functions
│   ├── s3.tf              # S3 bucket for SPA
│   ├── ecs.tf             # ECS Fargate for Auth API
│   ├── rds.tf             # PostgreSQL RDS
│   └── variables.tf
└── cloudformation/        # Alternative: CloudFormation templates
    └── stack.yaml

testutil/                   # Test helpers and fixtures
├── fixtures.go            # CreateTestUser(), CreateTestRole(), etc.
└── db.go                  # setupTestDB() with testcontainers
```

**Structure Decision**: Single Go API service (Option 1) - appropriate for authentication package that will be deployed as a standalone service or integrated with Lambda@Edge. Services are in public packages for reusability by the SPA and other applications.

**Architecture** (Constitution Principle X):
- Services/handlers: PUBLIC packages (return protobuf, reusable)
- Models: `internal/models/` (GORM only, never exposed)
- Protobuf: PUBLIC `api/gen/` (external apps need these)
- `AutoMigrate()`: Exported in `services/migrations.go`

## Testing Strategy

### Test-First Development (TDD)

TDD workflow (Constitution Development Workflow):

1. **Design**: Define API in `.proto` files → generate code
2. **Red**: Write integration tests → verify FAIL
3. **Green**: Implement → run tests → verify PASS
4. **Refactor**: Improve code → run tests after each change
5. **Complete**: Done only when ALL tests pass

### Integration Testing Requirements

Constitution Testing Principles I-IX:

- **Integration tests ONLY** (NO mocking in implementation code), real PostgreSQL via testcontainers
- **Mocking Policy**: ONLY in test code (`*_test.go`) for external systems with justification, NEVER in production code
- **Test Setup**: Use public APIs and dependency injection (NOT direct `internal/` package imports)
- **Table-driven** with `name` fields, execute using `t.Run(testCase.name, func(t *testing.T) {...})`
- **Edge cases MANDATORY**: Input validation (empty/nil, invalid formats, SQL injection, XSS), boundaries (zero/negative/max), auth (missing/expired/invalid tokens), data state (404s, conflicts), database (constraint violations, foreign key failures), HTTP (wrong methods, missing headers, invalid content-types, malformed JSON)
- **ServeHTTP testing** via root mux (NOT individual handlers), identical routing configuration from shared routes package
- **Protobuf** structs (NO `map[string]interface{}`), use `cmp.Diff()` with `protocmp.Transform()`
- **Derive from fixtures** (request data, database fixtures, config). Copy from response ONLY for truly random: UUIDs, timestamps, crypto-rand tokens. Read `testutil/fixtures.go` for defaults.
- **Run tests** after EVERY change: `go test -v ./...` and `go test -v -race ./...` (Principle VI)
- **Map scenarios** to tests (US#-AS# in test case names, Principle VIII)
- **Coverage >80%** for business logic (Principle IX), analyze gaps with `go tool cover -func=coverage.out`

### Error Handling Strategy

Constitution Principle XIII:

- **Service Layer**: Sentinel errors (package-level vars in `services/errors.go`, e.g., `var ErrProductNotFound = errors.New("product not found")`), wrap with `fmt.Errorf("context: %w", err)` for breadcrumb trail
- **HTTP Layer**: Singleton error code struct in `handlers/error_codes.go` with fields `Code`, `Message`, `HTTPStatus`, `ServiceErr` for automatic mapping
- **Automatic Mapping**: `HandleServiceError()` uses `errors.Is()` to check service errors and map to HTTP responses (NO switch statements)
- **Context Errors**: Check `context.Canceled` (499) and `context.DeadlineExceeded` (504) first
- **Testing**: ALL errors (sentinel + HTTP codes) MUST have test cases
- **Error Assertions**: Tests MUST use error code definitions from `handlers/error_codes.go` (NOT literal strings)

### Test Database Isolation

- **testcontainers-go** with PostgreSQL (Docker required)
- **Truncation**: `defer truncateTables(db, "tables...")` with CASCADE
- **Truncate in reverse dependency order** (children before parents)
- **Centralize truncation logic** in helper function
- **Parallel**: `t.Parallel()` safe

### Context-Aware Operations

Constitution Principle XII:
- Service methods MUST accept `context.Context` as first parameter
- HTTP handlers MUST use `r.Context()` and pass to services
- Database operations MUST use `db.WithContext(ctx)`
- External HTTP calls MUST use `http.NewRequestWithContext(ctx, ...)`
- Long-running operations MUST check context cancellation periodically
- Tests MUST verify context cancellation behavior
- **Rationale**: Enables timeout handling, graceful cancellation, trace propagation, prevents resource leaks

### Distributed Tracing

Constitution Principle XI:
- HTTP endpoints MUST create OpenTracing spans with operation name (e.g., "POST /api/products")
- Service methods SHOULD create child spans (e.g., "ProductService.Create")
- Database operations: ONE span per transaction (NOT per SQL query - too much overhead)
- External calls (HTTP, gRPC) MUST propagate trace context
- Errors MUST set `span.SetTag("error", true)`
- Spans MUST include tags: `http.method`, `http.url`, `http.status_code`
- Development/Tests: Use `opentracing.NoopTracer{}`
- Production: Configure from environment variables (Jaeger, Zipkin, Datadog, etc.)
- **Rationale**: Provides observability for debugging latency, understanding request flows, identifying bottlenecks

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |
