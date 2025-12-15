# Tasks: SPA Authentication with Role-Based Access Control

**Input**: Design documents from `/specs/001-spa-auth-rbac/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Testing**: TDD mandatory - write tests BEFORE implementation (protobuf → tests → implementation).
**Organization**: Tasks grouped by user story for independent implementation.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Go Project Structure

- **Protobuf**: `api/proto/auth/v1/` (source), `api/gen/auth/v1/` (generated)
- **Services**: `services/` (PUBLIC - business logic, returns protobuf)
- **Handlers**: `handlers/` (PUBLIC - HTTP layer with `*_test.go`)
- **Models**: `internal/models/` (GORM - internal only)
- **Fixtures**: `testutil/` (helpers and fixtures)

---

## Phase 1: Setup

- [ ] T001 Initialize Go module with `go mod init github.com/user/spa_auth`
- [ ] T002 [P] Create directory structure: `api/proto/auth/v1/`, `api/gen/auth/v1/`, `services/`, `handlers/`, `internal/models/`, `internal/config/`, `testutil/`, `cmd/api/`, `cmd/seed/`, `lambda/auth-validator/`
- [ ] T003 [P] Create `go.mod` with dependencies: gorm, postgres driver, jwt-go, bcrypt, oauth2, protobuf, testcontainers-go
- [ ] T004 [P] Setup protobuf tooling: install `protoc`, `protoc-gen-go`, create `buf.yaml` or Makefile for code generation
- [ ] T005 Copy proto files from `specs/001-spa-auth-rbac/contracts/` to `api/proto/auth/v1/`
- [ ] T006 Run protoc to generate Go code in `api/gen/auth/v1/`

---

## Phase 2: Foundation (⚠️ BLOCKS all user stories)

- [ ] T010 Setup testcontainers-go in `testutil/db.go` with `SetupTestDB()`, `TruncateTables()` functions
- [ ] T011 [P] Create GORM models in `internal/models/user.go` (User entity from data-model.md)
- [ ] T012 [P] Create GORM models in `internal/models/role.go` (Role entity with is_system flag)
- [ ] T013 [P] Create GORM models in `internal/models/spa_section.go` (SpaSection entity)
- [ ] T014 [P] Create GORM models in `internal/models/role_permission.go` (RolePermission junction)
- [ ] T015 [P] Create GORM models in `internal/models/user_role.go` (UserRole junction)
- [ ] T016 [P] Create GORM models in `internal/models/session.go` (Session entity)
- [ ] T017 [P] Create GORM models in `internal/models/password_reset_token.go` (PasswordResetToken entity)
- [ ] T018 Create `services/migrations.go` with `AutoMigrate()` function for all models
- [ ] T019 [P] Create sentinel errors in `services/errors.go` (ErrInvalidCredentials, ErrUserNotFound, ErrRoleNotFound, ErrSessionExpired, etc.)
- [ ] T020 [P] Create HTTP error codes in `handlers/error_codes.go` with ServiceErr mapping
- [ ] T021 [P] Create `HandleServiceError()` function in `handlers/error_codes.go`
- [ ] T022 [P] Create configuration loading in `internal/config/config.go` (env vars for JWT, OAuth, DB, etc.)
- [ ] T023 [P] Setup OpenTracing NoopTracer in `handlers/tracing.go`
- [ ] T024 Create base routing in `handlers/routes.go` with health check endpoint
- [ ] T025 [P] Create test fixtures in `testutil/fixtures.go` with `CreateTestUser()`, `CreateTestRole()`, `CreateTestSpaSection()`
- [ ] T026 Create `services/jwt_service.go` with JWT generation and validation (HS256, configurable secret/TTL)
- [ ] T027 Create `services/password_service.go` with bcrypt hashing (cost 12) and verification

---

## Phase 3: User Story 1 - Email/Password Login (P1) 🎯 MVP

**Goal**: Users can log in with email/password and access the protected SPA  
**Acceptance Scenarios**: US1-AS1, US1-AS2, US1-AS3, US1-AS4

### Step 1: Tests (Red) 🔴

- [ ] T030 [US1] Write tests for US1-AS1 (successful login) in `handlers/auth_handler_test.go`
- [ ] T031 [US1] Write tests for US1-AS2 (incorrect password) in `handlers/auth_handler_test.go`
- [ ] T032 [US1] Write tests for US1-AS3 (logout) in `handlers/auth_handler_test.go`
- [ ] T033 [US1] Write tests for US1-AS4 (unauthenticated redirect) in `handlers/auth_handler_test.go`
- [ ] T034 [US1] Add edge case tests: empty email/password, invalid email format, password < 8 chars, SQL injection, rate limiting
- [ ] T035 [US1] **RUN TESTS** - Verify FAIL (red) ❌

### Step 2: Implementation (Green) 🟢

- [ ] T040 [US1] Create `services/auth_service.go` with `Login(ctx, email, password)` method
- [ ] T041 [US1] Create `services/session_service.go` with `CreateSession()`, `ValidateSession()`, `InvalidateSession()`
- [ ] T042 [US1] Create `handlers/auth_handler.go` with `POST /api/v1/auth/login` endpoint
- [ ] T043 [US1] Add `POST /api/v1/auth/logout` endpoint to `handlers/auth_handler.go`
- [ ] T044 [US1] Add `GET /api/v1/auth/me` endpoint to return current user info
- [ ] T045 [US1] Create auth middleware in `handlers/middleware.go` for token validation
- [ ] T046 [US1] Add rate limiting middleware in `handlers/middleware.go` (5 attempts/15 min)
- [ ] T047 [US1] Add routes to `handlers/routes.go`
- [ ] T048 [US1] Add OpenTracing spans to auth handler and service
- [ ] T049 [US1] **RUN TESTS** - Verify PASS (green) ✅

### Step 3: Refactor & Verify ♻️

- [ ] T050 [US1] Refactor: extract helpers, improve error messages
- [ ] T051 [US1] **RUN TESTS** with `-race` flag ✅
- [ ] T052 [US1] Run `go test -cover` - verify >80% coverage for auth

---

## Phase 4: User Story 2 - Google OAuth Login (P2)

**Goal**: Users can log in via Google OAuth if their email is pre-registered  
**Acceptance Scenarios**: US2-AS1, US2-AS2, US2-AS3

### Step 1: Tests (Red) 🔴

- [ ] T060 [US2] Write tests for US2-AS1 (successful OAuth link) in `handlers/auth_handler_test.go`
- [ ] T061 [US2] Write tests for US2-AS2 (email not registered) in `handlers/auth_handler_test.go`
- [ ] T062 [US2] Write tests for US2-AS3 (OAuth cancelled) in `handlers/auth_handler_test.go`
- [ ] T063 [US2] Add edge case tests: malformed callback params, invalid state token
- [ ] T064 [US2] **RUN TESTS** - Verify FAIL (red) ❌

### Step 2: Implementation (Green) 🟢

- [ ] T070 [US2] Create `services/oauth_service.go` with Google OAuth flow (authorization URL, token exchange)
- [ ] T071 [US2] Add `GET /api/v1/oauth/google/start` endpoint to `handlers/auth_handler.go`
- [ ] T072 [US2] Add `GET /api/v1/oauth/google/callback` endpoint to `handlers/auth_handler.go`
- [ ] T073 [US2] Implement email verification and Google account linking in `services/oauth_service.go`
- [ ] T074 [US2] Add routes to `handlers/routes.go`
- [ ] T075 [US2] **RUN TESTS** - Verify PASS (green) ✅

### Step 3: Refactor & Verify ♻️

- [ ] T076 [US2] Refactor and add OpenTracing spans
- [ ] T077 [US2] **RUN TESTS** with `-race` flag ✅

---

## Phase 5: User Story 3 - Super Admin User Management (P3)

**Goal**: Super admin can create, modify, and deactivate user accounts  
**Acceptance Scenarios**: US3-AS1, US3-AS2, US3-AS3, US3-AS4

### Step 1: Tests (Red) 🔴

- [ ] T080 [US3] Write tests for US3-AS1 (create user) in `handlers/user_handler_test.go`
- [ ] T081 [US3] Write tests for US3-AS2 (modify user role) in `handlers/user_handler_test.go`
- [ ] T082 [US3] Write tests for US3-AS3 (deactivate user) in `handlers/user_handler_test.go`
- [ ] T083 [US3] Write tests for US3-AS4 (reset password) in `handlers/user_handler_test.go`
- [ ] T084 [US3] Add edge case tests: duplicate email, non-super-admin access denied, invalid role
- [ ] T085 [US3] **RUN TESTS** - Verify FAIL (red) ❌

### Step 2: Implementation (Green) 🟢

- [ ] T090 [US3] Create `services/user_service.go` with `CreateUser()`, `UpdateUser()`, `DeactivateUser()`, `ReactivateUser()`
- [ ] T091 [US3] Add `AdminResetPassword()` to `services/user_service.go`
- [ ] T092 [US3] Create `handlers/user_handler.go` with CRUD endpoints for users
- [ ] T093 [US3] Add super-admin-only middleware check in `handlers/middleware.go`
- [ ] T094 [US3] Add routes to `handlers/routes.go`
- [ ] T095 [US3] **RUN TESTS** - Verify PASS (green) ✅

### Step 3: Refactor & Verify ♻️

- [ ] T096 [US3] Refactor and add OpenTracing spans
- [ ] T097 [US3] **RUN TESTS** with `-race` flag ✅

---

## Phase 6: User Story 4 - Role Configuration and Management (P4)

**Goal**: Super admin can create, configure, and manage custom roles with SPA section permissions  
**Acceptance Scenarios**: US4-AS1, US4-AS2, US4-AS3, US4-AS4, US4-AS5

### Step 1: Tests (Red) 🔴

- [ ] T100 [US4] Write tests for US4-AS1 (create role) in `handlers/role_handler_test.go`
- [ ] T101 [US4] Write tests for US4-AS2 (list roles) in `handlers/role_handler_test.go`
- [ ] T102 [US4] Write tests for US4-AS3 (update role permissions) in `handlers/role_handler_test.go`
- [ ] T103 [US4] Write tests for US4-AS4 (delete role without users) in `handlers/role_handler_test.go`
- [ ] T104 [US4] Write tests for US4-AS5 (delete role with users - prevented) in `handlers/role_handler_test.go`
- [ ] T105 [US4] Add edge case tests: duplicate role name, delete system role, invalid section IDs
- [ ] T106 [US4] **RUN TESTS** - Verify FAIL (red) ❌

### Step 2: Implementation (Green) 🟢

- [ ] T110 [US4] Create `services/role_service.go` with `CreateRole()`, `ListRoles()`, `UpdateRole()`, `DeleteRole()`
- [ ] T111 [US4] Create `services/spa_section_service.go` with CRUD for SPA sections
- [ ] T112 [US4] Create `handlers/role_handler.go` with role CRUD endpoints
- [ ] T113 [US4] Add SPA section management endpoints to `handlers/role_handler.go`
- [ ] T114 [US4] Add routes to `handlers/routes.go`
- [ ] T115 [US4] **RUN TESTS** - Verify PASS (green) ✅

### Step 3: Refactor & Verify ♻️

- [ ] T116 [US4] Refactor and add OpenTracing spans
- [ ] T117 [US4] **RUN TESTS** with `-race` flag ✅

---

## Phase 7: User Story 5 - Role-Based Access Enforcement (P5)

**Goal**: System enforces role-based access to SPA sections  
**Acceptance Scenarios**: US5-AS1, US5-AS2, US5-AS3

### Step 1: Tests (Red) 🔴

- [ ] T120 [US5] Write tests for US5-AS1 (access denied for restricted section) in `handlers/auth_handler_test.go`
- [ ] T121 [US5] Write tests for US5-AS2 (super_admin access all) in `handlers/auth_handler_test.go`
- [ ] T122 [US5] Write tests for US5-AS3 (permission changes immediate) in `handlers/auth_handler_test.go`
- [ ] T123 [US5] Add edge case tests: invalid section key, user with no roles
- [ ] T124 [US5] **RUN TESTS** - Verify FAIL (red) ❌

### Step 2: Implementation (Green) 🟢

- [ ] T130 [US5] Add `CheckSectionAccess()` to `services/role_service.go`
- [ ] T131 [US5] Add `GetUserSections()` to `services/role_service.go`
- [ ] T132 [US5] Add `POST /api/v1/permissions/check-section` endpoint to `handlers/role_handler.go`
- [ ] T133 [US5] Add `GET /api/v1/users/{id}/sections` endpoint to `handlers/user_handler.go`
- [ ] T134 [US5] Include user sections in JWT claims for client-side enforcement
- [ ] T135 [US5] **RUN TESTS** - Verify PASS (green) ✅

### Step 3: Refactor & Verify ♻️

- [ ] T136 [US5] Refactor and add OpenTracing spans
- [ ] T137 [US5] **RUN TESTS** with `-race` flag ✅

---

## Phase 8: User Story 6 - Password Reset (P6)

**Goal**: Users can reset their password via email  
**Acceptance Scenarios**: US6-AS1, US6-AS2, US6-AS3

### Step 1: Tests (Red) 🔴

- [ ] T140 [US6] Write tests for US6-AS1 (request password reset) in `handlers/auth_handler_test.go`
- [ ] T141 [US6] Write tests for US6-AS2 (reset with valid token) in `handlers/auth_handler_test.go`
- [ ] T142 [US6] Write tests for US6-AS3 (expired token) in `handlers/auth_handler_test.go`
- [ ] T143 [US6] Add edge case tests: email not found (silent success), token already used, weak password
- [ ] T144 [US6] **RUN TESTS** - Verify FAIL (red) ❌

### Step 2: Implementation (Green) 🟢

- [ ] T150 [US6] Add `RequestPasswordReset()`, `ResetPassword()` to `services/password_service.go`
- [ ] T151 [US6] Create email service interface in `services/email_service.go`
- [ ] T152 [US6] Add `POST /api/v1/password/reset/request` endpoint to `handlers/auth_handler.go`
- [ ] T153 [US6] Add `POST /api/v1/password/reset` endpoint to `handlers/auth_handler.go`
- [ ] T154 [US6] Add routes to `handlers/routes.go`
- [ ] T155 [US6] **RUN TESTS** - Verify PASS (green) ✅

### Step 3: Refactor & Verify ♻️

- [ ] T156 [US6] Refactor and add OpenTracing spans
- [ ] T157 [US6] **RUN TESTS** with `-race` flag ✅

---

## Phase 9: User Story 7 - Session Management (P7)

**Goal**: Sessions persist appropriately and expire correctly  
**Acceptance Scenarios**: US7-AS1, US7-AS2, US7-AS3

### Step 1: Tests (Red) 🔴

- [ ] T160 [US7] Write tests for US7-AS1 (session persistence) in `handlers/auth_handler_test.go`
- [ ] T161 [US7] Write tests for US7-AS2 (expired session redirect) in `handlers/auth_handler_test.go`
- [ ] T162 [US7] Write tests for US7-AS3 (inactivity timeout) in `handlers/auth_handler_test.go`
- [ ] T163 [US7] Add edge case tests: refresh token rotation, concurrent sessions
- [ ] T164 [US7] **RUN TESTS** - Verify FAIL (red) ❌

### Step 2: Implementation (Green) 🟢

- [ ] T170 [US7] Add `RefreshToken()` to `services/session_service.go`
- [ ] T171 [US7] Add session activity tracking to `services/session_service.go`
- [ ] T172 [US7] Add `POST /api/v1/auth/refresh` endpoint to `handlers/auth_handler.go`
- [ ] T173 [US7] Add `POST /api/v1/auth/validate` endpoint for Lambda@Edge
- [ ] T174 [US7] Update middleware to check session expiry and activity
- [ ] T175 [US7] **RUN TESTS** - Verify PASS (green) ✅

### Step 3: Refactor & Verify ♻️

- [ ] T176 [US7] Refactor and add OpenTracing spans
- [ ] T177 [US7] **RUN TESTS** with `-race` flag ✅

---

## Phase 10: Integration & Main Entry Point

- [ ] T180 Create `cmd/api/main.go` with server startup, config loading, DB connection
- [ ] T181 Create `cmd/seed/main.go` for super admin seeding from env vars
- [ ] T182 Add graceful shutdown handling to `cmd/api/main.go`
- [ ] T183 Create Lambda@Edge validator in `lambda/auth-validator/index.js`
- [ ] T184 Create `lambda/auth-validator/jwt.js` with JWT verification
- [ ] T185 Create `lambda/auth-validator/package.json` with minimal dependencies

---

## Phase 11: Polish

- [ ] T190 [P] Run `go test -cover ./...` - verify >80% coverage
- [ ] T191 [P] Run `go test -race ./...` - verify no race conditions
- [ ] T192 [P] Run `go vet ./...` - fix any issues
- [ ] T193 Verify ALL errors and scenarios have tests
- [ ] T194 Verify services are in public packages (not internal/)
- [ ] T195 Code cleanup: remove temp files, ensure comments explain WHY
- [ ] T196 Security review: SQL injection, XSS prevention, password hashing
- [ ] T197 Create README.md with setup instructions
- [ ] T198 Create .env.example with all required environment variables

---

## Execution Order

**Phase Dependencies**:
- Phase 1 (Setup) → Phase 2 (Foundation) → Phase 3+ (User Stories) → Phase 10-11 (Integration & Polish)
- Foundation BLOCKS all user stories
- User stories can proceed in parallel after Foundation (US1 recommended first as MVP)

**TDD Cycle** (Constitution Principle VI):
- Tests (red) → Implementation (green) → Refactor → Verify
- Tests BEFORE implementation (mandatory)
- Run tests after EVERY code change
- Story complete ONLY when all tests pass

**Parallel**: Tasks marked [P] can run in parallel

## Implementation Strategy

**MVP First** (Story 1 only): Setup → Foundation → US1 (TDD) → Validate → Deploy

**Incremental**: Each story follows TDD cycle, checkpoint after each

**Suggested Order**:
1. US1 (Email/Password Login) - Core authentication
2. US3 (User Management) - Needed to create test users
3. US4 (Role Configuration) - Needed before enforcement
4. US5 (Access Enforcement) - Depends on US4
5. US2 (Google OAuth) - Independent, can be parallel
6. US6 (Password Reset) - Independent
7. US7 (Session Management) - Refinement

---

## Summary

| Phase | User Story | Task Count | Parallel Opportunities |
|-------|------------|------------|------------------------|
| 1 | Setup | 6 | 4 |
| 2 | Foundation | 18 | 12 |
| 3 | US1 - Email/Password Login | 23 | 0 (sequential TDD) |
| 4 | US2 - Google OAuth | 18 | 0 |
| 5 | US3 - User Management | 18 | 0 |
| 6 | US4 - Role Configuration | 18 | 0 |
| 7 | US5 - Access Enforcement | 18 | 0 |
| 8 | US6 - Password Reset | 18 | 0 |
| 9 | US7 - Session Management | 18 | 0 |
| 10 | Integration | 6 | 0 |
| 11 | Polish | 9 | 3 |
| **Total** | | **170** | **19** |

**MVP Scope**: Phase 1 + Phase 2 + Phase 3 (US1) = 47 tasks
