# Feature Specification: SPA Authentication with Role-Based Access Control

**Feature Branch**: `001-spa-auth-rbac`  
**Created**: 2024-12-15  
**Status**: Draft  
**Input**: User description: "SPA authentication package with Google OAuth and email/password login, plus role-based access control for CloudFront/S3 deployed application"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Email/Password Login (Priority: P1)

A user whose account has been created by the super admin visits the SPA and logs in using their email address and password. This is the foundational authentication flow that enables access to the protected application.

**Why this priority**: Core authentication is required before any other feature can work. Without login capability, users cannot access the protected SPA at all.

**Independent Test**: Can be fully tested by logging in with admin-created credentials, accessing the SPA, and logging out. Delivers basic access control to the SPA.

**Acceptance Scenarios**:

1. **US1-AS1**: **Given** a user account created by the super admin, **When** the user enters their correct email and password on the login page, **Then** the system authenticates them and redirects to the SPA.
2. **US1-AS2**: **Given** a user on the login page, **When** they enter an incorrect password, **Then** the system displays an error message and does not grant access.
3. **US1-AS3**: **Given** an authenticated user in the SPA, **When** they click "Logout", **Then** their session is terminated and they are redirected to the login page.
4. **US1-AS4**: **Given** an unauthenticated user, **When** they attempt to access the SPA directly, **Then** the system redirects them to the login page.

---

### User Story 2 - Google OAuth Login (Priority: P2)

A user whose account has been created by the super admin prefers to use their Google account to sign in. The super admin has pre-registered the user's email, and when they sign in with Google using that email, the system links their Google account for future logins.

**Why this priority**: Google OAuth provides a frictionless login experience and is a common user expectation. However, email/password must work first as the baseline.

**Independent Test**: Can be fully tested by clicking Google sign-in, completing OAuth flow, and verifying access to the SPA for a pre-registered user.

**Acceptance Scenarios**:

1. **US2-AS1**: **Given** a user account created by the super admin with a specific email, **When** the user clicks "Sign in with Google" and authorizes with that same email, **Then** the system links the Google account and redirects them to the SPA.
2. **US2-AS2**: **Given** a user attempting Google OAuth with an email not registered by the super admin, **When** they complete the Google authorization, **Then** the system denies access and displays a message that their account does not exist.
3. **US2-AS3**: **Given** a user in the Google OAuth flow, **When** they cancel or deny authorization, **Then** the system returns them to the login page with an appropriate message.

---

### User Story 3 - Super Admin User Management (Priority: P3)

The super admin (seeded at system initialization) creates and manages all user accounts. Users cannot self-register; they must be created by the super admin who assigns their email, initial password, and role.

**Why this priority**: User management is essential for the invite-only access model. Must be in place before regular users can access the system.

**Independent Test**: Can be tested by the super admin creating a new user, assigning a role, and verifying the new user can log in with assigned credentials.

**Acceptance Scenarios**:

1. **US3-AS1**: **Given** the super admin is logged in, **When** they create a new user with email, password, and role, **Then** the system creates the user account and the new user can log in.
2. **US3-AS2**: **Given** the super admin is logged in, **When** they modify an existing user's role, **Then** the user's permissions are updated immediately.
3. **US3-AS3**: **Given** the super admin is logged in, **When** they deactivate a user account, **Then** the user is immediately logged out and cannot log in again.
4. **US3-AS4**: **Given** the super admin is logged in, **When** they reset a user's password, **Then** the user receives a new password and must use it to log in.

---

### User Story 4 - Role Configuration and Management (Priority: P4)

The super admin creates and configures custom roles that map to specific SPA sections/routes. Roles are fully configurable with CRUD operations, allowing the super admin to define which sections each role can access.

**Why this priority**: Role configuration must be in place before roles can be assigned to users and enforced.

**Independent Test**: Can be tested by the super admin creating a custom role, assigning it permissions for specific SPA sections, and verifying users with that role can only access those sections.

**Acceptance Scenarios**:

1. **US4-AS1**: **Given** the super admin is logged in, **When** they create a new role with a name, description, and list of permitted SPA sections, **Then** the system creates the role and it becomes available for assignment.
2. **US4-AS2**: **Given** the super admin is logged in, **When** they view the list of roles, **Then** the system displays all roles with their configured permissions.
3. **US4-AS3**: **Given** the super admin is logged in, **When** they update an existing role's permissions (add/remove SPA sections), **Then** the changes take effect immediately for all users with that role.
4. **US4-AS4**: **Given** the super admin is logged in, **When** they delete a role that has no users assigned, **Then** the system removes the role.
5. **US4-AS5**: **Given** the super admin is logged in, **When** they attempt to delete a role that has users assigned, **Then** the system prevents deletion and displays a warning.

---

### User Story 5 - Role-Based Access Enforcement (Priority: P5)

Users are assigned roles by the super admin, and the system enforces access based on the role's configured permissions for SPA sections.

**Why this priority**: Enforcement depends on roles being configured first.

**Independent Test**: Can be tested by logging in as users with different roles and verifying access to role-restricted sections.

**Acceptance Scenarios**:

1. **US5-AS1**: **Given** a user with a role that permits "dashboard" section only, **When** they attempt to access the "settings" section, **Then** the system denies access and displays an appropriate message.
2. **US5-AS2**: **Given** a user with "super_admin" role, **When** they access any section of the SPA, **Then** the system grants access to all features.
3. **US5-AS3**: **Given** a user whose role permissions were just changed by the super admin, **When** they navigate to a newly restricted section, **Then** the system enforces the new permissions without requiring re-login.

---

### User Story 6 - Password Reset (Priority: P6)

A user who was created with email/password has forgotten their password and needs to regain access to their account.

**Why this priority**: Essential for email/password users but not blocking core functionality.

**Independent Test**: Can be tested by requesting password reset, receiving email, and setting new password.

**Acceptance Scenarios**:

1. **US6-AS1**: **Given** a user on the login page, **When** they click "Forgot Password" and enter their registered email, **Then** the system sends a password reset link to that email.
2. **US6-AS2**: **Given** a user with a valid password reset link, **When** they click the link and enter a new password, **Then** the system updates their password and allows login with the new credentials.
3. **US6-AS3**: **Given** a user with an expired password reset link (older than 24 hours), **When** they click the link, **Then** the system displays an error and prompts them to request a new link.

---

### User Story 7 - Session Management (Priority: P7)

Users need their sessions to persist appropriately and be secured against unauthorized access.

**Why this priority**: Important for security and UX but builds on core authentication.

**Independent Test**: Can be tested by verifying session persistence across browser refreshes and automatic logout on token expiry.

**Acceptance Scenarios**:

1. **US7-AS1**: **Given** an authenticated user who closes their browser, **When** they return within the session validity period, **Then** they remain logged in without re-authentication.
2. **US7-AS2**: **Given** an authenticated user whose session has expired, **When** they attempt to access the SPA, **Then** the system redirects them to the login page.
3. **US7-AS3**: **Given** an authenticated user, **When** they are inactive for a configurable period, **Then** the system automatically logs them out.

---

### Edge Cases

**Invalid or Missing Input**:
- Empty email or password fields display validation errors before submission
- Invalid email format (missing @, invalid domain) is rejected with specific error message
- Password shorter than minimum length (8 characters) is rejected
- SQL injection or XSS attempts in login fields are sanitized and rejected
- Malformed OAuth callback parameters are rejected

**Boundary Conditions**:
- Maximum password length (128 characters) is enforced
- Email addresses at maximum length (254 characters) are handled correctly
- Rapid successive login attempts (rate limiting) are throttled after 5 failed attempts
- Concurrent sessions from multiple devices are handled per configuration

**Access Control**:
- Unauthenticated requests to protected SPA routes redirect to login
- Expired tokens return 401 and redirect to login
- Invalid tokens (tampered/malformed) are rejected
- Users with revoked access are immediately logged out
- Role changes take effect without requiring re-authentication

**Data Conflicts**:
- Admin creating user with already-registered email displays appropriate error
- Google OAuth with email not in system denies access with clear message
- Simultaneous password reset requests use only the most recent token

**System Errors**:
- Google OAuth service unavailable displays fallback message with retry option
- Database connection failures display user-friendly error without technical details
- Email service failures for password reset are logged and user is notified to retry

## Requirements *(mandatory)*

### Functional Requirements

**Authentication**:
- **FR-001**: System MUST authenticate users via email/password credentials
- **FR-002**: System MUST validate email format and password strength (minimum 8 characters)
- **FR-003**: System MUST authenticate users via Google OAuth 2.0 (for pre-registered emails only)
- **FR-004**: System MUST link Google accounts to existing user accounts with matching email addresses
- **FR-005**: System MUST deny Google OAuth login for emails not registered in the system
- **FR-006**: System MUST issue secure session tokens upon successful authentication
- **FR-007**: System MUST provide logout functionality that invalidates the current session

**User Management (Super Admin Only)**:
- **FR-008**: System MUST seed a super admin account on initial deployment
- **FR-009**: Super admin MUST be able to create new user accounts with email, password, and role
- **FR-010**: Super admin MUST be able to modify user roles
- **FR-011**: Super admin MUST be able to deactivate/reactivate user accounts
- **FR-012**: Super admin MUST be able to reset user passwords
- **FR-013**: System MUST NOT allow self-registration; only super admin can create users

**Password Management**:
- **FR-014**: System MUST allow users to request password reset via email
- **FR-015**: System MUST send password reset links that expire after 24 hours
- **FR-016**: System MUST allow users to set a new password via valid reset link
- **FR-017**: System MUST securely hash passwords before storage

**Session Management**:
- **FR-018**: System MUST maintain user sessions across browser refreshes
- **FR-019**: System MUST expire sessions after configurable inactivity period
- **FR-020**: System MUST validate session tokens on each protected request
- **FR-021**: System MUST redirect unauthenticated users to login page

**Role Management (Super Admin Only)**:
- **FR-022**: Super admin MUST be able to create custom roles with name and description
- **FR-023**: Super admin MUST be able to configure which SPA sections/routes each role can access
- **FR-024**: Super admin MUST be able to view all roles and their configured permissions
- **FR-025**: Super admin MUST be able to update role permissions (add/remove SPA sections)
- **FR-026**: Super admin MUST be able to delete roles that have no users assigned
- **FR-027**: System MUST prevent deletion of roles that have users assigned
- **FR-028**: System MUST provide a predefined "super_admin" role that cannot be deleted or modified

**Role-Based Access Enforcement**:
- **FR-029**: System MUST enforce role-based permissions on SPA routes/sections
- **FR-030**: Super admin MUST be able to assign and modify user roles
- **FR-031**: System MUST apply role/permission changes immediately without requiring re-login
- **FR-032**: System MUST deny access to unauthorized sections with appropriate feedback

**Security**:
- **FR-033**: System MUST rate-limit failed login attempts (max 5 per 15 minutes per IP/email)
- **FR-034**: System MUST protect against CSRF attacks
- **FR-035**: System MUST sanitize all user inputs to prevent injection attacks
- **FR-036**: System MUST use secure, HTTP-only cookies for session management

**Error Handling Requirements** (Constitution Principle XIII):
- **FR-ERR-001**: System MUST provide clear error messages when authentication fails
- **FR-ERR-002**: System MUST distinguish between invalid credentials and account not found (with care for security)
- **FR-ERR-003**: Error messages MUST NOT expose sensitive technical details to users

### Key Entities

- **User**: Represents an authenticated user; attributes include unique identifier, email, hashed password (optional for OAuth-only users), authentication provider(s), active status, created_by (reference to super admin), creation timestamp, last login timestamp
- **Role**: Represents a configurable permission level; attributes include unique identifier, role name, description, is_system (true for super_admin), list of permitted SPA sections/routes
- **SpaSection**: Represents a section/route in the SPA that can be protected; attributes include unique identifier, section key (e.g., "dashboard", "settings", "reports"), display name, description
- **RolePermission**: Association between Role and SpaSection; defines which sections a role can access
- **UserRole**: Association between User and Role; supports multiple roles per user
- **Session**: Represents an active user session; attributes include session token, user reference, creation time, expiration time, last activity time
- **PasswordResetToken**: Temporary token for password reset; attributes include token value, user reference, creation time, expiration time, used status

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Super admin can create a new user account in under 30 seconds
- **SC-002**: Users can complete login in under 30 seconds
- **SC-003**: Google OAuth login completes in under 10 seconds (excluding Google's authentication time)
- **SC-004**: 95% of users successfully complete login on first attempt
- **SC-005**: Password reset email is delivered within 2 minutes of request
- **SC-006**: Role permission changes take effect within 1 second
- **SC-007**: System handles 100 concurrent authentication requests without degradation
- **SC-008**: Failed login attempts are rate-limited, blocking after 5 failures within 15 minutes

### Verification Requirements

All acceptance scenarios and edge cases listed above MUST be:

- **Testable**: Each scenario can be demonstrated and verified in a test environment
- **Complete**: Tests verify the entire expected behavior, not partial outcomes
- **Automated**: Tests can be run repeatedly without manual intervention
- **Independent**: Each scenario can be tested separately

Every acceptance scenario (US#-AS#) listed above will have a corresponding automated test that validates the expected outcome matches the "Then" clause (Constitution Principle VIII).

### Testing Requirements

Implementation MUST follow Constitution Testing Principles:

- **I. Integration Testing (No Mocking)**: Real PostgreSQL via testcontainers (NO mocking in implementation code), test isolation with table truncation, fixtures via GORM. Mocking ONLY in test code (`*_test.go`) for external systems with written justification. Mock implementations NEVER in production code files.
- **II. Table-Driven Design**: Test cases as slices of structs with descriptive `name` fields, execute using `t.Run(testCase.name, func(t *testing.T) {...})`
- **III. Comprehensive Edge Case Coverage**: All edge cases listed above MUST have corresponding tests (input validation, boundary conditions, auth, data state, database, HTTP)
- **IV. ServeHTTP Endpoint Testing**: Tests call root mux ServeHTTP (NOT individual handlers) using `httptest.ResponseRecorder`, identical routing configuration from shared routes package, HTTP path patterns, `r.PathValue()` for parameters
- **V. Protobuf Data Structures**: API contracts in `.proto` files (single source of truth), tests use protobuf structs (NO `map[string]interface{}`), compare using `cmp.Diff()` with `protocmp.Transform()` (NO `==`, `reflect.DeepEqual`, or individual field checks). Expected values MUST be derived from TEST FIXTURES (request data, database fixtures, config). Copy from response ONLY for truly random fields: UUIDs, timestamps, crypto-rand tokens.
- **VI. Continuous Test Verification**: Tests MUST be executed after EVERY code change. Run `go test -v ./...` and `go test -v -race ./...` for concurrency safety. Tests MUST pass before commit. Test failures MUST be fixed immediately (NO skipping/disabling tests).
- **VII. Root Cause Tracing (Debugging Discipline)**: When problems occur, MUST trace backward through call chain to find root cause. Distinguish symptoms from root causes. Fixes MUST address source, NOT work around symptoms. Test cases MUST NOT be removed or weakened. Use debuggers and logging to understand control flow.
- **VIII. Acceptance Scenario Coverage (Spec-to-Test Mapping)**: Every user scenario (US#-AS#) in this spec MUST have corresponding automated test. Test case names MUST reference source scenarios (e.g., "US1-AS1: New customer enrolls"). Tests MUST validate complete "Then" clause, not partial behavior.
- **IX. Test Coverage & Gap Analysis**: Run `go test -coverprofile=coverage.out ./...` and `go tool cover -func=coverage.out` to identify gaps. Target >80% coverage for business logic. Remove dead code if unreachable.

### Architecture Requirements

Implementation MUST follow Constitution System Architecture Principles:

- **X. Service Layer Architecture (Dependency Injection)**: Business logic MUST be Go interfaces (service layer). Services MUST NOT depend on HTTP types (only `context.Context` allowed). Handlers MUST be thin wrappers delegating to services. Services and handlers MUST be in public packages (NOT `internal/`) for reusability. External dependencies MUST be injected via builder pattern: `NewService(db).WithLogger(log).Build()`. Service methods MUST use protobuf structs for ALL parameters and return types (NO primitives, NO maps). `cmd/main.go` MUST ONLY call handlers or services (NEVER `internal/` packages directly).

- **XI. Distributed Tracing (OpenTracing)**: HTTP endpoints MUST create OpenTracing spans with operation name (e.g., "POST /api/products"). Service methods SHOULD create child spans (e.g., "ProductService.Create"). Database operations: ONE span per transaction (NOT per SQL query - too much overhead). External calls (HTTP, gRPC) MUST propagate trace context. Errors MUST set `span.SetTag("error", true)`. Spans MUST include tags: `http.method`, `http.url`, `http.status_code`. Development/Tests use `opentracing.NoopTracer{}`, Production configured from environment variables.

- **XII. Context-Aware Operations**: Service methods MUST accept `context.Context` as first parameter. HTTP handlers MUST use `r.Context()`. Database operations MUST use `db.WithContext(ctx)`. External HTTP calls MUST use `http.NewRequestWithContext(ctx, ...)`. Long-running operations MUST check context cancellation periodically. Tests MUST verify context cancellation behavior. **Rationale**: Enables timeout handling, graceful cancellation, trace propagation, prevents resource leaks.

- **XIII. Comprehensive Error Handling**: Two-layer strategy with environment-aware details. **Service Layer**: Sentinel errors (package-level vars) with `fmt.Errorf("%w")` wrapping for error breadcrumb trail. **HTTP Layer**: Singleton error code struct with automatic service error mapping via `HandleServiceError()` (NO switch statements). **Environment-Aware Details**: ErrorResponse includes `details` field with full error chain by default; hidden when `HIDE_ERROR_DETAILS=true`. `RespondWithError(w, errCode, err)` always passes original error. **Testing**: ALL errors (sentinel + HTTP codes) MUST have test cases. Error assertions MUST use error code definitions (NOT literal strings).
