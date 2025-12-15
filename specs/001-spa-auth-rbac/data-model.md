# Data Model: SPA Authentication with Role-Based Access Control

**Feature Branch**: `001-spa-auth-rbac`  
**Date**: 2024-12-15  
**Source**: [spec.md](./spec.md) Key Entities section

## Entity Relationship Diagram

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│      User       │       │      Role       │       │   SpaSection    │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ id (PK)         │       │ id (PK)         │       │ id (PK)         │
│ email (unique)  │       │ name (unique)   │       │ key (unique)    │
│ password_hash   │       │ description     │       │ display_name    │
│ google_id       │       │ is_system       │       │ description     │
│ is_active       │       │ created_at      │       │ created_at      │
│ created_by (FK) │───┐   │ updated_at      │       │ updated_at      │
│ created_at      │   │   └────────┬────────┘       └────────┬────────┘
│ updated_at      │   │            │                         │
│ last_login_at   │   │            │                         │
└────────┬────────┘   │            │                         │
         │            │            │                         │
         │            │            ▼                         │
         ▼            │   ┌─────────────────┐                │
┌─────────────────┐   │   │ RolePermission  │◄───────────────┘
│    UserRole     │   │   ├─────────────────┤
├─────────────────┤   │   │ role_id (FK,PK) │
│ user_id (FK,PK) │───┘   │ section_id(FK,PK│
│ role_id (FK,PK) │───────│ created_at      │
│ assigned_at     │       └─────────────────┘
│ assigned_by(FK) │
└─────────────────┘
         │
         │
┌────────┴────────┐       ┌─────────────────┐
│     Session     │       │ PasswordReset   │
├─────────────────┤       │     Token       │
│ id (PK)         │       ├─────────────────┤
│ user_id (FK)    │       │ id (PK)         │
│ token_hash      │       │ user_id (FK)    │
│ refresh_token   │       │ token_hash      │
│ expires_at      │       │ expires_at      │
│ last_activity   │       │ used_at         │
│ ip_address      │       │ created_at      │
│ user_agent      │       └─────────────────┘
│ created_at      │
└─────────────────┘
```

## Entities

### User

Represents an authenticated user in the system.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, auto-generated | Unique identifier |
| `email` | VARCHAR(254) | UNIQUE, NOT NULL | User's email address |
| `password_hash` | VARCHAR(60) | NULL | bcrypt hash (null for OAuth-only users) |
| `google_id` | VARCHAR(255) | UNIQUE, NULL | Google OAuth subject ID |
| `is_active` | BOOLEAN | NOT NULL, DEFAULT true | Account active status |
| `created_by` | UUID | FK → User.id, NULL | Super admin who created this user (null for seeded admin) |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT now() | Account creation time |
| `updated_at` | TIMESTAMP | NOT NULL, DEFAULT now() | Last update time |
| `last_login_at` | TIMESTAMP | NULL | Last successful login |

**Validation Rules**:
- Email must be valid format (RFC 5322)
- Email max length: 254 characters
- Password hash only present if user has password auth enabled
- At least one auth method required (password_hash OR google_id)

**Indexes**:
- `idx_users_email` on `email` (unique)
- `idx_users_google_id` on `google_id` (unique, partial where not null)
- `idx_users_is_active` on `is_active`

---

### Role

Represents a configurable permission level that can be assigned to users. Roles are created and managed by the super admin.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, auto-generated | Unique identifier |
| `name` | VARCHAR(50) | UNIQUE, NOT NULL | Role name (e.g., viewer, editor, admin) |
| `description` | TEXT | NULL | Human-readable description |
| `is_system` | BOOLEAN | NOT NULL, DEFAULT false | True for system roles that cannot be deleted/modified |
| `created_by` | UUID | FK → User.id, NULL | Super admin who created this role |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT now() | Role creation time |
| `updated_at` | TIMESTAMP | NOT NULL, DEFAULT now() | Last update time |

**System Roles** (seeded on initialization, `is_system=true`):
- `super_admin`: Full system access including user/role management - **cannot be deleted or modified**

**Validation Rules**:
- Name must be lowercase alphanumeric with underscores
- Name max length: 50 characters
- System roles (`is_system=true`) cannot be deleted or have permissions modified

**Indexes**:
- `idx_roles_name` on `name` (unique)
- `idx_roles_is_system` on `is_system`

---

### SpaSection

Represents a section/route in the SPA that can be protected by role-based access control.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, auto-generated | Unique identifier |
| `key` | VARCHAR(100) | UNIQUE, NOT NULL | Section identifier (e.g., "dashboard", "settings", "reports") |
| `display_name` | VARCHAR(100) | NOT NULL | Human-readable name for UI |
| `description` | TEXT | NULL | Description of what this section contains |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT now() | Section creation time |
| `updated_at` | TIMESTAMP | NOT NULL, DEFAULT now() | Last update time |

**Validation Rules**:
- Key must be lowercase alphanumeric with hyphens/underscores
- Key max length: 100 characters
- Display name max length: 100 characters

**Indexes**:
- `idx_spa_sections_key` on `key` (unique)

**Example Sections**:
| Key | Display Name | Description |
|-----|--------------|-------------|
| `dashboard` | Dashboard | Main dashboard view |
| `users` | User Management | User administration (super_admin only) |
| `roles` | Role Management | Role configuration (super_admin only) |
| `settings` | Settings | Application settings |
| `reports` | Reports | Analytics and reports |

---

### UserRole

Association table linking users to their assigned roles.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `user_id` | UUID | PK, FK → User.id | User reference |
| `role_id` | UUID | PK, FK → Role.id | Role reference |
| `assigned_at` | TIMESTAMP | NOT NULL, DEFAULT now() | When role was assigned |
| `assigned_by` | UUID | FK → User.id, NULL | Admin who assigned the role |

**Constraints**:
- Composite primary key: (`user_id`, `role_id`)
- ON DELETE CASCADE for both foreign keys

**Indexes**:
- `idx_user_roles_user_id` on `user_id`
- `idx_user_roles_role_id` on `role_id`

---

### RolePermission

Association table linking roles to the SPA sections they can access. Super admin configures these mappings.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `role_id` | UUID | PK, FK → Role.id | Role reference |
| `section_id` | UUID | PK, FK → SpaSection.id | SPA section reference |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT now() | When permission was granted |

**Constraints**:
- Composite primary key: (`role_id`, `section_id`)
- ON DELETE CASCADE for both foreign keys

**Indexes**:
- `idx_role_permissions_role_id` on `role_id`
- `idx_role_permissions_section_id` on `section_id`

**Notes**:
- `super_admin` role implicitly has access to ALL sections (enforced in application logic, not stored)
- When a role is deleted, all its permissions are cascade deleted
- When a section is deleted, all permissions referencing it are cascade deleted

---

### Session

Represents an active user session.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, auto-generated | Unique identifier |
| `user_id` | UUID | FK → User.id, NOT NULL | User reference |
| `token_hash` | VARCHAR(64) | UNIQUE, NOT NULL | SHA-256 hash of access token |
| `refresh_token_hash` | VARCHAR(64) | UNIQUE, NOT NULL | SHA-256 hash of refresh token |
| `expires_at` | TIMESTAMP | NOT NULL | Access token expiration |
| `refresh_expires_at` | TIMESTAMP | NOT NULL | Refresh token expiration |
| `last_activity_at` | TIMESTAMP | NOT NULL, DEFAULT now() | Last activity timestamp |
| `ip_address` | INET | NULL | Client IP address |
| `user_agent` | VARCHAR(500) | NULL | Client user agent |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT now() | Session creation time |

**Validation Rules**:
- Access token TTL: 15 minutes (configurable)
- Refresh token TTL: 7 days (configurable)
- Inactivity timeout: configurable (default 30 minutes)

**Indexes**:
- `idx_sessions_user_id` on `user_id`
- `idx_sessions_token_hash` on `token_hash` (unique)
- `idx_sessions_refresh_token_hash` on `refresh_token_hash` (unique)
- `idx_sessions_expires_at` on `expires_at` (for cleanup)

**Cleanup**:
- Expired sessions should be periodically deleted
- Recommend: cron job or background worker every hour

---

### PasswordResetToken

Temporary token for password reset functionality.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, auto-generated | Unique identifier |
| `user_id` | UUID | FK → User.id, NOT NULL | User reference |
| `token_hash` | VARCHAR(64) | UNIQUE, NOT NULL | SHA-256 hash of reset token |
| `expires_at` | TIMESTAMP | NOT NULL | Token expiration (24 hours from creation) |
| `used_at` | TIMESTAMP | NULL | When token was used (null if unused) |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT now() | Token creation time |

**Validation Rules**:
- Token expiry: 24 hours (FR-015)
- Only one active token per user (new request invalidates old)
- Token is single-use (marked used_at on consumption)

**Indexes**:
- `idx_password_reset_tokens_user_id` on `user_id`
- `idx_password_reset_tokens_token_hash` on `token_hash` (unique)
- `idx_password_reset_tokens_expires_at` on `expires_at` (for cleanup)

**Constraints**:
- ON DELETE CASCADE for user_id

---

## State Transitions

### User Account States

```
                    ┌──────────────┐
                    │   Created    │
                    │  (is_active  │
                    │    =true)    │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  Login   │ │  OAuth   │ │ Password │
        │ (email/  │ │  Link    │ │  Reset   │
        │ password)│ │          │ │          │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │            │            │
             └────────────┼────────────┘
                          ▼
                    ┌──────────────┐
                    │    Active    │
                    │  (logged in) │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  Logout  │ │  Session │ │ Deactivate│
        │          │ │  Expire  │ │ (admin)   │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │            │            │
             ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  Logged  │ │  Logged  │ │ Inactive │
        │   Out    │ │   Out    │ │(is_active│
        │          │ │          │ │  =false) │
        └──────────┘ └──────────┘ └──────────┘
```

### Password Reset Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Request   │────▶│   Token     │────▶│   Token     │
│   Reset     │     │   Created   │     │   Sent      │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                    ┌──────────────────────────┘
                    ▼
              ┌──────────┐
              │  User    │
              │  Clicks  │
              │  Link    │
              └────┬─────┘
                   │
         ┌─────────┼─────────┐
         ▼         ▼         ▼
   ┌──────────┐ ┌──────────┐ ┌──────────┐
   │  Valid   │ │ Expired  │ │  Used    │
   │  Token   │ │  Token   │ │  Token   │
   └────┬─────┘ └────┬─────┘ └────┬─────┘
        │            │            │
        ▼            ▼            ▼
   ┌──────────┐ ┌──────────┐ ┌──────────┐
   │ Password │ │  Error   │ │  Error   │
   │ Updated  │ │ (request │ │ (already │
   │          │ │  new)    │ │  used)   │
   └──────────┘ └──────────┘ └──────────┘
```

## Database Migrations

### Initial Migration (001_create_auth_tables.sql)

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(60),
    google_id VARCHAR(255) UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP,
    CONSTRAINT chk_auth_method CHECK (password_hash IS NOT NULL OR google_id IS NOT NULL)
);

-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- User roles junction table
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

-- Permissions table
CREATE TABLE permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(20) NOT NULL,
    PRIMARY KEY (role_id, resource, action)
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    refresh_token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    refresh_expires_at TIMESTAMP NOT NULL,
    last_activity_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ip_address INET,
    user_agent VARCHAR(500),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Password reset tokens table
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
```

### Seed Data Migration (002_seed_roles.sql)

```sql
-- Seed default roles
INSERT INTO roles (id, name, description) VALUES
    (uuid_generate_v4(), 'super_admin', 'Full system access including user management'),
    (uuid_generate_v4(), 'admin', 'Full content access, no user management'),
    (uuid_generate_v4(), 'editor', 'Read and write content'),
    (uuid_generate_v4(), 'viewer', 'Read-only access');

-- Seed permissions for super_admin
INSERT INTO permissions (role_id, resource, action)
SELECT r.id, p.resource, p.action
FROM roles r
CROSS JOIN (VALUES 
    ('users', 'read'), ('users', 'write'), ('users', 'delete'), ('users', 'manage'),
    ('roles', 'read'), ('roles', 'write'), ('roles', 'manage'),
    ('content', 'read'), ('content', 'write'), ('content', 'delete')
) AS p(resource, action)
WHERE r.name = 'super_admin';

-- Seed permissions for admin
INSERT INTO permissions (role_id, resource, action)
SELECT r.id, p.resource, p.action
FROM roles r
CROSS JOIN (VALUES 
    ('content', 'read'), ('content', 'write'), ('content', 'delete')
) AS p(resource, action)
WHERE r.name = 'admin';

-- Seed permissions for editor
INSERT INTO permissions (role_id, resource, action)
SELECT r.id, p.resource, p.action
FROM roles r
CROSS JOIN (VALUES 
    ('content', 'read'), ('content', 'write')
) AS p(resource, action)
WHERE r.name = 'editor';

-- Seed permissions for viewer
INSERT INTO permissions (role_id, resource, action)
SELECT r.id, 'content', 'read'
FROM roles r
WHERE r.name = 'viewer';
```
