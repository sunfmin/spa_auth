package services

import "errors"

var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrUserNotFound         = errors.New("user not found")
	ErrUserInactive         = errors.New("user account is inactive")
	ErrUserAlreadyExists    = errors.New("user with this email already exists")
	ErrRoleNotFound         = errors.New("role not found")
	ErrRoleHasUsers         = errors.New("cannot delete role with assigned users")
	ErrRoleIsSystem         = errors.New("cannot modify or delete system role")
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionExpired       = errors.New("session has expired")
	ErrTokenExpired         = errors.New("token has expired")
	ErrTokenInvalid         = errors.New("token is invalid")
	ErrTokenAlreadyUsed     = errors.New("token has already been used")
	ErrSectionNotFound      = errors.New("spa section not found")
	ErrAccessDenied         = errors.New("access denied")
	ErrRateLimitExceeded    = errors.New("rate limit exceeded")
	ErrPasswordTooShort     = errors.New("password must be at least 8 characters")
	ErrInvalidEmail         = errors.New("invalid email format")
	ErrOAuthEmailNotFound   = errors.New("email not registered in system")
	ErrOAuthStateMismatch   = errors.New("oauth state mismatch")
	ErrInternalError        = errors.New("internal server error")
)
