package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/user/spa_auth/services"
)

type ErrorCode struct {
	Code       string
	Message    string
	HTTPStatus int
	ServiceErr error
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

var (
	ErrCodeInvalidCredentials = ErrorCode{
		Code:       "INVALID_CREDENTIALS",
		Message:    "Invalid email or password",
		HTTPStatus: http.StatusUnauthorized,
		ServiceErr: services.ErrInvalidCredentials,
	}
	ErrCodeUserNotFound = ErrorCode{
		Code:       "USER_NOT_FOUND",
		Message:    "User not found",
		HTTPStatus: http.StatusNotFound,
		ServiceErr: services.ErrUserNotFound,
	}
	ErrCodeUserInactive = ErrorCode{
		Code:       "USER_INACTIVE",
		Message:    "User account is inactive",
		HTTPStatus: http.StatusForbidden,
		ServiceErr: services.ErrUserInactive,
	}
	ErrCodeUserAlreadyExists = ErrorCode{
		Code:       "USER_ALREADY_EXISTS",
		Message:    "User with this email already exists",
		HTTPStatus: http.StatusConflict,
		ServiceErr: services.ErrUserAlreadyExists,
	}
	ErrCodeRoleNotFound = ErrorCode{
		Code:       "ROLE_NOT_FOUND",
		Message:    "Role not found",
		HTTPStatus: http.StatusNotFound,
		ServiceErr: services.ErrRoleNotFound,
	}
	ErrCodeRoleHasUsers = ErrorCode{
		Code:       "ROLE_HAS_USERS",
		Message:    "Cannot delete role with assigned users",
		HTTPStatus: http.StatusConflict,
		ServiceErr: services.ErrRoleHasUsers,
	}
	ErrCodeRoleIsSystem = ErrorCode{
		Code:       "ROLE_IS_SYSTEM",
		Message:    "Cannot modify or delete system role",
		HTTPStatus: http.StatusForbidden,
		ServiceErr: services.ErrRoleIsSystem,
	}
	ErrCodeSessionExpired = ErrorCode{
		Code:       "SESSION_EXPIRED",
		Message:    "Session has expired",
		HTTPStatus: http.StatusUnauthorized,
		ServiceErr: services.ErrSessionExpired,
	}
	ErrCodeTokenExpired = ErrorCode{
		Code:       "TOKEN_EXPIRED",
		Message:    "Token has expired",
		HTTPStatus: http.StatusGone,
		ServiceErr: services.ErrTokenExpired,
	}
	ErrCodeTokenInvalid = ErrorCode{
		Code:       "TOKEN_INVALID",
		Message:    "Token is invalid",
		HTTPStatus: http.StatusUnauthorized,
		ServiceErr: services.ErrTokenInvalid,
	}
	ErrCodeTokenAlreadyUsed = ErrorCode{
		Code:       "TOKEN_ALREADY_USED",
		Message:    "Token has already been used",
		HTTPStatus: http.StatusGone,
		ServiceErr: services.ErrTokenAlreadyUsed,
	}
	ErrCodeAccessDenied = ErrorCode{
		Code:       "ACCESS_DENIED",
		Message:    "Access denied",
		HTTPStatus: http.StatusForbidden,
		ServiceErr: services.ErrAccessDenied,
	}
	ErrCodeRateLimitExceeded = ErrorCode{
		Code:       "RATE_LIMIT_EXCEEDED",
		Message:    "Too many requests, please try again later",
		HTTPStatus: http.StatusTooManyRequests,
		ServiceErr: services.ErrRateLimitExceeded,
	}
	ErrCodePasswordTooShort = ErrorCode{
		Code:       "PASSWORD_TOO_SHORT",
		Message:    "Password must be at least 8 characters",
		HTTPStatus: http.StatusBadRequest,
		ServiceErr: services.ErrPasswordTooShort,
	}
	ErrCodeInvalidEmail = ErrorCode{
		Code:       "INVALID_EMAIL",
		Message:    "Invalid email format",
		HTTPStatus: http.StatusBadRequest,
		ServiceErr: services.ErrInvalidEmail,
	}
	ErrCodeOAuthEmailNotFound = ErrorCode{
		Code:       "OAUTH_EMAIL_NOT_FOUND",
		Message:    "Email not registered in system",
		HTTPStatus: http.StatusForbidden,
		ServiceErr: services.ErrOAuthEmailNotFound,
	}
	ErrCodeInternalError = ErrorCode{
		Code:       "INTERNAL_ERROR",
		Message:    "An internal error occurred",
		HTTPStatus: http.StatusInternalServerError,
		ServiceErr: services.ErrInternalError,
	}
	ErrCodeBadRequest = ErrorCode{
		Code:       "BAD_REQUEST",
		Message:    "Invalid request",
		HTTPStatus: http.StatusBadRequest,
		ServiceErr: nil,
	}
	ErrCodeUnauthorized = ErrorCode{
		Code:       "UNAUTHORIZED",
		Message:    "Authentication required",
		HTTPStatus: http.StatusUnauthorized,
		ServiceErr: nil,
	}
)

var errorCodeRegistry = []ErrorCode{
	ErrCodeInvalidCredentials,
	ErrCodeUserNotFound,
	ErrCodeUserInactive,
	ErrCodeUserAlreadyExists,
	ErrCodeRoleNotFound,
	ErrCodeRoleHasUsers,
	ErrCodeRoleIsSystem,
	ErrCodeSessionExpired,
	ErrCodeTokenExpired,
	ErrCodeTokenInvalid,
	ErrCodeTokenAlreadyUsed,
	ErrCodeAccessDenied,
	ErrCodeRateLimitExceeded,
	ErrCodePasswordTooShort,
	ErrCodeInvalidEmail,
	ErrCodeOAuthEmailNotFound,
	ErrCodeInternalError,
}

var hideErrorDetails = false

func SetHideErrorDetails(hide bool) {
	hideErrorDetails = hide
}

func HandleServiceError(w http.ResponseWriter, err error) {
	for _, ec := range errorCodeRegistry {
		if ec.ServiceErr != nil && errors.Is(err, ec.ServiceErr) {
			RespondWithError(w, ec, err)
			return
		}
	}
	RespondWithError(w, ErrCodeInternalError, err)
}

func RespondWithError(w http.ResponseWriter, errCode ErrorCode, err error) {
	resp := ErrorResponse{
		Code:    errCode.Code,
		Message: errCode.Message,
	}

	if !hideErrorDetails && err != nil {
		resp.Details = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errCode.HTTPStatus)
	json.NewEncoder(w).Encode(resp)
}
