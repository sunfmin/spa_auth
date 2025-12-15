package handlers

import (
	"net/http"
	"strings"

	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/services"
)

type AuthHandler struct {
	authService services.AuthService
}

func NewAuthHandler(authService services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req pb.LoginRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}

	resp, err := h.authService.Login(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := extractBearerToken(r)
	if token == "" {
		RespondWithError(w, ErrCodeUnauthorized, nil)
		return
	}

	resp, err := h.authService.Logout(ctx, &pb.LogoutRequest{}, token)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := extractBearerToken(r)
	if token == "" {
		RespondWithError(w, ErrCodeUnauthorized, nil)
		return
	}

	resp, err := h.authService.GetCurrentUser(ctx, &pb.ValidateTokenRequest{Token: token})
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US7
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *AuthHandler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US7
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *AuthHandler) OAuthGoogleStart(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US2
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *AuthHandler) OAuthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US2
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US6
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US6
	RespondWithError(w, ErrCodeInternalError, nil)
}
