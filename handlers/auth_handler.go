package handlers

import (
	"net/http"
	"strings"

	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/services"
)

type AuthHandler struct {
	authService  services.AuthService
	oauthService services.OAuthService
}

func NewAuthHandler(authService services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) WithOAuthService(oauthService services.OAuthService) *AuthHandler {
	h.oauthService = oauthService
	return h
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
	ctx := r.Context()

	var req pb.RefreshTokenRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}

	resp, err := h.authService.RefreshToken(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *AuthHandler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req pb.ValidateTokenRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}

	resp, err := h.authService.ValidateToken(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *AuthHandler) OAuthGoogleStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req pb.OAuthStartRequest
	// Allow empty body for GET request
	if r.ContentLength > 0 {
		if err := DecodeProtoJSON(r, &req); err != nil {
			RespondWithError(w, ErrCodeBadRequest, err)
			return
		}
	}

	resp, err := h.oauthService.StartOAuth(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *AuthHandler) OAuthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get code and state from query params (Google redirects with GET)
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	req := &pb.OAuthCallbackRequest{
		Code:  code,
		State: state,
	}

	resp, err := h.oauthService.HandleCallback(ctx, req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req pb.RequestPasswordResetRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}

	resp, err := h.authService.RequestPasswordReset(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req pb.ResetPasswordRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}

	resp, err := h.authService.ResetPassword(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}
