package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/user/spa_auth/services"
)

func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

type AuthHandler struct {
	authService     services.AuthService
	jwtService      services.JWTService
	sessionService  services.SessionService
	passwordService services.PasswordService
}

func NewAuthHandler(
	authService services.AuthService,
	jwtService services.JWTService,
	sessionService services.SessionService,
	passwordService services.PasswordService,
) *AuthHandler {
	return &AuthHandler{
		authService:     authService,
		jwtService:      jwtService,
		sessionService:  sessionService,
		passwordService: passwordService,
	}
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	User         UserResponse `json:"user"`
	AccessToken  string       `json:"accessToken"`
	RefreshToken string       `json:"refreshToken"`
	ExpiresAt    string       `json:"expiresAt"`
}

type UserResponse struct {
	ID       string   `json:"id"`
	Email    string   `json:"email"`
	IsActive bool     `json:"isActive"`
	Roles    []string `json:"roles"`
	Sections []string `json:"sections"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}

	user, roles, sections, err := h.authService.Login(ctx, req.Email, req.Password)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	tokenPair, err := h.jwtService.GenerateTokenPair(ctx, user.ID, user.Email, roles, sections)
	if err != nil {
		RespondWithError(w, ErrCodeInternalError, err)
		return
	}

	ipAddress := extractIP(r.RemoteAddr)
	userAgent := r.UserAgent()

	_, err = h.sessionService.CreateSession(ctx, user.ID, tokenPair.AccessToken, tokenPair.RefreshToken, h.jwtService.GetAccessTTL(), h.jwtService.GetRefreshTTL(), ipAddress, userAgent)
	if err != nil {
		RespondWithError(w, ErrCodeInternalError, err)
		return
	}

	resp := LoginResponse{
		User: UserResponse{
			ID:       user.ID.String(),
			Email:    user.Email,
			IsActive: user.IsActive,
			Roles:    roles,
			Sections: sections,
		},
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		RespondWithError(w, ErrCodeUnauthorized, nil)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		RespondWithError(w, ErrCodeUnauthorized, nil)
		return
	}

	token := parts[1]

	_, err := h.jwtService.ValidateToken(ctx, token)
	if err != nil {
		RespondWithError(w, ErrCodeUnauthorized, err)
		return
	}

	tokenHash := services.HashToken(token)
	session, err := h.sessionService.ValidateSession(ctx, tokenHash)
	if err != nil {
		RespondWithError(w, ErrCodeUnauthorized, err)
		return
	}

	if err := h.sessionService.InvalidateSession(ctx, session.ID); err != nil {
		RespondWithError(w, ErrCodeInternalError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		RespondWithError(w, ErrCodeUnauthorized, nil)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		RespondWithError(w, ErrCodeUnauthorized, nil)
		return
	}

	token := parts[1]

	claims, err := h.jwtService.ValidateToken(ctx, token)
	if err != nil {
		RespondWithError(w, ErrCodeUnauthorized, err)
		return
	}

	resp := UserResponse{
		ID:       claims.UserID,
		Email:    claims.Email,
		IsActive: true,
		Roles:    claims.Roles,
		Sections: claims.Sections,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
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
