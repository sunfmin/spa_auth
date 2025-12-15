package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/user/spa_auth/services"
)

type Middleware func(http.Handler) http.Handler

type routerBuilder struct {
	mux             *http.ServeMux
	authService     services.AuthService
	userService     services.UserService
	roleService     services.RoleService
	sessionService  services.SessionService
	passwordService services.PasswordService
	jwtService      services.JWTService
	middlewares     []Middleware
}

func NewRouter() *routerBuilder {
	return &routerBuilder{}
}

func (b *routerBuilder) WithMux(mux *http.ServeMux) *routerBuilder {
	b.mux = mux
	return b
}

func (b *routerBuilder) WithAuthService(svc services.AuthService) *routerBuilder {
	b.authService = svc
	return b
}

func (b *routerBuilder) WithUserService(svc services.UserService) *routerBuilder {
	b.userService = svc
	return b
}

func (b *routerBuilder) WithRoleService(svc services.RoleService) *routerBuilder {
	b.roleService = svc
	return b
}

func (b *routerBuilder) WithSessionService(svc services.SessionService) *routerBuilder {
	b.sessionService = svc
	return b
}

func (b *routerBuilder) WithPasswordService(svc services.PasswordService) *routerBuilder {
	b.passwordService = svc
	return b
}

func (b *routerBuilder) WithJWTService(svc services.JWTService) *routerBuilder {
	b.jwtService = svc
	return b
}

func (b *routerBuilder) WithMiddlewares(mws ...Middleware) *routerBuilder {
	b.middlewares = append(b.middlewares, mws...)
	return b
}

func (b *routerBuilder) Build() http.Handler {
	mux := b.mux
	if mux == nil {
		mux = http.NewServeMux()
	}

	mux.HandleFunc("GET /health", healthHandler)

	if b.authService != nil {
		h := NewAuthHandler(b.authService)
		mux.HandleFunc("POST /api/v1/auth/login", h.Login)
		mux.HandleFunc("POST /api/v1/auth/logout", h.Logout)
		mux.HandleFunc("GET /api/v1/auth/me", h.GetCurrentUser)
		mux.HandleFunc("POST /api/v1/auth/refresh", h.RefreshToken)
		mux.HandleFunc("POST /api/v1/auth/validate", h.ValidateToken)
		mux.HandleFunc("GET /api/v1/oauth/google/start", h.OAuthGoogleStart)
		mux.HandleFunc("GET /api/v1/oauth/google/callback", h.OAuthGoogleCallback)
		mux.HandleFunc("POST /api/v1/password/reset/request", h.RequestPasswordReset)
		mux.HandleFunc("POST /api/v1/password/reset", h.ResetPassword)
	}

	if b.userService != nil {
		h := NewUserHandler(b.userService)
		mux.HandleFunc("POST /api/v1/users", h.CreateUser)
		mux.HandleFunc("GET /api/v1/users", h.ListUsers)
		mux.HandleFunc("GET /api/v1/users/{id}", h.GetUser)
		mux.HandleFunc("PATCH /api/v1/users/{id}", h.UpdateUser)
		mux.HandleFunc("DELETE /api/v1/users/{id}", h.DeleteUser)
		mux.HandleFunc("POST /api/v1/users/{id}/deactivate", h.DeactivateUser)
		mux.HandleFunc("POST /api/v1/users/{id}/reactivate", h.ReactivateUser)
		mux.HandleFunc("POST /api/v1/users/{id}/password", h.AdminResetPassword)
	}

	if b.roleService != nil {
		h := NewRoleHandler(b.roleService)
		mux.HandleFunc("POST /api/v1/roles", h.CreateRole)
		mux.HandleFunc("GET /api/v1/roles", h.ListRoles)
		mux.HandleFunc("GET /api/v1/roles/{id}", h.GetRole)
		mux.HandleFunc("PATCH /api/v1/roles/{id}", h.UpdateRole)
		mux.HandleFunc("DELETE /api/v1/roles/{id}", h.DeleteRole)
		mux.HandleFunc("POST /api/v1/spa-sections", h.CreateSpaSection)
		mux.HandleFunc("GET /api/v1/spa-sections", h.ListSpaSections)
		mux.HandleFunc("POST /api/v1/permissions/check-section", h.CheckSectionAccess)
	}

	var handler http.Handler = mux
	for _, mw := range b.middlewares {
		handler = mw(handler)
	}
	return handler
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
