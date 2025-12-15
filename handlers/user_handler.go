package handlers

import (
	"net/http"

	"github.com/user/spa_auth/services"
)

type UserHandler struct {
	userService services.UserService
}

func NewUserHandler(userService services.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US3
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US3
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US3
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US3
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US3
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *UserHandler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US3
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *UserHandler) ReactivateUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US3
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *UserHandler) AdminResetPassword(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US3
	RespondWithError(w, ErrCodeInternalError, nil)
}
