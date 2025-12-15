package handlers

import (
	"net/http"

	"github.com/user/spa_auth/services"
)

type RoleHandler struct {
	roleService services.RoleService
}

func NewRoleHandler(roleService services.RoleService) *RoleHandler {
	return &RoleHandler{roleService: roleService}
}

func (h *RoleHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US4
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *RoleHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US4
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *RoleHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US4
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *RoleHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US4
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *RoleHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US4
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *RoleHandler) CreateSpaSection(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US4
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *RoleHandler) ListSpaSections(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US4
	RespondWithError(w, ErrCodeInternalError, nil)
}

func (h *RoleHandler) CheckSectionAccess(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement in US5
	RespondWithError(w, ErrCodeInternalError, nil)
}
