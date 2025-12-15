package handlers

import (
	"net/http"

	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/services"
)

type RoleHandler struct {
	roleService services.RoleService
}

func NewRoleHandler(roleService services.RoleService) *RoleHandler {
	return &RoleHandler{roleService: roleService}
}

func (h *RoleHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req pb.CreateRoleRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}

	createdBy := r.Header.Get("X-User-ID")
	if createdBy == "" {
		RespondWithError(w, ErrCodeUnauthorized, nil)
		return
	}

	resp, err := h.roleService.CreateRole(ctx, &req, createdBy)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusCreated, resp)
}

func (h *RoleHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := &pb.ListRolesRequest{
		IncludeSystem: r.URL.Query().Get("include_system") == "true",
	}

	resp, err := h.roleService.ListRoles(ctx, req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *RoleHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleID := r.PathValue("id")
	if roleID == "" {
		RespondWithError(w, ErrCodeBadRequest, nil)
		return
	}

	resp, err := h.roleService.GetRole(ctx, &pb.GetRoleRequest{
		Identifier: &pb.GetRoleRequest_Id{Id: roleID},
	})
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *RoleHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleID := r.PathValue("id")
	if roleID == "" {
		RespondWithError(w, ErrCodeBadRequest, nil)
		return
	}

	var req pb.UpdateRoleRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}
	req.Id = roleID

	resp, err := h.roleService.UpdateRole(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *RoleHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roleID := r.PathValue("id")
	if roleID == "" {
		RespondWithError(w, ErrCodeBadRequest, nil)
		return
	}

	resp, err := h.roleService.DeleteRole(ctx, &pb.DeleteRoleRequest{Id: roleID})
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *RoleHandler) CreateSpaSection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req pb.CreateSpaSectionRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}

	resp, err := h.roleService.CreateSpaSection(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusCreated, resp)
}

func (h *RoleHandler) ListSpaSections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	resp, err := h.roleService.ListSpaSections(ctx, &pb.ListSpaSectionsRequest{})
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *RoleHandler) CheckSectionAccess(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := r.URL.Query().Get("user_id")
	sectionKey := r.URL.Query().Get("section_key")

	resp, err := h.roleService.CheckSectionAccess(ctx, &pb.CheckSectionAccessRequest{
		UserId:     userID,
		SectionKey: sectionKey,
	})
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}
