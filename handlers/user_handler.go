package handlers

import (
	"fmt"
	"net/http"

	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/services"
)

type UserHandler struct {
	userService services.UserService
}

func NewUserHandler(userService services.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req pb.CreateUserRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}

	createdBy := r.Header.Get("X-User-ID")
	if createdBy == "" {
		RespondWithError(w, ErrCodeUnauthorized, nil)
		return
	}

	resp, err := h.userService.CreateUser(ctx, &req, createdBy)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusCreated, resp)
}

func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := &pb.ListUsersRequest{
		PageSize:        int32(parseIntQuery(r, "page_size", 20)),
		PageToken:       r.URL.Query().Get("page_token"),
		IncludeInactive: r.URL.Query().Get("include_inactive") == "true",
	}

	resp, err := h.userService.ListUsers(ctx, req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := r.PathValue("id")
	if userID == "" {
		RespondWithError(w, ErrCodeBadRequest, nil)
		return
	}

	resp, err := h.userService.GetUser(ctx, &pb.GetUserRequest{Id: userID})
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := r.PathValue("id")
	if userID == "" {
		RespondWithError(w, ErrCodeBadRequest, nil)
		return
	}

	var req pb.UpdateUserRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}
	req.Id = userID

	resp, err := h.userService.UpdateUser(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := r.PathValue("id")
	if userID == "" {
		RespondWithError(w, ErrCodeBadRequest, nil)
		return
	}

	resp, err := h.userService.DeleteUser(ctx, &pb.DeleteUserRequest{Id: userID})
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *UserHandler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := r.PathValue("id")
	if userID == "" {
		RespondWithError(w, ErrCodeBadRequest, nil)
		return
	}

	resp, err := h.userService.DeactivateUser(ctx, &pb.DeactivateUserRequest{Id: userID})
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *UserHandler) ReactivateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := r.PathValue("id")
	if userID == "" {
		RespondWithError(w, ErrCodeBadRequest, nil)
		return
	}

	resp, err := h.userService.ReactivateUser(ctx, &pb.ReactivateUserRequest{Id: userID})
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func (h *UserHandler) AdminResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := r.PathValue("id")
	if userID == "" {
		RespondWithError(w, ErrCodeBadRequest, nil)
		return
	}

	var req pb.AdminResetPasswordRequest
	if err := DecodeProtoJSON(r, &req); err != nil {
		RespondWithError(w, ErrCodeBadRequest, err)
		return
	}
	req.UserId = userID

	resp, err := h.userService.AdminResetPassword(ctx, &req)
	if err != nil {
		HandleServiceError(w, err)
		return
	}

	RespondWithProto(w, http.StatusOK, resp)
}

func parseIntQuery(r *http.Request, key string, defaultVal int) int {
	val := r.URL.Query().Get(key)
	if val == "" {
		return defaultVal
	}
	var result int
	if _, err := fmt.Sscanf(val, "%d", &result); err != nil {
		return defaultVal
	}
	return result
}
