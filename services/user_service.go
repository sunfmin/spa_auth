package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/internal/models"
	"gorm.io/gorm"
)

type UserService interface {
	CreateUser(ctx context.Context, req *pb.CreateUserRequest, createdBy string) (*pb.CreateUserResponse, error)
	GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error)
	ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error)
	UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error)
	DeactivateUser(ctx context.Context, req *pb.DeactivateUserRequest) (*pb.DeactivateUserResponse, error)
	ReactivateUser(ctx context.Context, req *pb.ReactivateUserRequest) (*pb.ReactivateUserResponse, error)
	DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error)
	AdminResetPassword(ctx context.Context, req *pb.AdminResetPasswordRequest) (*pb.AdminResetPasswordResponse, error)
}

type userService struct {
	db              *gorm.DB
	passwordService PasswordService
	sessionService  SessionService
}

type userServiceBuilder struct {
	db              *gorm.DB
	passwordService PasswordService
	sessionService  SessionService
}

func NewUserService(db *gorm.DB) *userServiceBuilder {
	return &userServiceBuilder{db: db}
}

func (b *userServiceBuilder) WithPasswordService(ps PasswordService) *userServiceBuilder {
	b.passwordService = ps
	return b
}

func (b *userServiceBuilder) WithSessionService(ss SessionService) *userServiceBuilder {
	b.sessionService = ss
	return b
}

func (b *userServiceBuilder) Build() UserService {
	return &userService{
		db:              b.db,
		passwordService: b.passwordService,
		sessionService:  b.sessionService,
	}
}

func (s *userService) CreateUser(ctx context.Context, req *pb.CreateUserRequest, createdBy string) (*pb.CreateUserResponse, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("email: %w", ErrInvalidEmail)
	}

	hash, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	var existing models.User
	if err := s.db.WithContext(ctx).Where("email = ?", req.Email).First(&existing).Error; err == nil {
		return nil, ErrUserAlreadyExists
	}

	createdByUUID, err := uuid.Parse(createdBy)
	if err != nil {
		return nil, fmt.Errorf("invalid createdBy: %w", err)
	}

	user := &models.User{
		Email:        req.Email,
		PasswordHash: &hash,
		IsActive:     true,
		CreatedBy:    &createdByUUID,
	}

	var roleIDs []uuid.UUID
	for _, roleName := range req.Roles {
		var role models.Role
		if err := s.db.WithContext(ctx).Where("name = ?", roleName).First(&role).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil, fmt.Errorf("role %s: %w", roleName, ErrRoleNotFound)
			}
			return nil, fmt.Errorf("find role: %w", err)
		}
		roleIDs = append(roleIDs, role.ID)
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		for _, roleID := range roleIDs {
			userRole := &models.UserRole{
				UserID:     user.ID,
				RoleID:     roleID,
				AssignedBy: &createdByUUID,
			}
			if err := tx.Create(userRole).Error; err != nil {
				return fmt.Errorf("assign role: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	if err := s.db.WithContext(ctx).Preload("UserRoles.Role.RolePermissions.Section").First(user, user.ID).Error; err != nil {
		return nil, fmt.Errorf("reload user: %w", err)
	}

	roles, sections := extractRolesAndSections(user.UserRoles)

	return &pb.CreateUserResponse{
		User: modelToProtoUser(user, roles, sections),
	}, nil
}

func (s *userService) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	userID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", ErrInvalidID)
	}

	var user models.User
	err = s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("id = ?", userID).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	roles, sections := extractRolesAndSections(user.UserRoles)

	return &pb.GetUserResponse{
		User: modelToProtoUser(&user, roles, sections),
	}, nil
}

func (s *userService) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	var users []models.User
	var total int64

	pageSize := int(req.PageSize)
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	query := s.db.WithContext(ctx).Model(&models.User{})
	if !req.IncludeInactive {
		query = query.Where("is_active = ?", true)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}

	offset := 0
	if req.PageToken != "" {
		var err error
		offset, err = decodePageToken(req.PageToken)
		if err != nil {
			return nil, fmt.Errorf("invalid page token: %w", err)
		}
	}

	err := query.
		Preload("UserRoles.Role.RolePermissions.Section").
		Limit(pageSize).
		Offset(offset).
		Order("created_at DESC").
		Find(&users).Error

	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	var pbUsers []*pb.User
	for _, user := range users {
		roles, sections := extractRolesAndSections(user.UserRoles)
		pbUsers = append(pbUsers, modelToProtoUser(&user, roles, sections))
	}

	var nextPageToken string
	if offset+pageSize < int(total) {
		nextPageToken = encodePageToken(offset + pageSize)
	}

	return &pb.ListUsersResponse{
		Users:         pbUsers,
		NextPageToken: nextPageToken,
		TotalCount:    int32(total),
	}, nil
}

func (s *userService) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
	userID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		updates := make(map[string]interface{})

		if req.Email != nil && *req.Email != "" {
			var existing models.User
			if err := tx.Where("email = ? AND id != ?", *req.Email, userID).First(&existing).Error; err == nil {
				return ErrUserAlreadyExists
			}
			updates["email"] = *req.Email
		}

		if req.IsActive != nil {
			updates["is_active"] = *req.IsActive
		}

		if len(updates) > 0 {
			if err := tx.Model(&user).Updates(updates).Error; err != nil {
				return fmt.Errorf("update user: %w", err)
			}
		}

		if len(req.Roles) > 0 {
			if err := tx.Delete(&models.UserRole{}, "user_id = ?", userID).Error; err != nil {
				return fmt.Errorf("delete old roles: %w", err)
			}

			for _, roleName := range req.Roles {
				var role models.Role
				if err := tx.Where("name = ?", roleName).First(&role).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						return fmt.Errorf("role %s: %w", roleName, ErrRoleNotFound)
					}
					return fmt.Errorf("find role: %w", err)
				}
				userRole := &models.UserRole{
					UserID: userID,
					RoleID: role.ID,
				}
				if err := tx.Create(userRole).Error; err != nil {
					return fmt.Errorf("assign role: %w", err)
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	getResp, err := s.GetUser(ctx, &pb.GetUserRequest{Id: req.Id})
	if err != nil {
		return nil, err
	}

	return &pb.UpdateUserResponse{User: getResp.User}, nil
}

func (s *userService) DeactivateUser(ctx context.Context, req *pb.DeactivateUserRequest) (*pb.DeactivateUserResponse, error) {
	userID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	result := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("is_active", false)

	if result.Error != nil {
		return nil, fmt.Errorf("deactivate user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return nil, ErrUserNotFound
	}

	if s.sessionService != nil {
		if err := s.sessionService.InvalidateAllUserSessions(ctx, userID); err != nil {
			return nil, fmt.Errorf("invalidate sessions: %w", err)
		}
	}

	return &pb.DeactivateUserResponse{
		Success: true,
		Message: "User deactivated successfully",
	}, nil
}

func (s *userService) ReactivateUser(ctx context.Context, req *pb.ReactivateUserRequest) (*pb.ReactivateUserResponse, error) {
	userID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	result := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("is_active", true)

	if result.Error != nil {
		return nil, fmt.Errorf("reactivate user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return nil, ErrUserNotFound
	}

	return &pb.ReactivateUserResponse{
		Success: true,
		Message: "User reactivated successfully",
	}, nil
}

func (s *userService) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	userID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	result := s.db.WithContext(ctx).Delete(&models.User{}, "id = ?", userID)
	if result.Error != nil {
		return nil, fmt.Errorf("delete user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return nil, ErrUserNotFound
	}

	return &pb.DeleteUserResponse{
		Success: true,
		Message: "User deleted successfully",
	}, nil
}

func (s *userService) AdminResetPassword(ctx context.Context, req *pb.AdminResetPasswordRequest) (*pb.AdminResetPasswordResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	hash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		return nil, err
	}

	result := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("password_hash", hash)

	if result.Error != nil {
		return nil, fmt.Errorf("reset password: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return nil, ErrUserNotFound
	}

	return &pb.AdminResetPasswordResponse{
		Success: true,
		Message: "Password reset successfully",
	}, nil
}

func encodePageToken(offset int) string {
	return fmt.Sprintf("%d", offset)
}

func decodePageToken(token string) (int, error) {
	var offset int
	_, err := fmt.Sscanf(token, "%d", &offset)
	return offset, err
}
