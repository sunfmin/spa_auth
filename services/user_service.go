package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/user/spa_auth/internal/models"
	"gorm.io/gorm"
)

type UserService interface {
	CreateUser(ctx context.Context, email, password string, roleIDs []uuid.UUID, createdBy uuid.UUID) (*models.User, error)
	GetUser(ctx context.Context, userID uuid.UUID) (*models.User, error)
	ListUsers(ctx context.Context, includeInactive bool, limit, offset int) ([]*models.User, int64, error)
	UpdateUser(ctx context.Context, userID uuid.UUID, email *string, roleIDs []uuid.UUID, isActive *bool) (*models.User, error)
	DeactivateUser(ctx context.Context, userID uuid.UUID) error
	ReactivateUser(ctx context.Context, userID uuid.UUID) error
	DeleteUser(ctx context.Context, userID uuid.UUID) error
	AdminResetPassword(ctx context.Context, userID uuid.UUID, newPassword string) error
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

func (s *userService) CreateUser(ctx context.Context, email, password string, roleIDs []uuid.UUID, createdBy uuid.UUID) (*models.User, error) {
	if email == "" {
		return nil, fmt.Errorf("email: %w", ErrInvalidEmail)
	}

	hash, err := s.passwordService.HashPassword(password)
	if err != nil {
		return nil, err
	}

	var existing models.User
	if err := s.db.WithContext(ctx).Where("email = ?", email).First(&existing).Error; err == nil {
		return nil, ErrUserAlreadyExists
	}

	user := &models.User{
		Email:        email,
		PasswordHash: &hash,
		IsActive:     true,
		CreatedBy:    &createdBy,
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		for _, roleID := range roleIDs {
			userRole := &models.UserRole{
				UserID:     user.ID,
				RoleID:     roleID,
				AssignedBy: &createdBy,
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

	return user, nil
}

func (s *userService) GetUser(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).
		Preload("UserRoles.Role").
		Where("id = ?", userID).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	return &user, nil
}

func (s *userService) ListUsers(ctx context.Context, includeInactive bool, limit, offset int) ([]*models.User, int64, error) {
	var users []*models.User
	var total int64

	query := s.db.WithContext(ctx).Model(&models.User{})
	if !includeInactive {
		query = query.Where("is_active = ?", true)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	err := query.
		Preload("UserRoles.Role").
		Limit(limit).
		Offset(offset).
		Order("created_at DESC").
		Find(&users).Error

	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}

	return users, total, nil
}

func (s *userService) UpdateUser(ctx context.Context, userID uuid.UUID, email *string, roleIDs []uuid.UUID, isActive *bool) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		updates := make(map[string]interface{})

		if email != nil && *email != "" {
			var existing models.User
			if err := tx.Where("email = ? AND id != ?", *email, userID).First(&existing).Error; err == nil {
				return ErrUserAlreadyExists
			}
			updates["email"] = *email
		}

		if isActive != nil {
			updates["is_active"] = *isActive
		}

		if len(updates) > 0 {
			if err := tx.Model(&user).Updates(updates).Error; err != nil {
				return fmt.Errorf("update user: %w", err)
			}
		}

		if len(roleIDs) > 0 {
			if err := tx.Delete(&models.UserRole{}, "user_id = ?", userID).Error; err != nil {
				return fmt.Errorf("delete old roles: %w", err)
			}

			for _, roleID := range roleIDs {
				userRole := &models.UserRole{
					UserID: userID,
					RoleID: roleID,
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

	return s.GetUser(ctx, userID)
}

func (s *userService) DeactivateUser(ctx context.Context, userID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("is_active", false)

	if result.Error != nil {
		return fmt.Errorf("deactivate user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}

	if s.sessionService != nil {
		return s.sessionService.InvalidateAllUserSessions(ctx, userID)
	}

	return nil
}

func (s *userService) ReactivateUser(ctx context.Context, userID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("is_active", true)

	if result.Error != nil {
		return fmt.Errorf("reactivate user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (s *userService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	result := s.db.WithContext(ctx).Delete(&models.User{}, "id = ?", userID)
	if result.Error != nil {
		return fmt.Errorf("delete user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (s *userService) AdminResetPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	hash, err := s.passwordService.HashPassword(newPassword)
	if err != nil {
		return err
	}

	result := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("password_hash", hash)

	if result.Error != nil {
		return fmt.Errorf("reset password: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}
