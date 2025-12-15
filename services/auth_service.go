package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/user/spa_auth/internal/models"
	"gorm.io/gorm"
)

type AuthService interface {
	Login(ctx context.Context, email, password string) (*models.User, []string, []string, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, []string, []string, error)
}

type authService struct {
	db              *gorm.DB
	passwordService PasswordService
}

type authServiceBuilder struct {
	db              *gorm.DB
	passwordService PasswordService
}

func NewAuthService(db *gorm.DB) *authServiceBuilder {
	return &authServiceBuilder{db: db}
}

func (b *authServiceBuilder) WithPasswordService(ps PasswordService) *authServiceBuilder {
	b.passwordService = ps
	return b
}

func (b *authServiceBuilder) Build() AuthService {
	return &authService{
		db:              b.db,
		passwordService: b.passwordService,
	}
}

func (s *authService) Login(ctx context.Context, email, password string) (*models.User, []string, []string, error) {
	if email == "" {
		return nil, nil, nil, fmt.Errorf("email: %w", ErrInvalidEmail)
	}
	if password == "" {
		return nil, nil, nil, ErrInvalidCredentials
	}

	var user models.User
	err := s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("email = ?", email).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil, nil, ErrInvalidCredentials
		}
		return nil, nil, nil, fmt.Errorf("find user: %w", err)
	}

	if !user.IsActive {
		return nil, nil, nil, ErrUserInactive
	}

	if user.PasswordHash == nil {
		return nil, nil, nil, ErrInvalidCredentials
	}

	if err := s.passwordService.VerifyPassword(*user.PasswordHash, password); err != nil {
		return nil, nil, nil, ErrInvalidCredentials
	}

	roles, sections := extractRolesAndSections(user.UserRoles)

	return &user, roles, sections, nil
}

func (s *authService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, []string, []string, error) {
	var user models.User
	err := s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("id = ?", userID).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil, nil, ErrUserNotFound
		}
		return nil, nil, nil, fmt.Errorf("find user: %w", err)
	}

	if !user.IsActive {
		return nil, nil, nil, ErrUserInactive
	}

	roles, sections := extractRolesAndSections(user.UserRoles)

	return &user, roles, sections, nil
}

func extractRolesAndSections(userRoles []models.UserRole) ([]string, []string) {
	roleSet := make(map[string]bool)
	sectionSet := make(map[string]bool)

	for _, ur := range userRoles {
		roleSet[ur.Role.Name] = true
		if ur.Role.Name == "super_admin" {
			sectionSet["*"] = true
		} else {
			for _, rp := range ur.Role.RolePermissions {
				sectionSet[rp.Section.Key] = true
			}
		}
	}

	roles := make([]string, 0, len(roleSet))
	for r := range roleSet {
		roles = append(roles, r)
	}

	sections := make([]string, 0, len(sectionSet))
	for s := range sectionSet {
		sections = append(sections, s)
	}

	return roles, sections
}
