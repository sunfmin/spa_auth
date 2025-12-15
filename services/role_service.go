package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/user/spa_auth/internal/models"
	"gorm.io/gorm"
)

type RoleService interface {
	CreateRole(ctx context.Context, name, description string, sectionIDs []uuid.UUID, createdBy uuid.UUID) (*models.Role, error)
	GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error)
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)
	ListRoles(ctx context.Context, includeSystem bool) ([]*models.Role, error)
	UpdateRole(ctx context.Context, roleID uuid.UUID, name, description *string, sectionIDs []uuid.UUID) (*models.Role, error)
	DeleteRole(ctx context.Context, roleID uuid.UUID) error
	CreateSpaSection(ctx context.Context, key, displayName, description string) (*models.SpaSection, error)
	ListSpaSections(ctx context.Context) ([]*models.SpaSection, error)
	CheckSectionAccess(ctx context.Context, userID uuid.UUID, sectionKey string) (bool, error)
	GetUserSections(ctx context.Context, userID uuid.UUID) ([]*models.SpaSection, error)
}

type roleService struct {
	db *gorm.DB
}

type roleServiceBuilder struct {
	db *gorm.DB
}

func NewRoleService(db *gorm.DB) *roleServiceBuilder {
	return &roleServiceBuilder{db: db}
}

func (b *roleServiceBuilder) Build() RoleService {
	return &roleService{db: b.db}
}

func (s *roleService) CreateRole(ctx context.Context, name, description string, sectionIDs []uuid.UUID, createdBy uuid.UUID) (*models.Role, error) {
	if name == "" {
		return nil, fmt.Errorf("role name: %w", ErrRoleNotFound)
	}

	var existing models.Role
	if err := s.db.WithContext(ctx).Where("name = ?", name).First(&existing).Error; err == nil {
		return nil, fmt.Errorf("role name already exists: %w", ErrRoleNotFound)
	}

	desc := &description
	if description == "" {
		desc = nil
	}

	role := &models.Role{
		Name:        name,
		Description: desc,
		IsSystem:    false,
		CreatedBy:   &createdBy,
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(role).Error; err != nil {
			return fmt.Errorf("create role: %w", err)
		}

		for _, sectionID := range sectionIDs {
			perm := &models.RolePermission{
				RoleID:    role.ID,
				SectionID: sectionID,
			}
			if err := tx.Create(perm).Error; err != nil {
				return fmt.Errorf("assign section: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return s.GetRole(ctx, role.ID)
}

func (s *roleService) GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	var role models.Role
	err := s.db.WithContext(ctx).
		Preload("RolePermissions.Section").
		Where("id = ?", roleID).
		First(&role).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("find role: %w", err)
	}

	return &role, nil
}

func (s *roleService) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	var role models.Role
	err := s.db.WithContext(ctx).
		Preload("RolePermissions.Section").
		Where("name = ?", name).
		First(&role).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("find role: %w", err)
	}

	return &role, nil
}

func (s *roleService) ListRoles(ctx context.Context, includeSystem bool) ([]*models.Role, error) {
	var roles []*models.Role

	query := s.db.WithContext(ctx).Preload("RolePermissions.Section")
	if !includeSystem {
		query = query.Where("is_system = ?", false)
	}

	err := query.Order("name ASC").Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}

	return roles, nil
}

func (s *roleService) UpdateRole(ctx context.Context, roleID uuid.UUID, name, description *string, sectionIDs []uuid.UUID) (*models.Role, error) {
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ?", roleID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("find role: %w", err)
	}

	if role.IsSystem {
		return nil, ErrRoleIsSystem
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		updates := make(map[string]interface{})

		if name != nil && *name != "" {
			var existing models.Role
			if err := tx.Where("name = ? AND id != ?", *name, roleID).First(&existing).Error; err == nil {
				return fmt.Errorf("role name already exists")
			}
			updates["name"] = *name
		}

		if description != nil {
			updates["description"] = *description
		}

		if len(updates) > 0 {
			if err := tx.Model(&role).Updates(updates).Error; err != nil {
				return fmt.Errorf("update role: %w", err)
			}
		}

		if len(sectionIDs) > 0 {
			if err := tx.Delete(&models.RolePermission{}, "role_id = ?", roleID).Error; err != nil {
				return fmt.Errorf("delete old permissions: %w", err)
			}

			for _, sectionID := range sectionIDs {
				perm := &models.RolePermission{
					RoleID:    roleID,
					SectionID: sectionID,
				}
				if err := tx.Create(perm).Error; err != nil {
					return fmt.Errorf("assign section: %w", err)
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return s.GetRole(ctx, roleID)
}

func (s *roleService) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ?", roleID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrRoleNotFound
		}
		return fmt.Errorf("find role: %w", err)
	}

	if role.IsSystem {
		return ErrRoleIsSystem
	}

	var count int64
	s.db.WithContext(ctx).Model(&models.UserRole{}).Where("role_id = ?", roleID).Count(&count)
	if count > 0 {
		return ErrRoleHasUsers
	}

	if err := s.db.WithContext(ctx).Delete(&role).Error; err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	return nil
}

func (s *roleService) CreateSpaSection(ctx context.Context, key, displayName, description string) (*models.SpaSection, error) {
	if key == "" {
		return nil, fmt.Errorf("section key: %w", ErrSectionNotFound)
	}

	var existing models.SpaSection
	if err := s.db.WithContext(ctx).Where("key = ?", key).First(&existing).Error; err == nil {
		return nil, fmt.Errorf("section key already exists")
	}

	desc := &description
	if description == "" {
		desc = nil
	}

	section := &models.SpaSection{
		Key:         key,
		DisplayName: displayName,
		Description: desc,
	}

	if err := s.db.WithContext(ctx).Create(section).Error; err != nil {
		return nil, fmt.Errorf("create section: %w", err)
	}

	return section, nil
}

func (s *roleService) ListSpaSections(ctx context.Context) ([]*models.SpaSection, error) {
	var sections []*models.SpaSection
	err := s.db.WithContext(ctx).Order("key ASC").Find(&sections).Error
	if err != nil {
		return nil, fmt.Errorf("list sections: %w", err)
	}
	return sections, nil
}

func (s *roleService) CheckSectionAccess(ctx context.Context, userID uuid.UUID, sectionKey string) (bool, error) {
	var user models.User
	err := s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("id = ?", userID).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, ErrUserNotFound
		}
		return false, fmt.Errorf("find user: %w", err)
	}

	for _, ur := range user.UserRoles {
		if ur.Role.Name == "super_admin" {
			return true, nil
		}
		for _, rp := range ur.Role.RolePermissions {
			if rp.Section.Key == sectionKey {
				return true, nil
			}
		}
	}

	return false, nil
}

func (s *roleService) GetUserSections(ctx context.Context, userID uuid.UUID) ([]*models.SpaSection, error) {
	var user models.User
	err := s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("id = ?", userID).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	sectionMap := make(map[uuid.UUID]*models.SpaSection)

	for _, ur := range user.UserRoles {
		if ur.Role.Name == "super_admin" {
			return s.ListSpaSections(ctx)
		}
		for _, rp := range ur.Role.RolePermissions {
			sectionMap[rp.Section.ID] = &rp.Section
		}
	}

	sections := make([]*models.SpaSection, 0, len(sectionMap))
	for _, section := range sectionMap {
		sections = append(sections, section)
	}

	return sections, nil
}
