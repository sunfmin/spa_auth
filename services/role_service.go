package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/internal/models"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type RoleService interface {
	CreateRole(ctx context.Context, req *pb.CreateRoleRequest, createdBy string) (*pb.CreateRoleResponse, error)
	GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.GetRoleResponse, error)
	ListRoles(ctx context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error)
	UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.UpdateRoleResponse, error)
	DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*pb.DeleteRoleResponse, error)
	CreateSpaSection(ctx context.Context, req *pb.CreateSpaSectionRequest) (*pb.CreateSpaSectionResponse, error)
	ListSpaSections(ctx context.Context, req *pb.ListSpaSectionsRequest) (*pb.ListSpaSectionsResponse, error)
	CheckSectionAccess(ctx context.Context, req *pb.CheckSectionAccessRequest) (*pb.CheckSectionAccessResponse, error)
	GetUserSections(ctx context.Context, req *pb.GetUserSectionsRequest) (*pb.GetUserSectionsResponse, error)
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

func (s *roleService) CreateRole(ctx context.Context, req *pb.CreateRoleRequest, createdBy string) (*pb.CreateRoleResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("role name: %w", ErrInvalidRoleName)
	}

	var existing models.Role
	if err := s.db.WithContext(ctx).Where("name = ?", req.Name).First(&existing).Error; err == nil {
		return nil, ErrRoleAlreadyExists
	}

	createdByUUID, err := uuid.Parse(createdBy)
	if err != nil {
		return nil, fmt.Errorf("invalid createdBy: %w", err)
	}

	desc := &req.Description
	if req.Description == "" {
		desc = nil
	}

	role := &models.Role{
		Name:        req.Name,
		Description: desc,
		IsSystem:    false,
		CreatedBy:   &createdByUUID,
	}

	var sectionIDs []uuid.UUID
	for _, sectionID := range req.SectionIds {
		id, err := uuid.Parse(sectionID)
		if err != nil {
			return nil, fmt.Errorf("invalid section ID %s: %w", sectionID, err)
		}
		sectionIDs = append(sectionIDs, id)
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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

	getResp, err := s.GetRole(ctx, &pb.GetRoleRequest{Identifier: &pb.GetRoleRequest_Id{Id: role.ID.String()}})
	if err != nil {
		return nil, err
	}

	return &pb.CreateRoleResponse{Role: getResp.Role}, nil
}

func (s *roleService) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.GetRoleResponse, error) {
	var role models.Role
	var err error

	switch id := req.Identifier.(type) {
	case *pb.GetRoleRequest_Id:
		roleID, parseErr := uuid.Parse(id.Id)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid role ID: %w", ErrInvalidID)
		}
		err = s.db.WithContext(ctx).
			Preload("RolePermissions.Section").
			Where("id = ?", roleID).
			First(&role).Error
	case *pb.GetRoleRequest_Name:
		err = s.db.WithContext(ctx).
			Preload("RolePermissions.Section").
			Where("name = ?", id.Name).
			First(&role).Error
	default:
		return nil, fmt.Errorf("identifier required")
	}

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("find role: %w", err)
	}

	return &pb.GetRoleResponse{Role: modelToProtoRole(&role)}, nil
}

func (s *roleService) ListRoles(ctx context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	var roles []models.Role

	query := s.db.WithContext(ctx).Preload("RolePermissions.Section")
	if !req.IncludeSystem {
		query = query.Where("is_system = ?", false)
	}

	err := query.Order("name ASC").Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}

	var pbRoles []*pb.Role
	for _, role := range roles {
		pbRoles = append(pbRoles, modelToProtoRole(&role))
	}

	return &pb.ListRolesResponse{Roles: pbRoles}, nil
}

func (s *roleService) UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.UpdateRoleResponse, error) {
	roleID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID: %w", err)
	}

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

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		updates := make(map[string]interface{})

		if req.Name != nil && *req.Name != "" {
			var existing models.Role
			if err := tx.Where("name = ? AND id != ?", *req.Name, roleID).First(&existing).Error; err == nil {
				return fmt.Errorf("role name already exists")
			}
			updates["name"] = *req.Name
		}

		if req.Description != nil {
			updates["description"] = *req.Description
		}

		if len(updates) > 0 {
			if err := tx.Model(&role).Updates(updates).Error; err != nil {
				return fmt.Errorf("update role: %w", err)
			}
		}

		if len(req.SectionIds) > 0 {
			if err := tx.Delete(&models.RolePermission{}, "role_id = ?", roleID).Error; err != nil {
				return fmt.Errorf("delete old permissions: %w", err)
			}

			for _, sectionIDStr := range req.SectionIds {
				sectionID, err := uuid.Parse(sectionIDStr)
				if err != nil {
					return fmt.Errorf("invalid section ID %s: %w", sectionIDStr, err)
				}
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

	getResp, err := s.GetRole(ctx, &pb.GetRoleRequest{Identifier: &pb.GetRoleRequest_Id{Id: req.Id}})
	if err != nil {
		return nil, err
	}

	return &pb.UpdateRoleResponse{Role: getResp.Role}, nil
}

func (s *roleService) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*pb.DeleteRoleResponse, error) {
	roleID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID: %w", ErrInvalidID)
	}

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

	var count int64
	s.db.WithContext(ctx).Model(&models.UserRole{}).Where("role_id = ?", roleID).Count(&count)
	if count > 0 {
		return nil, ErrRoleHasUsers
	}

	if err := s.db.WithContext(ctx).Delete(&role).Error; err != nil {
		return nil, fmt.Errorf("delete role: %w", err)
	}

	return &pb.DeleteRoleResponse{Success: true, Message: "Role deleted successfully"}, nil
}

func (s *roleService) CreateSpaSection(ctx context.Context, req *pb.CreateSpaSectionRequest) (*pb.CreateSpaSectionResponse, error) {
	if req.Key == "" {
		return nil, fmt.Errorf("section key: %w", ErrSectionNotFound)
	}

	var existing models.SpaSection
	if err := s.db.WithContext(ctx).Where("key = ?", req.Key).First(&existing).Error; err == nil {
		return nil, fmt.Errorf("section key already exists")
	}

	desc := &req.Description
	if req.Description == "" {
		desc = nil
	}

	section := &models.SpaSection{
		Key:         req.Key,
		DisplayName: req.DisplayName,
		Description: desc,
	}

	if err := s.db.WithContext(ctx).Create(section).Error; err != nil {
		return nil, fmt.Errorf("create section: %w", err)
	}

	return &pb.CreateSpaSectionResponse{Section: modelToProtoSpaSection(section)}, nil
}

func (s *roleService) ListSpaSections(ctx context.Context, req *pb.ListSpaSectionsRequest) (*pb.ListSpaSectionsResponse, error) {
	var sections []models.SpaSection
	err := s.db.WithContext(ctx).Order("key ASC").Find(&sections).Error
	if err != nil {
		return nil, fmt.Errorf("list sections: %w", err)
	}

	var pbSections []*pb.SpaSection
	for _, section := range sections {
		pbSections = append(pbSections, modelToProtoSpaSection(&section))
	}

	return &pb.ListSpaSectionsResponse{Sections: pbSections}, nil
}

func (s *roleService) CheckSectionAccess(ctx context.Context, req *pb.CheckSectionAccessRequest) (*pb.CheckSectionAccessResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
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

	for _, ur := range user.UserRoles {
		if ur.Role.Name == "super_admin" {
			return &pb.CheckSectionAccessResponse{Allowed: true}, nil
		}
		for _, rp := range ur.Role.RolePermissions {
			if rp.Section.Key == req.SectionKey {
				return &pb.CheckSectionAccessResponse{Allowed: true}, nil
			}
		}
	}

	return &pb.CheckSectionAccessResponse{Allowed: false, Reason: "User does not have access to this section"}, nil
}

func (s *roleService) GetUserSections(ctx context.Context, req *pb.GetUserSectionsRequest) (*pb.GetUserSectionsResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
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

	sectionMap := make(map[uuid.UUID]*models.SpaSection)

	for _, ur := range user.UserRoles {
		if ur.Role.Name == "super_admin" {
			allSections, err := s.ListSpaSections(ctx, &pb.ListSpaSectionsRequest{})
			if err != nil {
				return nil, err
			}
			return &pb.GetUserSectionsResponse{Sections: allSections.Sections}, nil
		}
		for _, rp := range ur.Role.RolePermissions {
			sectionMap[rp.Section.ID] = &rp.Section
		}
	}

	var pbSections []*pb.SpaSection
	for _, section := range sectionMap {
		pbSections = append(pbSections, modelToProtoSpaSection(section))
	}

	return &pb.GetUserSectionsResponse{Sections: pbSections}, nil
}

func modelToProtoRole(role *models.Role) *pb.Role {
	pbRole := &pb.Role{
		Id:        role.ID.String(),
		Name:      role.Name,
		IsSystem:  role.IsSystem,
		CreatedAt: timestamppb.New(role.CreatedAt),
		UpdatedAt: timestamppb.New(role.UpdatedAt),
	}

	if role.Description != nil {
		pbRole.Description = *role.Description
	}

	if role.CreatedBy != nil {
		pbRole.CreatedBy = role.CreatedBy.String()
	}

	for _, rp := range role.RolePermissions {
		pbRole.Sections = append(pbRole.Sections, modelToProtoSpaSection(&rp.Section))
	}

	return pbRole
}

func modelToProtoSpaSection(section *models.SpaSection) *pb.SpaSection {
	pbSection := &pb.SpaSection{
		Id:          section.ID.String(),
		Key:         section.Key,
		DisplayName: section.DisplayName,
		CreatedAt:   timestamppb.New(section.CreatedAt),
	}

	if section.Description != nil {
		pbSection.Description = *section.Description
	}

	return pbSection
}
