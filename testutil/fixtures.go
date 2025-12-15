package testutil

import (
	"time"

	"github.com/google/uuid"
	"github.com/user/spa_auth/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func CreateTestUser(db *gorm.DB, email string, password string, isActive bool) (*models.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	hashStr := string(hash)

	user := &models.User{
		Email:        email,
		PasswordHash: &hashStr,
		IsActive:     isActive,
	}

	if err := db.Create(user).Error; err != nil {
		return nil, err
	}
	
	if !isActive {
		if err := db.Model(user).Update("is_active", false).Error; err != nil {
			return nil, err
		}
		user.IsActive = false
	}
	
	return user, nil
}

func CreateTestRole(db *gorm.DB, name string, description string, isSystem bool) (*models.Role, error) {
	role := &models.Role{
		Name:        name,
		Description: &description,
		IsSystem:    isSystem,
	}

	if err := db.Create(role).Error; err != nil {
		return nil, err
	}
	return role, nil
}

func CreateTestRoleWithCreator(db *gorm.DB, name string, description string, isSystem bool, createdBy uuid.UUID) (*models.Role, error) {
	role := &models.Role{
		Name:        name,
		Description: &description,
		IsSystem:    isSystem,
		CreatedBy:   &createdBy,
	}

	if err := db.Create(role).Error; err != nil {
		return nil, err
	}
	return role, nil
}

func CreateTestSpaSection(db *gorm.DB, key string, displayName string) (*models.SpaSection, error) {
	section := &models.SpaSection{
		Key:         key,
		DisplayName: displayName,
	}

	if err := db.Create(section).Error; err != nil {
		return nil, err
	}
	return section, nil
}

func CreateTestUserRole(db *gorm.DB, userID, roleID uuid.UUID) (*models.UserRole, error) {
	userRole := &models.UserRole{
		UserID:     userID,
		RoleID:     roleID,
		AssignedAt: time.Now(),
	}

	if err := db.Create(userRole).Error; err != nil {
		return nil, err
	}
	return userRole, nil
}

func CreateTestRolePermission(db *gorm.DB, roleID, sectionID uuid.UUID) (*models.RolePermission, error) {
	perm := &models.RolePermission{
		RoleID:    roleID,
		SectionID: sectionID,
		CreatedAt: time.Now(),
	}

	if err := db.Create(perm).Error; err != nil {
		return nil, err
	}
	return perm, nil
}

func CreateTestSession(db *gorm.DB, userID uuid.UUID, tokenHash, refreshHash string, expiresAt time.Time) (*models.Session, error) {
	session := &models.Session{
		UserID:           userID,
		TokenHash:        tokenHash,
		RefreshTokenHash: refreshHash,
		ExpiresAt:        expiresAt,
		RefreshExpiresAt: expiresAt.Add(7 * 24 * time.Hour),
		LastActivityAt:   time.Now(),
	}

	if err := db.Create(session).Error; err != nil {
		return nil, err
	}
	return session, nil
}

func CreateSuperAdmin(db *gorm.DB, email, password string) (*models.User, *models.Role, error) {
	role, err := CreateTestRole(db, "super_admin", "Full system access", true)
	if err != nil {
		return nil, nil, err
	}

	user, err := CreateTestUser(db, email, password, true)
	if err != nil {
		return nil, nil, err
	}

	_, err = CreateTestUserRole(db, user.ID, role.ID)
	if err != nil {
		return nil, nil, err
	}

	return user, role, nil
}
