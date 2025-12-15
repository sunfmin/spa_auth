package services

import (
	"github.com/user/spa_auth/internal/models"
	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.SpaSection{},
		&models.RolePermission{},
		&models.UserRole{},
		&models.Session{},
		&models.PasswordResetToken{},
	)
}
