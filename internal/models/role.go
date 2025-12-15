package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Role struct {
	ID          uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Name        string         `gorm:"type:varchar(50);uniqueIndex;not null"`
	Description *string        `gorm:"type:text"`
	IsSystem    bool           `gorm:"not null;default:false"`
	CreatedBy   *uuid.UUID     `gorm:"type:uuid"`
	CreatedAt   time.Time      `gorm:"not null;default:now()"`
	UpdatedAt   time.Time      `gorm:"not null;default:now()"`
	DeletedAt   gorm.DeletedAt `gorm:"index"`

	RolePermissions []RolePermission `gorm:"foreignKey:RoleID"`
	UserRoles       []UserRole       `gorm:"foreignKey:RoleID"`
}

func (r *Role) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}
