package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Email        string         `gorm:"type:varchar(254);uniqueIndex;not null"`
	PasswordHash *string        `gorm:"type:varchar(60)"`
	GoogleID     *string        `gorm:"type:varchar(255);uniqueIndex"`
	IsActive     bool           `gorm:"not null;default:true"`
	CreatedBy    *uuid.UUID     `gorm:"type:uuid"`
	CreatedAt    time.Time      `gorm:"not null;default:now()"`
	UpdatedAt    time.Time      `gorm:"not null;default:now()"`
	LastLoginAt  *time.Time     `gorm:""`
	DeletedAt    gorm.DeletedAt `gorm:"index"`

	UserRoles []UserRole `gorm:"foreignKey:UserID"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}
