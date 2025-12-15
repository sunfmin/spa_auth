package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SpaSection struct {
	ID          uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Key         string         `gorm:"type:varchar(100);uniqueIndex;not null"`
	DisplayName string         `gorm:"type:varchar(100);not null"`
	Description *string        `gorm:"type:text"`
	CreatedAt   time.Time      `gorm:"not null;default:now()"`
	UpdatedAt   time.Time      `gorm:"not null;default:now()"`
	DeletedAt   gorm.DeletedAt `gorm:"index"`

	RolePermissions []RolePermission `gorm:"foreignKey:SectionID"`
}

func (s *SpaSection) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}
