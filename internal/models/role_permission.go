package models

import (
	"time"

	"github.com/google/uuid"
)

type RolePermission struct {
	RoleID    uuid.UUID `gorm:"type:uuid;primaryKey"`
	SectionID uuid.UUID `gorm:"type:uuid;primaryKey"`
	CreatedAt time.Time `gorm:"not null;default:now()"`

	Role    Role       `gorm:"foreignKey:RoleID;constraint:OnDelete:CASCADE"`
	Section SpaSection `gorm:"foreignKey:SectionID;constraint:OnDelete:CASCADE"`
}
