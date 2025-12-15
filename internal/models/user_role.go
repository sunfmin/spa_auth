package models

import (
	"time"

	"github.com/google/uuid"
)

type UserRole struct {
	UserID     uuid.UUID  `gorm:"type:uuid;primaryKey"`
	RoleID     uuid.UUID  `gorm:"type:uuid;primaryKey"`
	AssignedAt time.Time  `gorm:"not null;default:now()"`
	AssignedBy *uuid.UUID `gorm:"type:uuid"`

	User     User  `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Role     Role  `gorm:"foreignKey:RoleID;constraint:OnDelete:CASCADE"`
	Assigner *User `gorm:"foreignKey:AssignedBy"`
}
