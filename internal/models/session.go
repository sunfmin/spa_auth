package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Session struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID           uuid.UUID `gorm:"type:uuid;not null;index"`
	TokenHash        string    `gorm:"type:varchar(64);uniqueIndex;not null"`
	RefreshTokenHash string    `gorm:"type:varchar(64);uniqueIndex;not null"`
	ExpiresAt        time.Time `gorm:"not null;index"`
	RefreshExpiresAt time.Time `gorm:"not null"`
	LastActivityAt   time.Time `gorm:"not null;default:now()"`
	IPAddress        *string   `gorm:"type:inet"`
	UserAgent        *string   `gorm:"type:varchar(500)"`
	CreatedAt        time.Time `gorm:"not null;default:now()"`

	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (s *Session) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}
