package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/user/spa_auth/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type PasswordService interface {
	HashPassword(password string) (string, error)
	VerifyPassword(hash, password string) error
	CreateResetToken(ctx context.Context, userID uuid.UUID) (string, error)
	ValidateResetToken(ctx context.Context, token string) (*models.PasswordResetToken, error)
	UseResetToken(ctx context.Context, tokenID uuid.UUID) error
}

type passwordService struct {
	db       *gorm.DB
	cost     int
	resetTTL time.Duration
}

type passwordServiceBuilder struct {
	db       *gorm.DB
	cost     int
	resetTTL time.Duration
}

func NewPasswordService(db *gorm.DB) *passwordServiceBuilder {
	return &passwordServiceBuilder{
		db:       db,
		cost:     12,
		resetTTL: 24 * time.Hour,
	}
}

func (b *passwordServiceBuilder) WithCost(cost int) *passwordServiceBuilder {
	b.cost = cost
	return b
}

func (b *passwordServiceBuilder) WithResetTTL(ttl time.Duration) *passwordServiceBuilder {
	b.resetTTL = ttl
	return b
}

func (b *passwordServiceBuilder) Build() PasswordService {
	return &passwordService{
		db:       b.db,
		cost:     b.cost,
		resetTTL: b.resetTTL,
	}
}

func (s *passwordService) HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", ErrPasswordTooShort
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

func (s *passwordService) VerifyPassword(hash, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

func (s *passwordService) CreateResetToken(ctx context.Context, userID uuid.UUID) (string, error) {
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND used_at IS NULL", userID).
		Delete(&models.PasswordResetToken{}).Error; err != nil {
		return "", fmt.Errorf("failed to invalidate old tokens: %w", err)
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	resetToken := &models.PasswordResetToken{
		UserID:    userID,
		TokenHash: HashToken(token),
		ExpiresAt: time.Now().Add(s.resetTTL),
	}

	if err := s.db.WithContext(ctx).Create(resetToken).Error; err != nil {
		return "", fmt.Errorf("failed to create reset token: %w", err)
	}

	return token, nil
}

func (s *passwordService) ValidateResetToken(ctx context.Context, token string) (*models.PasswordResetToken, error) {
	tokenHash := HashToken(token)

	var resetToken models.PasswordResetToken
	err := s.db.WithContext(ctx).
		Where("token_hash = ?", tokenHash).
		First(&resetToken).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrTokenInvalid
		}
		return nil, fmt.Errorf("failed to find reset token: %w", err)
	}

	if resetToken.UsedAt != nil {
		return nil, ErrTokenAlreadyUsed
	}

	if time.Now().After(resetToken.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return &resetToken, nil
}

func (s *passwordService) UseResetToken(ctx context.Context, tokenID uuid.UUID) error {
	now := time.Now()
	return s.db.WithContext(ctx).
		Model(&models.PasswordResetToken{}).
		Where("id = ?", tokenID).
		Update("used_at", &now).Error
}
