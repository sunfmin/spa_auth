package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/user/spa_auth/internal/models"
	"gorm.io/gorm"
)

type SessionService interface {
	CreateSession(ctx context.Context, userID uuid.UUID, accessToken, refreshToken string, accessTTL, refreshTTL time.Duration, ipAddress, userAgent string) (*models.Session, error)
	ValidateSession(ctx context.Context, tokenHash string) (*models.Session, error)
	ValidateRefreshToken(ctx context.Context, refreshTokenHash string) (*models.Session, error)
	InvalidateSession(ctx context.Context, sessionID uuid.UUID) error
	InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error
	UpdateActivity(ctx context.Context, sessionID uuid.UUID) error
}

type sessionService struct {
	db *gorm.DB
}

type sessionServiceBuilder struct {
	db *gorm.DB
}

func NewSessionService(db *gorm.DB) *sessionServiceBuilder {
	return &sessionServiceBuilder{db: db}
}

func (b *sessionServiceBuilder) Build() SessionService {
	return &sessionService{db: b.db}
}

func (s *sessionService) CreateSession(ctx context.Context, userID uuid.UUID, accessToken, refreshToken string, accessTTL, refreshTTL time.Duration, ipAddress, userAgent string) (*models.Session, error) {
	now := time.Now()

	var ip, ua *string
	if ipAddress != "" {
		ip = &ipAddress
	}
	if userAgent != "" {
		ua = &userAgent
	}

	session := &models.Session{
		UserID:           userID,
		TokenHash:        HashToken(accessToken),
		RefreshTokenHash: HashToken(refreshToken),
		ExpiresAt:        now.Add(accessTTL),
		RefreshExpiresAt: now.Add(refreshTTL),
		LastActivityAt:   now,
		IPAddress:        ip,
		UserAgent:        ua,
	}

	if err := s.db.WithContext(ctx).Create(session).Error; err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return session, nil
}

func (s *sessionService) ValidateSession(ctx context.Context, tokenHash string) (*models.Session, error) {
	var session models.Session
	err := s.db.WithContext(ctx).
		Where("token_hash = ?", tokenHash).
		First(&session).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("find session: %w", err)
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return &session, nil
}

func (s *sessionService) ValidateRefreshToken(ctx context.Context, refreshTokenHash string) (*models.Session, error) {
	var session models.Session
	err := s.db.WithContext(ctx).
		Where("refresh_token_hash = ?", refreshTokenHash).
		First(&session).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("find session: %w", err)
	}

	if time.Now().After(session.RefreshExpiresAt) {
		return nil, ErrSessionExpired
	}

	return &session, nil
}

func (s *sessionService) InvalidateSession(ctx context.Context, sessionID uuid.UUID) error {
	result := s.db.WithContext(ctx).Delete(&models.Session{}, "id = ?", sessionID)
	if result.Error != nil {
		return fmt.Errorf("delete session: %w", result.Error)
	}
	return nil
}

func (s *sessionService) InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	result := s.db.WithContext(ctx).Delete(&models.Session{}, "user_id = ?", userID)
	if result.Error != nil {
		return fmt.Errorf("delete user sessions: %w", result.Error)
	}
	return nil
}

func (s *sessionService) UpdateActivity(ctx context.Context, sessionID uuid.UUID) error {
	return s.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("id = ?", sessionID).
		Update("last_activity_at", time.Now()).Error
}
