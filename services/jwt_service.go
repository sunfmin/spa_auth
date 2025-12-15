package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTService interface {
	GenerateTokenPair(ctx context.Context, userID uuid.UUID, email string, roles, sections []string) (*TokenPair, error)
	ValidateToken(ctx context.Context, tokenString string) (*JWTClaims, error)
	GetAccessTTL() time.Duration
	GetRefreshTTL() time.Duration
}

type jwtService struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

type jwtServiceBuilder struct {
	secret     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

type JWTClaims struct {
	jwt.RegisteredClaims
	UserID   string   `json:"user_id"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	Sections []string `json:"sections"`
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

func NewJWTService(secret string) *jwtServiceBuilder {
	return &jwtServiceBuilder{
		secret:     secret,
		accessTTL:  15 * time.Minute,
		refreshTTL: 7 * 24 * time.Hour,
	}
}

func (b *jwtServiceBuilder) WithAccessTTL(ttl time.Duration) *jwtServiceBuilder {
	b.accessTTL = ttl
	return b
}

func (b *jwtServiceBuilder) WithRefreshTTL(ttl time.Duration) *jwtServiceBuilder {
	b.refreshTTL = ttl
	return b
}

func (b *jwtServiceBuilder) Build() JWTService {
	return &jwtService{
		secret:     []byte(b.secret),
		accessTTL:  b.accessTTL,
		refreshTTL: b.refreshTTL,
	}
}

func (s *jwtService) GenerateTokenPair(ctx context.Context, userID uuid.UUID, email string, roles, sections []string) (*TokenPair, error) {
	now := time.Now()
	expiresAt := now.Add(s.accessTTL)

	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        uuid.New().String(),
		},
		UserID:   userID.String(),
		Email:    email,
		Roles:    roles,
		Sections: sections,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString(s.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	refreshToken := uuid.New().String()

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *jwtService) ValidateToken(ctx context.Context, tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	return claims, nil
}

func (s *jwtService) GetAccessTTL() time.Duration {
	return s.accessTTL
}

func (s *jwtService) GetRefreshTTL() time.Duration {
	return s.refreshTTL
}

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
