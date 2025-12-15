package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/internal/models"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type AuthService interface {
	Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error)
	Logout(ctx context.Context, req *pb.LogoutRequest, token string) (*pb.LogoutResponse, error)
	GetCurrentUser(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.User, error)
	RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error)
	ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error)
	RequestPasswordReset(ctx context.Context, req *pb.RequestPasswordResetRequest) (*pb.RequestPasswordResetResponse, error)
	ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error)
}

type authService struct {
	db              *gorm.DB
	passwordService PasswordService
	jwtService      JWTService
	sessionService  SessionService
}

type authServiceBuilder struct {
	db              *gorm.DB
	passwordService PasswordService
	jwtService      JWTService
	sessionService  SessionService
}

func NewAuthService(db *gorm.DB) *authServiceBuilder {
	return &authServiceBuilder{db: db}
}

func (b *authServiceBuilder) WithPasswordService(ps PasswordService) *authServiceBuilder {
	b.passwordService = ps
	return b
}

func (b *authServiceBuilder) WithJWTService(js JWTService) *authServiceBuilder {
	b.jwtService = js
	return b
}

func (b *authServiceBuilder) WithSessionService(ss SessionService) *authServiceBuilder {
	b.sessionService = ss
	return b
}

func (b *authServiceBuilder) Build() AuthService {
	return &authService{
		db:              b.db,
		passwordService: b.passwordService,
		jwtService:      b.jwtService,
		sessionService:  b.sessionService,
	}
}

func (s *authService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("email: %w", ErrInvalidEmail)
	}
	if req.Password == "" {
		return nil, ErrInvalidCredentials
	}

	var user models.User
	err := s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("email = ?", req.Email).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	if user.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}

	if err := s.passwordService.VerifyPassword(*user.PasswordHash, req.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	roles, sections := extractRolesAndSections(user.UserRoles)

	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, user.ID, user.Email, roles, sections)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	return &pb.LoginResponse{
		User:         modelToProtoUser(&user, roles, sections),
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    timestamppb.New(tokenPair.ExpiresAt),
	}, nil
}

func (s *authService) Logout(ctx context.Context, req *pb.LogoutRequest, token string) (*pb.LogoutResponse, error) {
	_, err := s.jwtService.ValidateToken(ctx, token)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	tokenHash := HashToken(token)
	session, err := s.sessionService.ValidateSession(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	if err := s.sessionService.InvalidateSession(ctx, session.ID); err != nil {
		return nil, fmt.Errorf("invalidate session: %w", err)
	}

	return &pb.LogoutResponse{Success: true}, nil
}

func (s *authService) GetCurrentUser(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.User, error) {
	claims, err := s.jwtService.ValidateToken(ctx, req.Token)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	var user models.User
	err = s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("id = ?", userID).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	roles, sections := extractRolesAndSections(user.UserRoles)

	return modelToProtoUser(&user, roles, sections), nil
}

func modelToProtoUser(user *models.User, roles, sections []string) *pb.User {
	pbUser := &pb.User{
		Id:          user.ID.String(),
		Email:       user.Email,
		IsActive:    user.IsActive,
		Roles:       roles,
		Sections:    sections,
		HasPassword: user.PasswordHash != nil,
		HasGoogle:   user.GoogleID != nil,
		CreatedAt:   timestamppb.New(user.CreatedAt),
	}

	if user.LastLoginAt != nil {
		pbUser.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}

	if user.CreatedBy != nil {
		pbUser.CreatedBy = user.CreatedBy.String()
	}

	return pbUser
}

func (s *authService) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, ErrTokenInvalid
	}

	// Validate refresh token via session service
	refreshTokenHash := HashToken(req.RefreshToken)
	session, err := s.sessionService.ValidateRefreshToken(ctx, refreshTokenHash)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	var user models.User
	err = s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("id = ?", session.UserID).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	roles, sections := extractRolesAndSections(user.UserRoles)

	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, user.ID, user.Email, roles, sections)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	// Update session with new tokens
	if err := s.sessionService.UpdateSessionTokens(ctx, session.ID, HashToken(tokenPair.AccessToken), HashToken(tokenPair.RefreshToken)); err != nil {
		return nil, fmt.Errorf("update session: %w", err)
	}

	return &pb.RefreshTokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    timestamppb.New(tokenPair.ExpiresAt),
	}, nil
}

func (s *authService) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	if req.Token == "" {
		return &pb.ValidateTokenResponse{Valid: false}, nil
	}

	claims, err := s.jwtService.ValidateToken(ctx, req.Token)
	if err != nil {
		return &pb.ValidateTokenResponse{Valid: false}, nil
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return &pb.ValidateTokenResponse{Valid: false}, nil
	}

	var user models.User
	err = s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("id = ?", userID).
		First(&user).Error

	if err != nil {
		return &pb.ValidateTokenResponse{Valid: false}, nil
	}

	if !user.IsActive {
		return &pb.ValidateTokenResponse{Valid: false}, nil
	}

	roles, sections := extractRolesAndSections(user.UserRoles)

	return &pb.ValidateTokenResponse{
		Valid: true,
		User:  modelToProtoUser(&user, roles, sections),
		Roles: roles,
	}, nil
}

func (s *authService) RequestPasswordReset(ctx context.Context, req *pb.RequestPasswordResetRequest) (*pb.RequestPasswordResetResponse, error) {
	// Always return success to prevent email enumeration
	// In production, this would send an email if user exists
	return &pb.RequestPasswordResetResponse{
		Success: true,
		Message: "If the email exists, a password reset link has been sent",
	}, nil
}

func (s *authService) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error) {
	if req.Token == "" {
		return nil, ErrTokenInvalid
	}

	if len(req.NewPassword) < 8 {
		return nil, ErrPasswordTooShort
	}

	// In production, this would validate the reset token and update password
	// For now, return token invalid since we don't have a real token
	return nil, ErrTokenInvalid
}

func extractRolesAndSections(userRoles []models.UserRole) ([]string, []string) {
	roleSet := make(map[string]bool)
	sectionSet := make(map[string]bool)

	for _, ur := range userRoles {
		roleSet[ur.Role.Name] = true
		if ur.Role.Name == "super_admin" {
			sectionSet["*"] = true
		} else {
			for _, rp := range ur.Role.RolePermissions {
				sectionSet[rp.Section.Key] = true
			}
		}
	}

	roles := make([]string, 0, len(roleSet))
	for r := range roleSet {
		roles = append(roles, r)
	}

	sections := make([]string, 0, len(sectionSet))
	for sec := range sectionSet {
		sections = append(sections, sec)
	}

	return roles, sections
}
