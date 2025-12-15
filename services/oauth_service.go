package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/internal/models"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type OAuthService interface {
	StartOAuth(ctx context.Context, req *pb.OAuthStartRequest) (*pb.OAuthStartResponse, error)
	HandleCallback(ctx context.Context, req *pb.OAuthCallbackRequest) (*pb.OAuthCallbackResponse, error)
}

type oauthService struct {
	db             *gorm.DB
	clientID       string
	clientSecret   string
	redirectURL    string
	jwtService     JWTService
	sessionService SessionService
	stateStore     map[string]time.Time // In production, use Redis
}

type oauthServiceBuilder struct {
	db             *gorm.DB
	clientID       string
	clientSecret   string
	redirectURL    string
	jwtService     JWTService
	sessionService SessionService
}

func NewOAuthService(db *gorm.DB) *oauthServiceBuilder {
	return &oauthServiceBuilder{db: db}
}

func (b *oauthServiceBuilder) WithClientID(clientID string) *oauthServiceBuilder {
	b.clientID = clientID
	return b
}

func (b *oauthServiceBuilder) WithClientSecret(clientSecret string) *oauthServiceBuilder {
	b.clientSecret = clientSecret
	return b
}

func (b *oauthServiceBuilder) WithRedirectURL(redirectURL string) *oauthServiceBuilder {
	b.redirectURL = redirectURL
	return b
}

func (b *oauthServiceBuilder) WithJWTService(js JWTService) *oauthServiceBuilder {
	b.jwtService = js
	return b
}

func (b *oauthServiceBuilder) WithSessionService(ss SessionService) *oauthServiceBuilder {
	b.sessionService = ss
	return b
}

func (b *oauthServiceBuilder) Build() OAuthService {
	return &oauthService{
		db:             b.db,
		clientID:       b.clientID,
		clientSecret:   b.clientSecret,
		redirectURL:    b.redirectURL,
		jwtService:     b.jwtService,
		sessionService: b.sessionService,
		stateStore:     make(map[string]time.Time),
	}
}

func (s *oauthService) StartOAuth(ctx context.Context, req *pb.OAuthStartRequest) (*pb.OAuthStartResponse, error) {
	if s.clientID == "" {
		return nil, fmt.Errorf("OAuth not configured: %w", ErrInternalError)
	}

	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	// Store state with expiry (5 minutes)
	s.stateStore[state] = time.Now().Add(5 * time.Minute)

	redirectURI := s.redirectURL
	if req.RedirectUri != "" {
		redirectURI = req.RedirectUri
	}

	params := url.Values{
		"client_id":     {s.clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}

	authURL := "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()

	return &pb.OAuthStartResponse{
		AuthorizationUrl: authURL,
		State:            state,
	}, nil
}

func (s *oauthService) HandleCallback(ctx context.Context, req *pb.OAuthCallbackRequest) (*pb.OAuthCallbackResponse, error) {
	if req.Code == "" {
		return nil, fmt.Errorf("missing authorization code: %w", ErrInvalidCredentials)
	}

	// Validate state
	expiry, exists := s.stateStore[req.State]
	if !exists || time.Now().After(expiry) {
		return nil, ErrOAuthStateMismatch
	}
	delete(s.stateStore, req.State)

	// Exchange code for tokens
	googleUser, err := s.exchangeCodeForUser(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	// Find user by email (must be pre-registered)
	var user models.User
	err = s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("email = ?", googleUser.Email).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrOAuthEmailNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	// Link Google account if not already linked
	if user.GoogleID == nil {
		user.GoogleID = &googleUser.ID
		if err := s.db.WithContext(ctx).Save(&user).Error; err != nil {
			return nil, fmt.Errorf("link google account: %w", err)
		}
	}

	// Generate tokens
	roles, sections := extractRolesAndSections(user.UserRoles)
	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, user.ID, user.Email, roles, sections)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	// Create session
	_, err = s.sessionService.CreateSession(ctx, user.ID, tokenPair.AccessToken, tokenPair.RefreshToken, s.jwtService.GetAccessTTL(), s.jwtService.GetRefreshTTL(), "", "")
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &pb.OAuthCallbackResponse{
		User:         modelToProtoUser(&user, roles, sections),
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    timestamppb.New(tokenPair.ExpiresAt),
	}, nil
}

type googleUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (s *oauthService) exchangeCodeForUser(ctx context.Context, code string) (*googleUserInfo, error) {
	// Exchange code for access token
	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {s.redirectURL},
	})
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenData struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	// Get user info
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	userResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo failed with status %d", userResp.StatusCode)
	}

	var userInfo googleUserInfo
	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	return &userInfo, nil
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// MockOAuthService for testing without real Google API calls
type MockOAuthService struct {
	db             *gorm.DB
	jwtService     JWTService
	sessionService SessionService
	stateStore     map[string]time.Time
	mockEmail      string
	mockGoogleID   string
}

func NewMockOAuthService(db *gorm.DB, jwtService JWTService, sessionService SessionService) *MockOAuthService {
	return &MockOAuthService{
		db:             db,
		jwtService:     jwtService,
		sessionService: sessionService,
		stateStore:     make(map[string]time.Time),
	}
}

func (s *MockOAuthService) SetMockUser(email, googleID string) {
	s.mockEmail = email
	s.mockGoogleID = googleID
}

func (s *MockOAuthService) StartOAuth(ctx context.Context, req *pb.OAuthStartRequest) (*pb.OAuthStartResponse, error) {
	state, _ := generateState()
	s.stateStore[state] = time.Now().Add(5 * time.Minute)

	return &pb.OAuthStartResponse{
		AuthorizationUrl: "https://accounts.google.com/mock-auth?state=" + state,
		State:            state,
	}, nil
}

func (s *MockOAuthService) HandleCallback(ctx context.Context, req *pb.OAuthCallbackRequest) (*pb.OAuthCallbackResponse, error) {
	if req.Code == "" {
		return nil, fmt.Errorf("missing authorization code: %w", ErrInvalidCredentials)
	}

	// For "cancelled" test case
	if strings.Contains(req.Code, "cancelled") {
		return nil, fmt.Errorf("OAuth cancelled: %w", ErrInvalidCredentials)
	}

	// Validate state
	expiry, exists := s.stateStore[req.State]
	if !exists || time.Now().After(expiry) {
		return nil, ErrOAuthStateMismatch
	}
	delete(s.stateStore, req.State)

	// Find user by mock email
	var user models.User
	err := s.db.WithContext(ctx).
		Preload("UserRoles.Role.RolePermissions.Section").
		Where("email = ?", s.mockEmail).
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrOAuthEmailNotFound
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	// Link Google account
	if user.GoogleID == nil && s.mockGoogleID != "" {
		user.GoogleID = &s.mockGoogleID
		s.db.WithContext(ctx).Save(&user)
	}

	roles, sections := extractRolesAndSections(user.UserRoles)
	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, user.ID, user.Email, roles, sections)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	_, err = s.sessionService.CreateSession(ctx, user.ID, tokenPair.AccessToken, tokenPair.RefreshToken, s.jwtService.GetAccessTTL(), s.jwtService.GetRefreshTTL(), "", "")
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &pb.OAuthCallbackResponse{
		User:         modelToProtoUser(&user, roles, sections),
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    timestamppb.New(tokenPair.ExpiresAt),
	}, nil
}
