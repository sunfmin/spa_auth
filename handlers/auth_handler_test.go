package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/handlers"
	"github.com/user/spa_auth/services"
	"github.com/user/spa_auth/testutil"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestAuthHandler_Login(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, superAdminRole, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}
	_ = superAdmin
	_ = superAdminRole

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	_ = testUser

	inactiveUser, err := testutil.CreateTestUser(tdb.DB, "inactive@example.com", "inactivepass", false)
	if err != nil {
		t.Fatalf("failed to create inactive user: %v", err)
	}
	_ = inactiveUser

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	jwtSvc := services.NewJWTService("test-secret-key-32-bytes-long!!").Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	authSvc := services.NewAuthService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		Build()

	testCases := []struct {
		name           string
		scenario       string
		request        *pb.LoginRequest
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.LoginResponse, req *pb.LoginRequest)
	}{
		{
			name:     "US1-AS1: Successful login with valid credentials",
			scenario: "Given a user account created by the super admin, When the user enters their correct email and password, Then the system authenticates them",
			request: &pb.LoginRequest{
				Email:    "user@example.com",
				Password: "userpass123",
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.LoginResponse, req *pb.LoginRequest) {
				if resp.AccessToken == "" {
					t.Error("Expected accessToken in response")
				}
				if resp.User == nil {
					t.Fatal("Expected user in response")
				}
				// Use cmp.Diff with protocmp.Transform() per constitution
				expected := &pb.User{
					Id:          resp.User.Id,          // Random UUID from response
					Email:       req.Email,             // From request fixture
					IsActive:    true,                  // Default for active user
					HasPassword: true,                  // User has password (from fixture)
					Roles:       resp.User.Roles,       // Dynamic from DB
					Sections:    resp.User.Sections,    // Dynamic from DB
					CreatedAt:   resp.User.CreatedAt,   // Timestamp from response
				}
				if diff := cmp.Diff(expected, resp.User, protocmp.Transform()); diff != "" {
					t.Errorf("User mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:     "US1-AS2: Login fails with incorrect password",
			scenario: "Given a user on the login page, When they enter an incorrect password, Then the system displays an error message",
			request: &pb.LoginRequest{
				Email:    "user@example.com",
				Password: "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "INVALID_CREDENTIALS",
		},
		{
			name:     "Edge case: Empty email",
			scenario: "Empty email field should return validation error",
			request: &pb.LoginRequest{
				Email:    "",
				Password: "somepassword",
			},
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "INVALID_EMAIL",
		},
		{
			name:     "Edge case: Empty password",
			scenario: "Empty password field should return validation error",
			request: &pb.LoginRequest{
				Email:    "user@example.com",
				Password: "",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "INVALID_CREDENTIALS",
		},
		{
			name:     "Edge case: User not found",
			scenario: "Non-existent email should return invalid credentials (security: don't reveal if email exists)",
			request: &pb.LoginRequest{
				Email:    "nonexistent@example.com",
				Password: "somepassword",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "INVALID_CREDENTIALS",
		},
		{
			name:     "Edge case: Inactive user cannot login",
			scenario: "Deactivated user should not be able to login",
			request: &pb.LoginRequest{
				Email:    "inactive@example.com",
				Password: "inactivepass",
			},
			expectedStatus: http.StatusForbidden,
			expectedCode:   "USER_INACTIVE",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := protojson.Marshal(tc.request)
			req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}

			if tc.expectedCode != "" {
				var errResp handlers.ErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
					t.Fatalf("Failed to parse error response: %v", err)
				}
				if errResp.Code != tc.expectedCode {
					t.Errorf("Expected error code %s, got %s", tc.expectedCode, errResp.Code)
				}
			}

			if tc.expectedStatus == http.StatusOK && tc.validateResp != nil {
				var resp pb.LoginResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse success response: %v", err)
				}
				tc.validateResp(t, &resp, tc.request)
			}
		})
	}
}

func TestAuthHandler_Logout(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	jwtSvc := services.NewJWTService("test-secret-key-32-bytes-long!!").Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	authSvc := services.NewAuthService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	tokenPair, err := jwtSvc.GenerateTokenPair(context.Background(), testUser.ID, testUser.Email, []string{"viewer"}, []string{"dashboard"})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = sessionSvc.CreateSession(context.Background(), testUser.ID, tokenPair.AccessToken, tokenPair.RefreshToken, jwtSvc.GetAccessTTL(), jwtSvc.GetRefreshTTL(), "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		Build()

	testCases := []struct {
		name           string
		scenario       string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "US1-AS3: Successful logout",
			scenario:       "Given an authenticated user, When they click Logout, Then their session is terminated",
			authHeader:     "Bearer " + tokenPair.AccessToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Edge case: Logout without auth header",
			scenario:       "Missing authorization header should return unauthorized",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Edge case: Logout with invalid token",
			scenario:       "Invalid token should return unauthorized",
			authHeader:     "Bearer invalid-token",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAuthHandler_UnauthenticatedAccess(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	jwtSvc := services.NewJWTService("test-secret-key-32-bytes-long!!").Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	authSvc := services.NewAuthService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		Build()

	t.Run("US1-AS4: Unauthenticated access to /me returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})
}

func TestAuthHandler_PasswordReset(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "oldpassword123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	jwtSvc := services.NewJWTService("test-secret-key-32-bytes-long!!").Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	authSvc := services.NewAuthService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		Build()

	// US6-AS1: Request password reset
	t.Run("US6-AS1: Request password reset sends email", func(t *testing.T) {
		reqBody := &pb.RequestPasswordResetRequest{
			Email: testUser.Email,
		}
		body, _ := protojson.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/password/reset/request", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		// Should return success even if email doesn't exist (security)
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, rec.Code, rec.Body.String())
		}
	})

	// US6-AS1: Request password reset for non-existent email (silent success)
	t.Run("US6-AS1: Request password reset for non-existent email returns success", func(t *testing.T) {
		reqBody := &pb.RequestPasswordResetRequest{
			Email: "nonexistent@example.com",
		}
		body, _ := protojson.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/password/reset/request", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		// Should return success to prevent email enumeration
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, rec.Code, rec.Body.String())
		}
	})
}

func TestAuthHandler_RefreshToken(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	jwtSvc := services.NewJWTService("test-secret-key-32-bytes-long!!").Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	authSvc := services.NewAuthService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	// Generate initial tokens
	tokenPair, err := jwtSvc.GenerateTokenPair(context.Background(), testUser.ID, testUser.Email, []string{"viewer"}, []string{"dashboard"})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Create session
	_, err = sessionSvc.CreateSession(context.Background(), testUser.ID, tokenPair.AccessToken, tokenPair.RefreshToken, jwtSvc.GetAccessTTL(), jwtSvc.GetRefreshTTL(), "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		Build()

	testCases := []struct {
		name           string
		scenario       string
		refreshToken   string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.RefreshTokenResponse)
	}{
		{
			name:           "US7-AS1: Refresh token returns new access token",
			scenario:       "Given a valid refresh token, When user refreshes, Then new access token is returned",
			refreshToken:   tokenPair.RefreshToken,
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.RefreshTokenResponse) {
				if resp.AccessToken == "" {
					t.Error("Expected new access token")
				}
			},
		},
		{
			name:           "US7-AS2: Invalid refresh token returns error",
			scenario:       "Given an invalid refresh token, When user refreshes, Then error is returned",
			refreshToken:   "invalid-refresh-token",
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "TOKEN_INVALID",
		},
		{
			name:           "Edge case: Empty refresh token",
			scenario:       "Empty refresh token should return error",
			refreshToken:   "",
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "TOKEN_INVALID",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := &pb.RefreshTokenRequest{
				RefreshToken: tc.refreshToken,
			}
			body, _ := protojson.Marshal(reqBody)
			req := httptest.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}

			if tc.expectedCode != "" {
				var errResp handlers.ErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
					t.Fatalf("Failed to parse error response: %v", err)
				}
				if errResp.Code != tc.expectedCode {
					t.Errorf("Expected error code %s, got %s", tc.expectedCode, errResp.Code)
				}
			}

			if tc.validateResp != nil && tc.expectedStatus == http.StatusOK {
				var resp pb.RefreshTokenResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestAuthHandler_OAuthGoogleStart(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	jwtSvc := services.NewJWTService("test-secret-key-32-bytes-long!!").Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	authSvc := services.NewAuthService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	oauthSvc := services.NewMockOAuthService(tdb.DB, jwtSvc, sessionSvc)

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		WithOAuthService(oauthSvc).
		Build()

	t.Run("US2-AS1: OAuth start returns authorization URL", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/oauth/google/start", nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, rec.Code, rec.Body.String())
		}

		var resp pb.OAuthStartResponse
		if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if resp.AuthorizationUrl == "" {
			t.Error("Expected authorization URL in response")
		}
		if resp.State == "" {
			t.Error("Expected state token in response")
		}
	})
}

func TestAuthHandler_OAuthGoogleCallback(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	// Create a pre-registered user (OAuth requires pre-registration)
	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	jwtSvc := services.NewJWTService("test-secret-key-32-bytes-long!!").Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	authSvc := services.NewAuthService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	oauthSvc := services.NewMockOAuthService(tdb.DB, jwtSvc, sessionSvc)
	oauthSvc.SetMockUser(testUser.Email, "google-123456")

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		WithOAuthService(oauthSvc).
		Build()

	// First get a valid state token
	startReq := httptest.NewRequest("GET", "/api/v1/oauth/google/start", nil)
	startRec := httptest.NewRecorder()
	mux.ServeHTTP(startRec, startReq)

	var startResp pb.OAuthStartResponse
	protojson.Unmarshal(startRec.Body.Bytes(), &startResp)
	validState := startResp.State

	testCases := []struct {
		name           string
		scenario       string
		code           string
		state          string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.OAuthCallbackResponse)
	}{
		{
			name:           "US2-AS1: Successful OAuth callback links Google account",
			scenario:       "Given a pre-registered user, When they complete Google OAuth, Then their account is linked",
			code:           "valid-auth-code",
			state:          validState,
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.OAuthCallbackResponse) {
				if resp.AccessToken == "" {
					t.Error("Expected access token in response")
				}
				if resp.User == nil {
					t.Fatal("Expected user in response")
				}
				if resp.User.Email != testUser.Email {
					t.Errorf("Expected email %s, got %s", testUser.Email, resp.User.Email)
				}
			},
		},
		{
			name:           "US2-AS3: OAuth cancelled returns error",
			scenario:       "Given a user cancels OAuth, When callback is received, Then error is returned",
			code:           "cancelled",
			state:          validState,
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "INVALID_CREDENTIALS",
		},
		{
			name:           "Edge case: Invalid state token",
			scenario:       "Invalid state token should return error",
			code:           "valid-auth-code",
			state:          "invalid-state",
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "OAUTH_STATE_MISMATCH",
		},
		{
			name:           "Edge case: Missing authorization code",
			scenario:       "Missing code should return error",
			code:           "",
			state:          validState,
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "INVALID_CREDENTIALS",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Need fresh state for each test that uses validState
			if tc.state == validState && tc.name != "US2-AS1: Successful OAuth callback links Google account" {
				startReq := httptest.NewRequest("GET", "/api/v1/oauth/google/start", nil)
				startRec := httptest.NewRecorder()
				mux.ServeHTTP(startRec, startReq)
				var resp pb.OAuthStartResponse
				protojson.Unmarshal(startRec.Body.Bytes(), &resp)
				tc.state = resp.State
			}

			url := "/api/v1/oauth/google/callback?code=" + tc.code + "&state=" + tc.state
			req := httptest.NewRequest("GET", url, nil)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}

			if tc.expectedCode != "" {
				var errResp handlers.ErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
					t.Fatalf("Failed to parse error response: %v", err)
				}
				if errResp.Code != tc.expectedCode {
					t.Errorf("Expected error code %s, got %s", tc.expectedCode, errResp.Code)
				}
			}

			if tc.validateResp != nil && tc.expectedStatus == http.StatusOK {
				var resp pb.OAuthCallbackResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestAuthHandler_OAuthEmailNotRegistered(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	// No pre-registered user - OAuth should fail

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	jwtSvc := services.NewJWTService("test-secret-key-32-bytes-long!!").Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	authSvc := services.NewAuthService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	oauthSvc := services.NewMockOAuthService(tdb.DB, jwtSvc, sessionSvc)
	oauthSvc.SetMockUser("nonexistent@example.com", "google-123456")

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		WithOAuthService(oauthSvc).
		Build()

	// Get valid state
	startReq := httptest.NewRequest("GET", "/api/v1/oauth/google/start", nil)
	startRec := httptest.NewRecorder()
	mux.ServeHTTP(startRec, startReq)

	var startResp pb.OAuthStartResponse
	protojson.Unmarshal(startRec.Body.Bytes(), &startResp)

	t.Run("US2-AS2: OAuth fails for non-registered email", func(t *testing.T) {
		url := "/api/v1/oauth/google/callback?code=valid-code&state=" + startResp.State
		req := httptest.NewRequest("GET", url, nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusForbidden, rec.Code, rec.Body.String())
		}

		var errResp handlers.ErrorResponse
		json.Unmarshal(rec.Body.Bytes(), &errResp)
		if errResp.Code != "OAUTH_EMAIL_NOT_FOUND" {
			t.Errorf("Expected error code OAUTH_EMAIL_NOT_FOUND, got %s", errResp.Code)
		}
	})
}

func TestAuthHandler_ValidateToken(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	jwtSvc := services.NewJWTService("test-secret-key-32-bytes-long!!").Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	authSvc := services.NewAuthService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	// Generate token
	tokenPair, err := jwtSvc.GenerateTokenPair(context.Background(), testUser.ID, testUser.Email, []string{"viewer"}, []string{"dashboard"})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		Build()

	testCases := []struct {
		name           string
		token          string
		expectedStatus int
		validateResp   func(t *testing.T, resp *pb.ValidateTokenResponse)
	}{
		{
			name:           "Valid token returns user info",
			token:          tokenPair.AccessToken,
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.ValidateTokenResponse) {
				if !resp.Valid {
					t.Error("Expected token to be valid")
				}
				if resp.User == nil {
					t.Fatal("Expected user in response")
				}
				if resp.User.Id != testUser.ID.String() {
					t.Errorf("Expected user ID %s, got %s", testUser.ID.String(), resp.User.Id)
				}
			},
		},
		{
			name:           "Invalid token returns invalid",
			token:          "invalid-token",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.ValidateTokenResponse) {
				if resp.Valid {
					t.Error("Expected token to be invalid")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := &pb.ValidateTokenRequest{
				Token: tc.token,
			}
			body, _ := protojson.Marshal(reqBody)
			req := httptest.NewRequest("POST", "/api/v1/auth/validate", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}

			if tc.validateResp != nil {
				var resp pb.ValidateTokenResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}
