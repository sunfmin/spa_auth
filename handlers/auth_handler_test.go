package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/user/spa_auth/handlers"
	"github.com/user/spa_auth/services"
	"github.com/user/spa_auth/testutil"
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
	authSvc := services.NewAuthService(tdb.DB).WithPasswordService(passwordSvc).Build()

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		WithPasswordService(passwordSvc).
		Build()

	testCases := []struct {
		name           string
		scenario       string
		requestBody    map[string]string
		expectedStatus int
		expectedCode   string
	}{
		{
			name:     "US1-AS1: Successful login with valid credentials",
			scenario: "Given a user account created by the super admin, When the user enters their correct email and password, Then the system authenticates them",
			requestBody: map[string]string{
				"email":    "user@example.com",
				"password": "userpass123",
			},
			expectedStatus: http.StatusOK,
			expectedCode:   "",
		},
		{
			name:     "US1-AS2: Login fails with incorrect password",
			scenario: "Given a user on the login page, When they enter an incorrect password, Then the system displays an error message",
			requestBody: map[string]string{
				"email":    "user@example.com",
				"password": "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "INVALID_CREDENTIALS",
		},
		{
			name:     "Edge case: Empty email",
			scenario: "Empty email field should return validation error",
			requestBody: map[string]string{
				"email":    "",
				"password": "somepassword",
			},
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "INVALID_EMAIL",
		},
		{
			name:     "Edge case: Empty password",
			scenario: "Empty password field should return validation error",
			requestBody: map[string]string{
				"email":    "user@example.com",
				"password": "",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "INVALID_CREDENTIALS",
		},
		{
			name:     "Edge case: User not found",
			scenario: "Non-existent email should return invalid credentials (security: don't reveal if email exists)",
			requestBody: map[string]string{
				"email":    "nonexistent@example.com",
				"password": "somepassword",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "INVALID_CREDENTIALS",
		},
		{
			name:     "Edge case: Inactive user cannot login",
			scenario: "Deactivated user should not be able to login",
			requestBody: map[string]string{
				"email":    "inactive@example.com",
				"password": "inactivepass",
			},
			expectedStatus: http.StatusForbidden,
			expectedCode:   "USER_INACTIVE",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}

			if tc.expectedCode != "" {
				var resp handlers.ErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse error response: %v", err)
				}
				if resp.Code != tc.expectedCode {
					t.Errorf("Expected error code %s, got %s", tc.expectedCode, resp.Code)
				}
			}

			if tc.expectedStatus == http.StatusOK {
				var resp map[string]interface{}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse success response: %v", err)
				}
				if resp["accessToken"] == nil {
					t.Error("Expected accessToken in response")
				}
				if resp["user"] == nil {
					t.Error("Expected user in response")
				}
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
	authSvc := services.NewAuthService(tdb.DB).WithPasswordService(passwordSvc).Build()

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
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		WithPasswordService(passwordSvc).
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
	authSvc := services.NewAuthService(tdb.DB).WithPasswordService(passwordSvc).Build()

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		WithPasswordService(passwordSvc).
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
