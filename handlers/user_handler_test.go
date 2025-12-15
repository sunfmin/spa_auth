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

func TestUserHandler_CreateUser(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	_, err = testutil.CreateTestRoleWithCreator(tdb.DB, "viewer", "View only access", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create viewer role: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	userSvc := services.NewUserService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithUserService(userSvc).
		Build()

	testCases := []struct {
		name           string
		scenario       string
		request        *pb.CreateUserRequest
		userID         string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.CreateUserResponse, req *pb.CreateUserRequest)
	}{
		{
			name:     "US3-AS1: Super admin creates new user with email, password, and role",
			scenario: "Given the super admin is logged in, When they create a new user with email, password, and role, Then the system creates the user account",
			request: &pb.CreateUserRequest{
				Email:    "newuser@example.com",
				Password: "newuserpass123",
				Roles:    []string{"viewer"},
			},
			userID:         superAdmin.ID.String(),
			expectedStatus: http.StatusCreated,
			validateResp: func(t *testing.T, resp *pb.CreateUserResponse, req *pb.CreateUserRequest) {
				if resp.User == nil {
					t.Fatal("Expected user in response")
				}
				// Use cmp.Diff with protocmp.Transform() per constitution
				expected := &pb.User{
					Id:          resp.User.Id,          // Random UUID from response
					Email:       req.Email,             // From request fixture
					IsActive:    true,                  // Default for new user
					HasPassword: true,                  // User has password
					Roles:       req.Roles,             // From request fixture
					Sections:    resp.User.Sections,    // Dynamic from DB
					CreatedAt:   resp.User.CreatedAt,   // Timestamp from response
					CreatedBy:   resp.User.CreatedBy,   // UUID of creator from response
				}
				if diff := cmp.Diff(expected, resp.User, protocmp.Transform()); diff != "" {
					t.Errorf("User mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:     "Edge case: Create user with duplicate email",
			scenario: "Admin creating user with already-registered email displays appropriate error",
			request: &pb.CreateUserRequest{
				Email:    "admin@example.com",
				Password: "somepassword123",
				Roles:    []string{"viewer"},
			},
			userID:         superAdmin.ID.String(),
			expectedStatus: http.StatusConflict,
			expectedCode:   "USER_ALREADY_EXISTS",
		},
		{
			name:     "Edge case: Create user with empty email",
			scenario: "Empty email field should return validation error",
			request: &pb.CreateUserRequest{
				Email:    "",
				Password: "somepassword123",
				Roles:    []string{"viewer"},
			},
			userID:         superAdmin.ID.String(),
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "INVALID_EMAIL",
		},
		{
			name:     "Edge case: Create user with empty password",
			scenario: "Empty password field should return validation error",
			request: &pb.CreateUserRequest{
				Email:    "anotheruser@example.com",
				Password: "",
				Roles:    []string{"viewer"},
			},
			userID:         superAdmin.ID.String(),
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "PASSWORD_TOO_SHORT",
		},
		{
			name:     "Edge case: Create user without X-User-ID header",
			scenario: "Request without authentication should return unauthorized",
			request: &pb.CreateUserRequest{
				Email:    "noauth@example.com",
				Password: "somepassword123",
				Roles:    []string{"viewer"},
			},
			userID:         "",
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "UNAUTHORIZED",
		},
		{
			name:     "Edge case: Create user with non-existent role",
			scenario: "Non-existent role name should return error",
			request: &pb.CreateUserRequest{
				Email:    "invalidrole@example.com",
				Password: "somepassword123",
				Roles:    []string{"nonexistent_role"},
			},
			userID:         superAdmin.ID.String(),
			expectedStatus: http.StatusNotFound,
			expectedCode:   "ROLE_NOT_FOUND",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := protojson.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tc.userID != "" {
				req.Header.Set("X-User-ID", tc.userID)
			}

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

			if tc.validateResp != nil {
				var resp pb.CreateUserResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp, tc.request)
			}
		})
	}
}

func TestUserHandler_GetUser(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	userSvc := services.NewUserService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithUserService(userSvc).
		Build()

	testCases := []struct {
		name           string
		userID         string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.GetUserResponse)
	}{
		{
			name:           "Get existing user by ID",
			userID:         testUser.ID.String(),
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.GetUserResponse) {
				if resp.User == nil {
					t.Fatal("Expected user in response")
				}
				if resp.User.Email != "user@example.com" {
					t.Errorf("Expected email user@example.com, got %s", resp.User.Email)
				}
			},
		},
		{
			name:           "Get non-existent user returns 404",
			userID:         "00000000-0000-0000-0000-000000000000",
			expectedStatus: http.StatusNotFound,
			expectedCode:   "USER_NOT_FOUND",
		},
		{
			name:           "Get user with invalid UUID returns 400",
			userID:         "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "INVALID_ID",
		},
	}

	_ = superAdmin

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+tc.userID, nil)
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

			if tc.validateResp != nil {
				var resp pb.GetUserResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestUserHandler_ListUsers(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	_, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	_, err = testutil.CreateTestUser(tdb.DB, "user1@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user 1: %v", err)
	}

	_, err = testutil.CreateTestUser(tdb.DB, "user2@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user 2: %v", err)
	}

	_, err = testutil.CreateTestUser(tdb.DB, "inactive@example.com", "userpass123", false)
	if err != nil {
		t.Fatalf("failed to create inactive user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	userSvc := services.NewUserService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithUserService(userSvc).
		Build()

	testCases := []struct {
		name           string
		queryParams    string
		expectedStatus int
		validateResp   func(t *testing.T, resp *pb.ListUsersResponse)
	}{
		{
			name:           "List all active users",
			queryParams:    "",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.ListUsersResponse) {
				if len(resp.Users) != 3 {
					t.Errorf("Expected 3 active users, got %d", len(resp.Users))
				}
			},
		},
		{
			name:           "List users including inactive",
			queryParams:    "?include_inactive=true",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.ListUsersResponse) {
				if len(resp.Users) != 4 {
					t.Errorf("Expected 4 users (including inactive), got %d", len(resp.Users))
				}
			},
		},
		{
			name:           "List users with pagination",
			queryParams:    "?page_size=2",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.ListUsersResponse) {
				if len(resp.Users) != 2 {
					t.Errorf("Expected 2 users with page_size=2, got %d", len(resp.Users))
				}
				if resp.NextPageToken == "" {
					t.Error("Expected next_page_token for pagination")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/users"+tc.queryParams, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}

			if tc.validateResp != nil {
				var resp pb.ListUsersResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestUserHandler_UpdateUser(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	_, err = testutil.CreateTestRoleWithCreator(tdb.DB, "editor", "Edit access", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create editor role: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	userSvc := services.NewUserService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithUserService(userSvc).
		Build()

	_ = superAdmin

	newEmail := "updated@example.com"
	testCases := []struct {
		name           string
		userID         string
		request        *pb.UpdateUserRequest
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.UpdateUserResponse)
	}{
		{
			name:   "US3-AS2: Modify user role",
			userID: testUser.ID.String(),
			request: &pb.UpdateUserRequest{
				Id:    testUser.ID.String(),
				Roles: []string{"editor"},
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.UpdateUserResponse) {
				if resp.User == nil {
					t.Fatal("Expected user in response")
				}
				if len(resp.User.Roles) != 1 {
					t.Errorf("Expected 1 role, got %d", len(resp.User.Roles))
				}
				if resp.User.Roles[0] != "editor" {
					t.Errorf("Expected role editor, got %s", resp.User.Roles[0])
				}
			},
		},
		{
			name:   "Update user email",
			userID: testUser.ID.String(),
			request: &pb.UpdateUserRequest{
				Id:    testUser.ID.String(),
				Email: &newEmail,
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.UpdateUserResponse) {
				if resp.User.Email != "updated@example.com" {
					t.Errorf("Expected email updated@example.com, got %s", resp.User.Email)
				}
			},
		},
		{
			name:   "Update non-existent user returns 404",
			userID: "00000000-0000-0000-0000-000000000000",
			request: &pb.UpdateUserRequest{
				Id:    "00000000-0000-0000-0000-000000000000",
				Email: &newEmail,
			},
			expectedStatus: http.StatusNotFound,
			expectedCode:   "USER_NOT_FOUND",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := protojson.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/"+tc.userID, bytes.NewReader(body))
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

			if tc.validateResp != nil {
				var resp pb.UpdateUserResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestUserHandler_DeactivateUser(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	userSvc := services.NewUserService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithUserService(userSvc).
		Build()

	_ = superAdmin

	testCases := []struct {
		name           string
		userID         string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.DeactivateUserResponse)
	}{
		{
			name:           "US3-AS3: Deactivate user account",
			userID:         testUser.ID.String(),
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.DeactivateUserResponse) {
				if !resp.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name:           "Deactivate non-existent user returns 404",
			userID:         "00000000-0000-0000-0000-000000000000",
			expectedStatus: http.StatusNotFound,
			expectedCode:   "USER_NOT_FOUND",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+tc.userID+"/deactivate", nil)
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

			if tc.validateResp != nil {
				var resp pb.DeactivateUserResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestUserHandler_ReactivateUser(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	inactiveUser, err := testutil.CreateTestUser(tdb.DB, "inactive@example.com", "userpass123", false)
	if err != nil {
		t.Fatalf("failed to create inactive user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	userSvc := services.NewUserService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithUserService(userSvc).
		Build()

	_ = superAdmin

	testCases := []struct {
		name           string
		userID         string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.ReactivateUserResponse)
	}{
		{
			name:           "Reactivate inactive user",
			userID:         inactiveUser.ID.String(),
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.ReactivateUserResponse) {
				if !resp.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name:           "Reactivate non-existent user returns 404",
			userID:         "00000000-0000-0000-0000-000000000000",
			expectedStatus: http.StatusNotFound,
			expectedCode:   "USER_NOT_FOUND",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+tc.userID+"/reactivate", nil)
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

			if tc.validateResp != nil {
				var resp pb.ReactivateUserResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestUserHandler_AdminResetPassword(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

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
	userSvc := services.NewUserService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		WithUserService(userSvc).
		Build()

	_ = superAdmin

	testCases := []struct {
		name           string
		userID         string
		request        *pb.AdminResetPasswordRequest
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.AdminResetPasswordResponse)
	}{
		{
			name:   "US3-AS4: Admin resets user password",
			userID: testUser.ID.String(),
			request: &pb.AdminResetPasswordRequest{
				UserId:      testUser.ID.String(),
				NewPassword: "newpassword456",
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.AdminResetPasswordResponse) {
				if !resp.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name:   "Reset password for non-existent user returns 404",
			userID: "00000000-0000-0000-0000-000000000000",
			request: &pb.AdminResetPasswordRequest{
				UserId:      "00000000-0000-0000-0000-000000000000",
				NewPassword: "newpassword456",
			},
			expectedStatus: http.StatusNotFound,
			expectedCode:   "USER_NOT_FOUND",
		},
		{
			name:   "Reset password with empty password returns error",
			userID: testUser.ID.String(),
			request: &pb.AdminResetPasswordRequest{
				UserId:      testUser.ID.String(),
				NewPassword: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "PASSWORD_TOO_SHORT",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := protojson.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+tc.userID+"/password", bytes.NewReader(body))
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

			if tc.validateResp != nil {
				var resp pb.AdminResetPasswordResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestUserHandler_AdminResetPassword_CanLoginWithNewPassword(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	_, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

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
	userSvc := services.NewUserService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		WithUserService(userSvc).
		Build()

	resetReq := &pb.AdminResetPasswordRequest{
		UserId:      testUser.ID.String(),
		NewPassword: "newpassword456",
	}
	body, _ := protojson.Marshal(resetReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+testUser.ID.String()+"/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Failed to reset password: %s", rec.Body.String())
	}

	loginReq := &pb.LoginRequest{
		Email:    "user@example.com",
		Password: "newpassword456",
	}
	body, _ = protojson.Marshal(loginReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected login with new password to succeed, got status %d: %s", rec.Code, rec.Body.String())
	}

	loginReq = &pb.LoginRequest{
		Email:    "user@example.com",
		Password: "oldpassword123",
	}
	body, _ = protojson.Marshal(loginReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected login with old password to fail, got status %d", rec.Code)
	}
}

func TestUserHandler_DeleteUser(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	passwordSvc := services.NewPasswordService(tdb.DB).Build()
	sessionSvc := services.NewSessionService(tdb.DB).Build()
	userSvc := services.NewUserService(tdb.DB).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	mux := handlers.NewRouter().
		WithUserService(userSvc).
		Build()

	_ = superAdmin

	testCases := []struct {
		name           string
		userID         string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.DeleteUserResponse)
	}{
		{
			name:           "Delete existing user",
			userID:         testUser.ID.String(),
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.DeleteUserResponse) {
				if !resp.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name:           "Delete non-existent user returns 404",
			userID:         "00000000-0000-0000-0000-000000000000",
			expectedStatus: http.StatusNotFound,
			expectedCode:   "USER_NOT_FOUND",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+tc.userID, nil)
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

			if tc.validateResp != nil {
				var resp pb.DeleteUserResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

// Suppress unused import warning
var _ = context.Background
