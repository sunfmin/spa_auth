package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/user/spa_auth/api/gen/auth/v1"
	"github.com/user/spa_auth/handlers"
	"github.com/user/spa_auth/services"
	"github.com/user/spa_auth/testutil"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestRoleHandler_CreateRole(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	section1, err := testutil.CreateTestSpaSection(tdb.DB, "dashboard", "Dashboard")
	if err != nil {
		t.Fatalf("failed to create section: %v", err)
	}

	roleSvc := services.NewRoleService(tdb.DB).Build()

	mux := handlers.NewRouter().
		WithRoleService(roleSvc).
		Build()

	testCases := []struct {
		name           string
		scenario       string
		request        *pb.CreateRoleRequest
		userID         string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.CreateRoleResponse)
	}{
		{
			name:     "US4-AS1: Create role with name, description, and sections",
			scenario: "Given the super admin is logged in, When they create a new role with a name, description, and list of permitted SPA sections, Then the system creates the role",
			request: &pb.CreateRoleRequest{
				Name:        "editor",
				Description: "Can edit content",
				SectionIds:  []string{section1.ID.String()},
			},
			userID:         superAdmin.ID.String(),
			expectedStatus: http.StatusCreated,
			validateResp: func(t *testing.T, resp *pb.CreateRoleResponse) {
				if resp.Role == nil {
					t.Fatal("Expected role in response")
				}
				if resp.Role.Name != "editor" {
					t.Errorf("Expected name editor, got %s", resp.Role.Name)
				}
				if resp.Role.Description != "Can edit content" {
					t.Errorf("Expected description 'Can edit content', got %s", resp.Role.Description)
				}
				if len(resp.Role.Sections) != 1 {
					t.Errorf("Expected 1 section, got %d", len(resp.Role.Sections))
				}
			},
		},
		{
			name:     "Edge case: Create role with duplicate name",
			scenario: "Creating role with existing name should fail",
			request: &pb.CreateRoleRequest{
				Name:        "super_admin",
				Description: "Duplicate role",
			},
			userID:         superAdmin.ID.String(),
			expectedStatus: http.StatusConflict,
			expectedCode:   "ROLE_ALREADY_EXISTS",
		},
		{
			name:     "Edge case: Create role with empty name",
			scenario: "Empty role name should return validation error",
			request: &pb.CreateRoleRequest{
				Name:        "",
				Description: "No name role",
			},
			userID:         superAdmin.ID.String(),
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "INVALID_ROLE_NAME",
		},
		{
			name:     "Edge case: Create role without X-User-ID header",
			scenario: "Request without authentication should return unauthorized",
			request: &pb.CreateRoleRequest{
				Name:        "newrole",
				Description: "New role",
			},
			userID:         "",
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "UNAUTHORIZED",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := protojson.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
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
				var resp pb.CreateRoleResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestRoleHandler_ListRoles(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	_, err = testutil.CreateTestRoleWithCreator(tdb.DB, "editor", "Edit access", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create editor role: %v", err)
	}

	_, err = testutil.CreateTestRoleWithCreator(tdb.DB, "viewer", "View access", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create viewer role: %v", err)
	}

	roleSvc := services.NewRoleService(tdb.DB).Build()

	mux := handlers.NewRouter().
		WithRoleService(roleSvc).
		Build()

	testCases := []struct {
		name           string
		scenario       string
		queryParams    string
		expectedStatus int
		validateResp   func(t *testing.T, resp *pb.ListRolesResponse)
	}{
		{
			name:           "US4-AS2: List all roles excluding system roles",
			scenario:       "Given the super admin is logged in, When they view the list of roles, Then the system displays all roles",
			queryParams:    "",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.ListRolesResponse) {
				if len(resp.Roles) != 2 {
					t.Errorf("Expected 2 non-system roles, got %d", len(resp.Roles))
				}
			},
		},
		{
			name:           "List all roles including system roles",
			scenario:       "Include system roles in the list",
			queryParams:    "?include_system=true",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.ListRolesResponse) {
				if len(resp.Roles) < 3 {
					t.Errorf("Expected at least 3 roles (including super_admin), got %d", len(resp.Roles))
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/roles"+tc.queryParams, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}

			if tc.validateResp != nil {
				var resp pb.ListRolesResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestRoleHandler_GetRole(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	editorRole, err := testutil.CreateTestRoleWithCreator(tdb.DB, "editor", "Edit access", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create editor role: %v", err)
	}

	roleSvc := services.NewRoleService(tdb.DB).Build()

	mux := handlers.NewRouter().
		WithRoleService(roleSvc).
		Build()

	testCases := []struct {
		name           string
		roleID         string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.GetRoleResponse)
	}{
		{
			name:           "Get existing role by ID",
			roleID:         editorRole.ID.String(),
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.GetRoleResponse) {
				if resp.Role == nil {
					t.Fatal("Expected role in response")
				}
				if resp.Role.Name != "editor" {
					t.Errorf("Expected name editor, got %s", resp.Role.Name)
				}
			},
		},
		{
			name:           "Get non-existent role returns 404",
			roleID:         "00000000-0000-0000-0000-000000000000",
			expectedStatus: http.StatusNotFound,
			expectedCode:   "ROLE_NOT_FOUND",
		},
		{
			name:           "Get role with invalid UUID returns 400",
			roleID:         "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "INVALID_ID",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/"+tc.roleID, nil)
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
				var resp pb.GetRoleResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestRoleHandler_UpdateRole(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, superAdminRole, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	editorRole, err := testutil.CreateTestRoleWithCreator(tdb.DB, "editor", "Edit access", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create editor role: %v", err)
	}

	section1, err := testutil.CreateTestSpaSection(tdb.DB, "dashboard", "Dashboard")
	if err != nil {
		t.Fatalf("failed to create section: %v", err)
	}

	section2, err := testutil.CreateTestSpaSection(tdb.DB, "settings", "Settings")
	if err != nil {
		t.Fatalf("failed to create section: %v", err)
	}

	roleSvc := services.NewRoleService(tdb.DB).Build()

	mux := handlers.NewRouter().
		WithRoleService(roleSvc).
		Build()

	newName := "senior_editor"
	newDesc := "Senior editor with more permissions"
	testCases := []struct {
		name           string
		roleID         string
		request        *pb.UpdateRoleRequest
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.UpdateRoleResponse)
	}{
		{
			name:   "US4-AS3: Update role permissions",
			roleID: editorRole.ID.String(),
			request: &pb.UpdateRoleRequest{
				Id:         editorRole.ID.String(),
				SectionIds: []string{section1.ID.String(), section2.ID.String()},
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.UpdateRoleResponse) {
				if resp.Role == nil {
					t.Fatal("Expected role in response")
				}
				if len(resp.Role.Sections) != 2 {
					t.Errorf("Expected 2 sections, got %d", len(resp.Role.Sections))
				}
			},
		},
		{
			name:   "Update role name and description",
			roleID: editorRole.ID.String(),
			request: &pb.UpdateRoleRequest{
				Id:          editorRole.ID.String(),
				Name:        &newName,
				Description: &newDesc,
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.UpdateRoleResponse) {
				if resp.Role.Name != "senior_editor" {
					t.Errorf("Expected name senior_editor, got %s", resp.Role.Name)
				}
			},
		},
		{
			name:   "Edge case: Cannot modify system role",
			roleID: superAdminRole.ID.String(),
			request: &pb.UpdateRoleRequest{
				Id:          superAdminRole.ID.String(),
				Description: &newDesc,
			},
			expectedStatus: http.StatusForbidden,
			expectedCode:   "ROLE_IS_SYSTEM",
		},
		{
			name:   "Update non-existent role returns 404",
			roleID: "00000000-0000-0000-0000-000000000000",
			request: &pb.UpdateRoleRequest{
				Id:   "00000000-0000-0000-0000-000000000000",
				Name: &newName,
			},
			expectedStatus: http.StatusNotFound,
			expectedCode:   "ROLE_NOT_FOUND",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := protojson.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPatch, "/api/v1/roles/"+tc.roleID, bytes.NewReader(body))
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
				var resp pb.UpdateRoleResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestRoleHandler_DeleteRole(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, superAdminRole, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	editorRole, err := testutil.CreateTestRoleWithCreator(tdb.DB, "editor", "Edit access", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create editor role: %v", err)
	}

	roleWithUsers, err := testutil.CreateTestRoleWithCreator(tdb.DB, "viewer", "View access", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create viewer role: %v", err)
	}

	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	_, err = testutil.CreateTestUserRole(tdb.DB, testUser.ID, roleWithUsers.ID)
	if err != nil {
		t.Fatalf("failed to assign role to user: %v", err)
	}

	roleSvc := services.NewRoleService(tdb.DB).Build()

	mux := handlers.NewRouter().
		WithRoleService(roleSvc).
		Build()

	testCases := []struct {
		name           string
		roleID         string
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.DeleteRoleResponse)
	}{
		{
			name:           "US4-AS4: Delete role without users",
			roleID:         editorRole.ID.String(),
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.DeleteRoleResponse) {
				if !resp.Success {
					t.Error("Expected success to be true")
				}
			},
		},
		{
			name:           "US4-AS5: Cannot delete role with assigned users",
			roleID:         roleWithUsers.ID.String(),
			expectedStatus: http.StatusConflict,
			expectedCode:   "ROLE_HAS_USERS",
		},
		{
			name:           "Edge case: Cannot delete system role",
			roleID:         superAdminRole.ID.String(),
			expectedStatus: http.StatusForbidden,
			expectedCode:   "ROLE_IS_SYSTEM",
		},
		{
			name:           "Delete non-existent role returns 404",
			roleID:         "00000000-0000-0000-0000-000000000000",
			expectedStatus: http.StatusNotFound,
			expectedCode:   "ROLE_NOT_FOUND",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/"+tc.roleID, nil)
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
				var resp pb.DeleteRoleResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestRoleHandler_CreateSpaSection(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	roleSvc := services.NewRoleService(tdb.DB).Build()

	mux := handlers.NewRouter().
		WithRoleService(roleSvc).
		Build()

	testCases := []struct {
		name           string
		request        *pb.CreateSpaSectionRequest
		expectedStatus int
		expectedCode   string
		validateResp   func(t *testing.T, resp *pb.CreateSpaSectionResponse)
	}{
		{
			name: "Create SPA section",
			request: &pb.CreateSpaSectionRequest{
				Key:         "dashboard",
				DisplayName: "Dashboard",
				Description: "Main dashboard section",
			},
			expectedStatus: http.StatusCreated,
			validateResp: func(t *testing.T, resp *pb.CreateSpaSectionResponse) {
				if resp.Section == nil {
					t.Fatal("Expected section in response")
				}
				if resp.Section.Key != "dashboard" {
					t.Errorf("Expected key dashboard, got %s", resp.Section.Key)
				}
			},
		},
		{
			name: "Edge case: Create section with empty key",
			request: &pb.CreateSpaSectionRequest{
				Key:         "",
				DisplayName: "No Key",
			},
			expectedStatus: http.StatusNotFound,
			expectedCode:   "SECTION_NOT_FOUND",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := protojson.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/spa-sections", bytes.NewReader(body))
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
				var resp pb.CreateSpaSectionResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestRoleHandler_ListSpaSections(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	_, err := testutil.CreateTestSpaSection(tdb.DB, "dashboard", "Dashboard")
	if err != nil {
		t.Fatalf("failed to create section: %v", err)
	}

	_, err = testutil.CreateTestSpaSection(tdb.DB, "settings", "Settings")
	if err != nil {
		t.Fatalf("failed to create section: %v", err)
	}

	roleSvc := services.NewRoleService(tdb.DB).Build()

	mux := handlers.NewRouter().
		WithRoleService(roleSvc).
		Build()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spa-sections", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp pb.ListSpaSectionsResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(resp.Sections) != 2 {
		t.Errorf("Expected 2 sections, got %d", len(resp.Sections))
	}
}

func TestRoleHandler_CheckSectionAccess(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	// Create sections
	dashboardSection, err := testutil.CreateTestSpaSection(tdb.DB, "dashboard", "Dashboard")
	if err != nil {
		t.Fatalf("failed to create dashboard section: %v", err)
	}

	settingsSection, err := testutil.CreateTestSpaSection(tdb.DB, "settings", "Settings")
	if err != nil {
		t.Fatalf("failed to create settings section: %v", err)
	}

	// Create viewer role with only dashboard access
	viewerRole, err := testutil.CreateTestRoleWithCreator(tdb.DB, "viewer", "View only", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create viewer role: %v", err)
	}

	// Assign dashboard permission to viewer role
	_, err = testutil.CreateTestRolePermission(tdb.DB, viewerRole.ID, dashboardSection.ID)
	if err != nil {
		t.Fatalf("failed to create role permission: %v", err)
	}

	// Create test user with viewer role
	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	_, err = testutil.CreateTestUserRole(tdb.DB, testUser.ID, viewerRole.ID)
	if err != nil {
		t.Fatalf("failed to assign role to user: %v", err)
	}

	roleSvc := services.NewRoleService(tdb.DB).Build()

	mux := handlers.NewRouter().
		WithRoleService(roleSvc).
		Build()

	testCases := []struct {
		name           string
		scenario       string
		request        *pb.CheckSectionAccessRequest
		expectedStatus int
		validateResp   func(t *testing.T, resp *pb.CheckSectionAccessResponse)
	}{
		{
			name:     "US5-AS1: Access denied for restricted section",
			scenario: "Given a user with viewer role (dashboard only), When they access settings, Then access is denied",
			request: &pb.CheckSectionAccessRequest{
				UserId:     testUser.ID.String(),
				SectionKey: "settings",
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.CheckSectionAccessResponse) {
				if resp.Allowed {
					t.Error("Expected access to be denied for settings section")
				}
			},
		},
		{
			name:     "User can access permitted section",
			scenario: "Given a user with viewer role (dashboard only), When they access dashboard, Then access is granted",
			request: &pb.CheckSectionAccessRequest{
				UserId:     testUser.ID.String(),
				SectionKey: "dashboard",
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.CheckSectionAccessResponse) {
				if !resp.Allowed {
					t.Error("Expected access to be granted for dashboard section")
				}
			},
		},
		{
			name:     "US5-AS2: Super admin can access all sections",
			scenario: "Given a user with super_admin role, When they access any section, Then access is granted",
			request: &pb.CheckSectionAccessRequest{
				UserId:     superAdmin.ID.String(),
				SectionKey: "settings",
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.CheckSectionAccessResponse) {
				if !resp.Allowed {
					t.Error("Expected super_admin to have access to all sections")
				}
			},
		},
		{
			name:     "Edge case: Invalid section key",
			scenario: "Non-existent section key should deny access",
			request: &pb.CheckSectionAccessRequest{
				UserId:     testUser.ID.String(),
				SectionKey: "nonexistent",
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *pb.CheckSectionAccessResponse) {
				if resp.Allowed {
					t.Error("Expected access to be denied for non-existent section")
				}
			},
		},
	}

	_ = settingsSection

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := protojson.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/permissions/check-section", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}

			if tc.validateResp != nil {
				var resp pb.CheckSectionAccessResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				tc.validateResp(t, &resp)
			}
		})
	}
}

func TestRoleHandler_CheckSectionAccess_PermissionChangesImmediate(t *testing.T) {
	tdb := testutil.SetupTestDB(t)
	defer tdb.Close(t)
	defer testutil.TruncateAllTables(tdb.DB)

	superAdmin, _, err := testutil.CreateSuperAdmin(tdb.DB, "admin@example.com", "password123")
	if err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}

	// Create sections
	dashboardSection, err := testutil.CreateTestSpaSection(tdb.DB, "dashboard", "Dashboard")
	if err != nil {
		t.Fatalf("failed to create dashboard section: %v", err)
	}

	settingsSection, err := testutil.CreateTestSpaSection(tdb.DB, "settings", "Settings")
	if err != nil {
		t.Fatalf("failed to create settings section: %v", err)
	}

	// Create editor role with dashboard access only
	editorRole, err := testutil.CreateTestRoleWithCreator(tdb.DB, "editor", "Edit access", false, superAdmin.ID)
	if err != nil {
		t.Fatalf("failed to create editor role: %v", err)
	}

	_, err = testutil.CreateTestRolePermission(tdb.DB, editorRole.ID, dashboardSection.ID)
	if err != nil {
		t.Fatalf("failed to create role permission: %v", err)
	}

	// Create test user with editor role
	testUser, err := testutil.CreateTestUser(tdb.DB, "user@example.com", "userpass123", true)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	_, err = testutil.CreateTestUserRole(tdb.DB, testUser.ID, editorRole.ID)
	if err != nil {
		t.Fatalf("failed to assign role to user: %v", err)
	}

	roleSvc := services.NewRoleService(tdb.DB).Build()

	mux := handlers.NewRouter().
		WithRoleService(roleSvc).
		Build()

	// US5-AS3: Verify user cannot access settings initially
	checkReq := &pb.CheckSectionAccessRequest{
		UserId:     testUser.ID.String(),
		SectionKey: "settings",
	}
	body, _ := protojson.Marshal(checkReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/permissions/check-section", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp pb.CheckSectionAccessResponse
	protojson.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Error("Expected settings access to be denied initially")
	}

	// Add settings permission to editor role
	_, err = testutil.CreateTestRolePermission(tdb.DB, editorRole.ID, settingsSection.ID)
	if err != nil {
		t.Fatalf("failed to add settings permission: %v", err)
	}

	// US5-AS3: Verify permission change takes effect immediately
	body, _ = protojson.Marshal(checkReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/permissions/check-section", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	protojson.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Allowed {
		t.Error("US5-AS3: Expected settings access to be granted after permission change")
	}
}

// Suppress unused import warning
var _ = context.Background
