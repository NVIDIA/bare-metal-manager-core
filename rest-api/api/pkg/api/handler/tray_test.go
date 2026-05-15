// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/pagination"
	sc "github.com/NVIDIA/infra-controller-rest/api/pkg/client/site"
	authz "github.com/NVIDIA/infra-controller-rest/auth/pkg/authorization"
	"github.com/NVIDIA/infra-controller-rest/common/pkg/otelecho"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbu "github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/extra/bundebug"
	oteltrace "go.opentelemetry.io/otel/trace"
	tmocks "go.temporal.io/sdk/mocks"
)

func testTrayInitDB(t *testing.T) *cdb.Session {
	dbSession := cdbu.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("BUNDEBUG"),
	))

	ctx := context.Background()

	// Reset required tables in dependency order
	err := dbSession.DB.ResetModel(ctx, (*cdbm.User)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.InfrastructureProvider)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.Tenant)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.Site)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.TenantSite)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.TenantAccount)(nil))
	assert.Nil(t, err)

	return dbSession
}

func testTraySetupTestData(t *testing.T, dbSession *cdb.Session, org string) (*cdbm.InfrastructureProvider, *cdbm.Site, *cdbm.Tenant) {
	ctx := context.Background()

	// Create infrastructure provider
	ip := &cdbm.InfrastructureProvider{
		ID:   uuid.New(),
		Name: "test-provider",
		Org:  org,
	}
	_, err := dbSession.DB.NewInsert().Model(ip).Exec(ctx)
	assert.Nil(t, err)

	// Create site with Flow enabled
	site := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site",
		Org:                      org,
		InfrastructureProviderID: ip.ID,
		Status:                   cdbm.SiteStatusRegistered,
		Config:                   &cdbm.SiteConfig{Flow: true},
	}
	_, err = dbSession.DB.NewInsert().Model(site).Exec(ctx)
	assert.Nil(t, err)

	// Create tenant with TargetedInstanceCreation enabled (privileged tenant)
	tenant := &cdbm.Tenant{
		ID:  uuid.New(),
		Org: org,
		Config: &cdbm.TenantConfig{
			TargetedInstanceCreation: true,
		},
		CreatedBy: uuid.New(),
	}
	_, err = dbSession.DB.NewInsert().Model(tenant).Exec(ctx)
	assert.Nil(t, err)

	// Create tenant account for privileged tenant
	ta := &cdbm.TenantAccount{
		ID:                       uuid.New(),
		TenantID:                 &tenant.ID,
		InfrastructureProviderID: ip.ID,
	}
	_, err = dbSession.DB.NewInsert().Model(ta).Exec(ctx)
	assert.Nil(t, err)

	return ip, site, tenant
}

func testTrayBuildUser(t *testing.T, dbSession *cdb.Session, starfleetID string, org string, roles []string) *cdbm.User {
	uDAO := cdbm.NewUserDAO(dbSession)

	OrgData := cdbm.OrgData{}
	OrgData[org] = cdbm.Org{
		ID:          123,
		Name:        org,
		DisplayName: org,
		OrgType:     "ENTERPRISE",
		Roles:       roles,
	}
	u, err := uDAO.Create(
		context.Background(),
		nil,
		cdbm.UserCreateInput{
			AuxiliaryID: nil,
			StarfleetID: &starfleetID,
			Email:       cdb.GetStrPtr("test@test.com"),
			FirstName:   cdb.GetStrPtr("Test"),
			LastName:    cdb.GetStrPtr("User"),
			OrgData:     OrgData,
		},
	)
	assert.Nil(t, err)

	return u
}

// createMockComponent creates a mock Flow Component for testing
func createMockComponent(id, name, manufacturer, modelStr, componentID string, compType flowv1.ComponentType, rackID string) *flowv1.Component {
	comp := &flowv1.Component{
		Type:        compType,
		ComponentId: componentID,
		Info: &flowv1.DeviceInfo{
			Id:           &flowv1.UUID{Id: id},
			Name:         name,
			Manufacturer: manufacturer,
			Model:        &modelStr,
		},
	}
	if rackID != "" {
		comp.RackId = &flowv1.UUID{Id: rackID}
	}
	return comp
}

func TestGetTrayHandler_Handle(t *testing.T) {
	// Setup
	e := echo.New()
	dbSession := testTrayInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testTraySetupTestData(t, dbSession, org)

	// Create a site without Flow enabled
	siteNoRLA := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site-no-flow",
		Org:                      org,
		InfrastructureProviderID: site.InfrastructureProviderID,
		Status:                   cdbm.SiteStatusRegistered,
		Config:                   &cdbm.SiteConfig{},
	}
	_, err := dbSession.DB.NewInsert().Model(siteNoRLA).Exec(context.Background())
	assert.Nil(t, err)

	// Create provider user
	providerUser := testTrayBuildUser(t, dbSession, "provider-user-tray-get", org, []string{authz.ProviderAdminRole})

	// Create tenant user (no provider role, no site access)
	tenantUser := testTrayBuildUser(t, dbSession, "tenant-user-tray-get", org, []string{authz.TenantAdminRole})

	handler := NewGetTrayHandler(dbSession, nil, scp, cfg)

	trayID := uuid.New().String()

	// Create mock component for success cases
	mockComponent := createMockComponent(
		trayID, "compute-tray-1", "NVIDIA", "GB200", "nico-machine-001",
		flowv1.ComponentType_COMPONENT_TYPE_COMPUTE, "rack-id-1",
	)

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		trayID         string
		queryParams    map[string]string
		mockComponent  *flowv1.Component
		expectedStatus int
		wantErr        bool
	}{
		{
			name:   "success - get tray by ID",
			reqOrg: org,
			user:   providerUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			mockComponent:  mockComponent,
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
		{
			name:   "failure - Flow not enabled on site",
			reqOrg: org,
			user:   providerUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": siteNoRLA.ID.String(),
			},
			expectedStatus: http.StatusPreconditionFailed,
			wantErr:        true,
		},
		{
			name:        "failure - missing siteId",
			reqOrg:      org,
			user:        providerUser,
			trayID:      trayID,
			queryParams: map[string]string{
				// no siteId
			},
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name:   "failure - invalid siteId",
			reqOrg: org,
			user:   providerUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": uuid.New().String(), // non-existent site
			},
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name:   "failure - tray not found (nil component)",
			reqOrg: org,
			user:   providerUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			mockComponent:  nil,
			expectedStatus: http.StatusNotFound,
			wantErr:        true,
		},
		{
			name:   "failure - tenant access denied (no site access)",
			reqOrg: org,
			user:   tenantUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			expectedStatus: http.StatusForbidden,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock Temporal client
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			if tt.mockComponent != nil {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.GetComponentInfoResponse)
					resp.Component = tt.mockComponent
				}).Return(nil)
			} else {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.GetComponentInfoResponse)
					resp.Component = nil
				}).Return(nil)
			}
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "GetTray", mock.Anything).Return(mockWorkflowRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			// Build query string
			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			path := fmt.Sprintf("/v2/org/%s/nico/tray/%s?%s", tt.reqOrg, tt.trayID, q.Encode())

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tt.reqOrg, tt.trayID)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handler.Handle(ec)
			if tt.expectedStatus != rec.Code {
				t.Errorf("GetTrayHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}

			// Verify response
			var apiTray model.APITray
			err = json.Unmarshal(rec.Body.Bytes(), &apiTray)
			assert.NoError(t, err)
			assert.Equal(t, trayID, apiTray.ID)
			assert.Equal(t, "Compute", apiTray.Type)
			assert.Equal(t, "NVIDIA", apiTray.Manufacturer)
		})
	}
}

func TestGetAllTrayHandler_Handle(t *testing.T) {
	// Setup
	e := echo.New()
	dbSession := testTrayInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testTraySetupTestData(t, dbSession, org)

	// Create a site without Flow enabled
	siteNoRLA := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site-no-flow",
		Org:                      org,
		InfrastructureProviderID: site.InfrastructureProviderID,
		Status:                   cdbm.SiteStatusRegistered,
		Config:                   &cdbm.SiteConfig{},
	}
	_, err := dbSession.DB.NewInsert().Model(siteNoRLA).Exec(context.Background())
	assert.Nil(t, err)

	// Create provider user
	providerUser := testTrayBuildUser(t, dbSession, "provider-user-tray", org, []string{authz.ProviderAdminRole})

	// Create tenant user (no provider role, no site access)
	tenantUser := testTrayBuildUser(t, dbSession, "tenant-user-tray", org, []string{authz.TenantAdminRole})

	handler := NewGetAllTrayHandler(dbSession, nil, scp, cfg)

	rackID := uuid.New().String()

	// Helper to create mock Flow response
	createMockRLAResponse := func(components []*flowv1.Component, total int32) *flowv1.GetComponentsResponse {
		return &flowv1.GetComponentsResponse{
			Components: components,
			Total:      total,
		}
	}

	// Create test components (trays)
	testComponents := []*flowv1.Component{
		createMockComponent("tray-1", "Compute-001", "NVIDIA", "GB200", "comp-1", flowv1.ComponentType_COMPONENT_TYPE_COMPUTE, rackID),
		createMockComponent("tray-2", "Compute-002", "NVIDIA", "GB200", "comp-2", flowv1.ComponentType_COMPONENT_TYPE_COMPUTE, rackID),
		createMockComponent("tray-3", "Switch-001", "NVIDIA", "NVL-Switch", "comp-3", flowv1.ComponentType_COMPONENT_TYPE_NVSWITCH, rackID),
		createMockComponent("tray-4", "Power-001", "NVIDIA", "PowerShelf", "comp-4", flowv1.ComponentType_COMPONENT_TYPE_POWERSHELF, rackID),
		createMockComponent("tray-5", "ToRSwitch-001", "Dell", "S5248", "comp-5", flowv1.ComponentType_COMPONENT_TYPE_TORSWITCH, rackID),
	}

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		queryParams    map[string]string
		mockResponse   *flowv1.GetComponentsResponse
		expectedStatus int
		expectedCount  int
		expectedTotal  *int
		wantErr        bool
	}{
		{
			name:   "success - get all trays",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			mockResponse:   createMockRLAResponse(testComponents, int32(len(testComponents))),
			expectedStatus: http.StatusOK,
			expectedCount:  len(testComponents),
			expectedTotal:  cdb.GetIntPtr(len(testComponents)),
			wantErr:        false,
		},
		{
			name:   "success - filter by rackId",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"rackId": rackID,
			},
			mockResponse:   createMockRLAResponse(testComponents, int32(len(testComponents))),
			expectedStatus: http.StatusOK,
			expectedCount:  len(testComponents),
			expectedTotal:  cdb.GetIntPtr(len(testComponents)),
			wantErr:        false,
		},
		{
			name:   "success - filter by type compute",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"type":   "Compute",
			},
			mockResponse:   createMockRLAResponse(testComponents[:2], 2),
			expectedStatus: http.StatusOK,
			expectedCount:  2,
			expectedTotal:  cdb.GetIntPtr(2),
			wantErr:        false,
		},
		{
			name:   "success - filter by rackName",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":   site.ID.String(),
				"rackName": "Rack-001",
			},
			mockResponse:   createMockRLAResponse(testComponents, int32(len(testComponents))),
			expectedStatus: http.StatusOK,
			expectedCount:  len(testComponents),
			expectedTotal:  cdb.GetIntPtr(len(testComponents)),
			wantErr:        false,
		},
		{
			name:   "success - pagination",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":     site.ID.String(),
				"pageNumber": "1",
				"pageSize":   "2",
			},
			mockResponse:   createMockRLAResponse(testComponents[:2], int32(len(testComponents))),
			expectedStatus: http.StatusOK,
			expectedCount:  2,
			expectedTotal:  cdb.GetIntPtr(len(testComponents)),
			wantErr:        false,
		},
		{
			name:   "success - orderBy name ASC",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":  site.ID.String(),
				"orderBy": "NAME_ASC",
			},
			mockResponse:   createMockRLAResponse(testComponents, int32(len(testComponents))),
			expectedStatus: http.StatusOK,
			expectedCount:  len(testComponents),
			expectedTotal:  cdb.GetIntPtr(len(testComponents)),
			wantErr:        false,
		},
		{
			name:   "success - orderBy manufacturer DESC",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":  site.ID.String(),
				"orderBy": "MANUFACTURER_DESC",
			},
			mockResponse:   createMockRLAResponse(testComponents, int32(len(testComponents))),
			expectedStatus: http.StatusOK,
			expectedCount:  len(testComponents),
			expectedTotal:  cdb.GetIntPtr(len(testComponents)),
			wantErr:        false,
		},
		{
			name:   "failure - Flow not enabled on site",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": siteNoRLA.ID.String(),
			},
			mockResponse:   nil,
			expectedStatus: http.StatusPreconditionFailed,
			wantErr:        true,
		},
		{
			name:        "failure - missing siteId",
			reqOrg:      org,
			user:        providerUser,
			queryParams: map[string]string{
				// no siteId
			},
			mockResponse:   nil,
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name:   "failure - tenant access denied",
			reqOrg: org,
			user:   tenantUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			mockResponse:   nil,
			expectedStatus: http.StatusForbidden,
			wantErr:        true,
		},
		{
			name:   "failure - invalid orderBy",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":  site.ID.String(),
				"orderBy": "INVALID_FIELD_ASC",
			},
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name:   "failure - invalid pagination (negative pageNumber)",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":     site.ID.String(),
				"pageNumber": "-1",
			},
			mockResponse:   nil,
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name:   "failure - invalid rackId (not UUID)",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"rackId": "not-a-uuid",
			},
			mockResponse:   nil,
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name:   "failure - invalid type",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"type":   "invalid-type",
			},
			mockResponse:   nil,
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name:   "failure - componentId without type",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":      site.ID.String(),
				"componentId": "comp-1",
			},
			mockResponse:   nil,
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name:   "failure - rackId and rackName mutually exclusive",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":   site.ID.String(),
				"rackId":   rackID,
				"rackName": "Rack-001",
			},
			mockResponse:   nil,
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name:   "failure - rackId conflicts with id (rack vs component targeting)",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"rackId": rackID,
				"id":     uuid.New().String(),
			},
			mockResponse:   nil,
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock Temporal client
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			// Always set up Get mock, even for error cases, as handler may still call it
			if tt.mockResponse != nil {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.GetComponentsResponse)
					resp.Components = tt.mockResponse.Components
					resp.Total = tt.mockResponse.Total
				}).Return(nil)
			} else {
				// For error cases, set up a mock that returns empty response
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.GetComponentsResponse)
					resp.Components = []*flowv1.Component{}
					resp.Total = 0
				}).Return(nil)
			}
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "GetTrays", mock.Anything, mock.Anything).Return(mockWorkflowRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			// Build query string
			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			path := fmt.Sprintf("/v2/org/%s/nico/tray?%s", tt.reqOrg, q.Encode())

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(tt.reqOrg)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handler.Handle(ec)
			// In Echo, c.JSON() returns nil on success, so err can be nil even when returning error response
			// Check status code instead of err for error cases
			if tt.expectedStatus != rec.Code {
				t.Errorf("GetAllTrayHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}

			// Verify response
			var apiTrays []*model.APITray
			err = json.Unmarshal(rec.Body.Bytes(), &apiTrays)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCount, len(apiTrays))

			// Verify pagination header
			ph := rec.Header().Get(pagination.ResponseHeaderName)
			assert.NotEmpty(t, ph)

			pr := &pagination.PageResponse{}
			err = json.Unmarshal([]byte(ph), pr)
			assert.NoError(t, err)

			if tt.expectedTotal != nil {
				assert.Equal(t, *tt.expectedTotal, pr.Total)
			}
		})
	}
}

func TestValidateTrayHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testTrayInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testTraySetupTestData(t, dbSession, org)

	// Create a site without Flow enabled
	siteNoRLA := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site-no-flow",
		Org:                      org,
		InfrastructureProviderID: site.InfrastructureProviderID,
		Status:                   cdbm.SiteStatusRegistered,
		Config:                   &cdbm.SiteConfig{},
	}
	_, err := dbSession.DB.NewInsert().Model(siteNoRLA).Exec(context.Background())
	assert.Nil(t, err)

	providerUser := testTrayBuildUser(t, dbSession, "provider-user-validate-tray", org, []string{authz.ProviderAdminRole})
	tenantUser := testTrayBuildUser(t, dbSession, "tenant-user-validate-tray", org, []string{authz.TenantAdminRole})

	handler := NewValidateTrayHandler(dbSession, nil, scp, cfg)

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	trayID := uuid.NewString()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		trayID         string
		queryParams    map[string]string
		mockResponse   *flowv1.ValidateComponentsResponse
		expectedStatus int
	}{
		{
			name:   "success - validate tray with no diffs",
			reqOrg: org,
			user:   providerUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			mockResponse: &flowv1.ValidateComponentsResponse{
				Diffs:           []*flowv1.ComponentDiff{},
				TotalDiffs:      0,
				MissingCount:    0,
				UnexpectedCount: 0,
				MismatchCount:   0,
				MatchCount:      1,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "success - validate tray with diffs",
			reqOrg: org,
			user:   providerUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			mockResponse: &flowv1.ValidateComponentsResponse{
				Diffs: []*flowv1.ComponentDiff{
					{
						Type:        flowv1.DiffType_DIFF_TYPE_MISMATCH,
						ComponentId: "comp-1",
						FieldDiffs: []*flowv1.FieldDiff{
							{
								FieldName:     "firmware_version",
								ExpectedValue: "1.0.0",
								ActualValue:   "2.0.0",
							},
						},
					},
				},
				TotalDiffs:      1,
				MissingCount:    0,
				UnexpectedCount: 0,
				MismatchCount:   1,
				MatchCount:      0,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "failure - Flow not enabled on site",
			reqOrg: org,
			user:   providerUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": siteNoRLA.ID.String(),
			},
			expectedStatus: http.StatusPreconditionFailed,
		},
		{
			name:   "failure - tenant user forbidden",
			reqOrg: org,
			user:   tenantUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "failure - missing siteId",
			reqOrg:         org,
			user:           providerUser,
			trayID:         trayID,
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "failure - invalid siteId",
			reqOrg: org,
			user:   providerUser,
			trayID: trayID,
			queryParams: map[string]string{
				"siteId": uuid.NewString(),
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "failure - invalid tray ID",
			reqOrg: org,
			user:   providerUser,
			trayID: "not-a-uuid",
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			if tt.mockResponse != nil {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.ValidateComponentsResponse)
					resp.Diffs = tt.mockResponse.Diffs
					resp.TotalDiffs = tt.mockResponse.TotalDiffs
					resp.MissingCount = tt.mockResponse.MissingCount
					resp.UnexpectedCount = tt.mockResponse.UnexpectedCount
					resp.MismatchCount = tt.mockResponse.MismatchCount
					resp.MatchCount = tt.mockResponse.MatchCount
				}).Return(nil)
			} else {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.ValidateComponentsResponse)
					resp.Diffs = []*flowv1.ComponentDiff{}
					resp.TotalDiffs = 0
				}).Return(nil)
			}
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "ValidateRackComponents", mock.Anything).Return(mockWorkflowRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			path := fmt.Sprintf("/v2/org/%s/nico/tray/%s/validation?%s", tt.reqOrg, tt.trayID, q.Encode())

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tt.reqOrg, tt.trayID)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handler.Handle(ec)
			if tt.expectedStatus != rec.Code {
				t.Errorf("ValidateTrayHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}

			var apiResult model.APIRackValidationResult
			err = json.Unmarshal(rec.Body.Bytes(), &apiResult)
			assert.NoError(t, err)
			assert.Equal(t, tt.mockResponse.TotalDiffs, apiResult.TotalDiffs)
			assert.Equal(t, tt.mockResponse.MatchCount, apiResult.MatchCount)
			assert.Equal(t, len(tt.mockResponse.Diffs), len(apiResult.Diffs))
		})
	}
}

func TestValidateTraysHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testTrayInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testTraySetupTestData(t, dbSession, org)

	// Create a site without Flow enabled
	siteNoRLA := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site-no-flow",
		Org:                      org,
		InfrastructureProviderID: site.InfrastructureProviderID,
		Status:                   cdbm.SiteStatusRegistered,
		Config:                   &cdbm.SiteConfig{},
	}
	_, err := dbSession.DB.NewInsert().Model(siteNoRLA).Exec(context.Background())
	assert.Nil(t, err)

	providerUser := testTrayBuildUser(t, dbSession, "provider-user-validate-trays", org, []string{authz.ProviderAdminRole})
	tenantUser := testTrayBuildUser(t, dbSession, "tenant-user-validate-trays", org, []string{authz.TenantAdminRole})

	handler := NewValidateTraysHandler(dbSession, nil, scp, cfg)

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	rackID := uuid.NewString()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		queryParams    map[string]string
		mockResponse   *flowv1.ValidateComponentsResponse
		expectedStatus int
	}{
		{
			name:   "success - validate all trays (no filter)",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			mockResponse: &flowv1.ValidateComponentsResponse{
				Diffs:           []*flowv1.ComponentDiff{},
				TotalDiffs:      0,
				MissingCount:    0,
				UnexpectedCount: 0,
				MismatchCount:   0,
				MatchCount:      10,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "success - validate with name filter",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"name":   "Tray-001",
			},
			mockResponse: &flowv1.ValidateComponentsResponse{
				Diffs:      []*flowv1.ComponentDiff{},
				TotalDiffs: 0,
				MatchCount: 3,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "success - validate with type filter",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"type":   "Compute",
			},
			mockResponse: &flowv1.ValidateComponentsResponse{
				Diffs:      []*flowv1.ComponentDiff{},
				TotalDiffs: 0,
				MatchCount: 5,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "success - validate with rackId scope",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"rackId": rackID,
			},
			mockResponse: &flowv1.ValidateComponentsResponse{
				Diffs:      []*flowv1.ComponentDiff{},
				TotalDiffs: 0,
				MatchCount: 4,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "success - validate with rackName scope",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":   site.ID.String(),
				"rackName": "Rack-001",
			},
			mockResponse: &flowv1.ValidateComponentsResponse{
				Diffs:      []*flowv1.ComponentDiff{},
				TotalDiffs: 0,
				MatchCount: 4,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "success - validate with rackId and type filter combined",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"rackId": rackID,
				"type":   "Compute",
			},
			mockResponse: &flowv1.ValidateComponentsResponse{
				Diffs:      []*flowv1.ComponentDiff{},
				TotalDiffs: 0,
				MatchCount: 2,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "success - validate with componentId and type",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":      site.ID.String(),
				"componentId": "ext-comp-1",
				"type":        "Compute",
			},
			mockResponse: &flowv1.ValidateComponentsResponse{
				Diffs:      []*flowv1.ComponentDiff{},
				TotalDiffs: 0,
				MatchCount: 1,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "failure - rackId and rackName mutually exclusive",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":   site.ID.String(),
				"rackId":   rackID,
				"rackName": "Rack-001",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "failure - rackId and componentId mutually exclusive",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":      site.ID.String(),
				"rackId":      rackID,
				"componentId": "ext-comp-1",
				"type":        "Compute",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "failure - componentId without type",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId":      site.ID.String(),
				"componentId": "ext-comp-1",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "failure - invalid rackId",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
				"rackId": "not-a-uuid",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "failure - Flow not enabled on site",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": siteNoRLA.ID.String(),
			},
			expectedStatus: http.StatusPreconditionFailed,
		},
		{
			name:   "failure - tenant user forbidden",
			reqOrg: org,
			user:   tenantUser,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "failure - missing siteId",
			reqOrg:         org,
			user:           providerUser,
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "failure - invalid siteId",
			reqOrg: org,
			user:   providerUser,
			queryParams: map[string]string{
				"siteId": uuid.NewString(),
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			if tt.mockResponse != nil {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.ValidateComponentsResponse)
					resp.Diffs = tt.mockResponse.Diffs
					resp.TotalDiffs = tt.mockResponse.TotalDiffs
					resp.MissingCount = tt.mockResponse.MissingCount
					resp.UnexpectedCount = tt.mockResponse.UnexpectedCount
					resp.MismatchCount = tt.mockResponse.MismatchCount
					resp.MatchCount = tt.mockResponse.MatchCount
				}).Return(nil)
			} else {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.ValidateComponentsResponse)
					resp.Diffs = []*flowv1.ComponentDiff{}
					resp.TotalDiffs = 0
				}).Return(nil)
			}
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "ValidateRackComponents", mock.Anything).Return(mockWorkflowRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			path := fmt.Sprintf("/v2/org/%s/nico/tray/validation?%s", tt.reqOrg, q.Encode())

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(tt.reqOrg)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handler.Handle(ec)
			if tt.expectedStatus != rec.Code {
				t.Errorf("ValidateTraysHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}

			var apiResult model.APIRackValidationResult
			err = json.Unmarshal(rec.Body.Bytes(), &apiResult)
			assert.NoError(t, err)
			assert.Equal(t, tt.mockResponse.TotalDiffs, apiResult.TotalDiffs)
			assert.Equal(t, tt.mockResponse.MatchCount, apiResult.MatchCount)
			assert.Equal(t, len(tt.mockResponse.Diffs), len(apiResult.Diffs))
		})
	}
}

func TestUpdateTrayPowerStateHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testTrayInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testTraySetupTestData(t, dbSession, org)

	providerUser := testTrayBuildUser(t, dbSession, "provider-user-pc-tray", org, []string{authz.ProviderAdminRole})
	tenantUser := testTrayBuildUser(t, dbSession, "tenant-user-pc-tray", org, []string{authz.TenantAdminRole})

	handler := NewUpdateTrayPowerStateHandler(dbSession, nil, scp, cfg)

	trayID := uuid.New().String()

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		trayID         string
		body           string
		mockTaskIDs    []*flowv1.UUID
		expectedStatus int
	}{
		{
			name:           "success - power on tray",
			reqOrg:         org,
			user:           providerUser,
			trayID:         trayID,
			body:           fmt.Sprintf(`{"siteId":"%s","state":"on"}`, site.ID.String()),
			mockTaskIDs:    []*flowv1.UUID{{Id: uuid.NewString()}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "success - power off tray",
			reqOrg:         org,
			user:           providerUser,
			trayID:         trayID,
			body:           fmt.Sprintf(`{"siteId":"%s","state":"off"}`, site.ID.String()),
			mockTaskIDs:    []*flowv1.UUID{{Id: uuid.NewString()}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "success - force power cycle tray",
			reqOrg:         org,
			user:           providerUser,
			trayID:         trayID,
			body:           fmt.Sprintf(`{"siteId":"%s","state":"forcecycle"}`, site.ID.String()),
			mockTaskIDs:    []*flowv1.UUID{{Id: uuid.NewString()}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "failure - invalid state",
			reqOrg:         org,
			user:           providerUser,
			trayID:         trayID,
			body:           fmt.Sprintf(`{"siteId":"%s","state":"reboot"}`, site.ID.String()),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - missing siteId",
			reqOrg:         org,
			user:           providerUser,
			trayID:         trayID,
			body:           `{"state":"on"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - invalid tray ID (not UUID)",
			reqOrg:         org,
			user:           providerUser,
			trayID:         "not-a-uuid",
			body:           fmt.Sprintf(`{"siteId":"%s","state":"on"}`, site.ID.String()),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			reqOrg:         org,
			user:           tenantUser,
			trayID:         trayID,
			body:           fmt.Sprintf(`{"siteId":"%s","state":"on"}`, site.ID.String()),
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				resp := args.Get(1).(*flowv1.SubmitTaskResponse)
				if tt.mockTaskIDs != nil {
					resp.TaskIds = tt.mockTaskIDs
				}
			}).Return(nil)
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockWorkflowRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			path := fmt.Sprintf("/v2/org/%s/nico/tray/%s/power", tt.reqOrg, tt.trayID)

			req := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tt.reqOrg, tt.trayID)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handler.Handle(ec)

			if tt.expectedStatus != rec.Code {
				t.Errorf("UpdateTrayPowerStateHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}

			var apiResp model.APIUpdatePowerStateResponse
			err = json.Unmarshal(rec.Body.Bytes(), &apiResp)
			assert.NoError(t, err)
			assert.NotEmpty(t, apiResp.TaskIDs)
		})
	}
}

func TestBatchUpdateTrayPowerStateHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testTrayInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testTraySetupTestData(t, dbSession, org)

	providerUser := testTrayBuildUser(t, dbSession, "provider-user-pc-tray-batch", org, []string{authz.ProviderAdminRole})
	tenantUser := testTrayBuildUser(t, dbSession, "tenant-user-pc-tray-batch", org, []string{authz.TenantAdminRole})

	handler := NewBatchUpdateTrayPowerStateHandler(dbSession, nil, scp, cfg)

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	rackID := uuid.NewString()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		body           string
		mockTaskIDs    []*flowv1.UUID
		expectedStatus int
	}{
		{
			name:           "success - power on all trays (no filter)",
			reqOrg:         org,
			user:           providerUser,
			body:           fmt.Sprintf(`{"siteId":"%s","state":"on"}`, site.ID.String()),
			mockTaskIDs:    []*flowv1.UUID{{Id: uuid.NewString()}, {Id: uuid.NewString()}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "success - power cycle with rackId filter",
			reqOrg:         org,
			user:           providerUser,
			body:           fmt.Sprintf(`{"siteId":"%s","filter":{"rackId":"%s"},"state":"cycle"}`, site.ID.String(), rackID),
			mockTaskIDs:    []*flowv1.UUID{{Id: uuid.NewString()}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "failure - missing siteId",
			reqOrg:         org,
			user:           providerUser,
			body:           `{"state":"on"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - invalid state",
			reqOrg:         org,
			user:           providerUser,
			body:           fmt.Sprintf(`{"siteId":"%s","state":"unknown"}`, site.ID.String()),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			reqOrg:         org,
			user:           tenantUser,
			body:           fmt.Sprintf(`{"siteId":"%s","state":"on"}`, site.ID.String()),
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				resp := args.Get(1).(*flowv1.SubmitTaskResponse)
				if tt.mockTaskIDs != nil {
					resp.TaskIds = tt.mockTaskIDs
				}
			}).Return(nil)
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockWorkflowRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			path := fmt.Sprintf("/v2/org/%s/nico/tray/power", tt.reqOrg)

			req := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(tt.reqOrg)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handler.Handle(ec)

			if tt.expectedStatus != rec.Code {
				t.Errorf("BatchUpdateTrayPowerStateHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}

			var apiResp model.APIUpdatePowerStateResponse
			err = json.Unmarshal(rec.Body.Bytes(), &apiResp)
			assert.NoError(t, err)
			assert.NotEmpty(t, apiResp.TaskIDs)
		})
	}
}

func TestUpdateTrayFirmwareHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testTrayInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testTraySetupTestData(t, dbSession, org)

	providerUser := testTrayBuildUser(t, dbSession, "provider-user-fw-tray", org, []string{authz.ProviderAdminRole})
	tenantUser := testTrayBuildUser(t, dbSession, "tenant-user-fw-tray", org, []string{authz.TenantAdminRole})

	handler := NewUpdateTrayFirmwareHandler(dbSession, nil, scp, cfg)

	trayID := uuid.New().String()

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		trayID         string
		body           string
		mockTaskIDs    []*flowv1.UUID
		expectedStatus int
	}{
		{
			name:           "success - firmware update with version",
			reqOrg:         org,
			user:           providerUser,
			trayID:         trayID,
			body:           fmt.Sprintf(`{"siteId":"%s","version":"24.11.0"}`, site.ID.String()),
			mockTaskIDs:    []*flowv1.UUID{{Id: uuid.NewString()}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "success - firmware update without version",
			reqOrg:         org,
			user:           providerUser,
			trayID:         trayID,
			body:           fmt.Sprintf(`{"siteId":"%s"}`, site.ID.String()),
			mockTaskIDs:    []*flowv1.UUID{{Id: uuid.NewString()}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "failure - missing siteId",
			reqOrg:         org,
			user:           providerUser,
			trayID:         trayID,
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - invalid tray ID (not UUID)",
			reqOrg:         org,
			user:           providerUser,
			trayID:         "not-a-uuid",
			body:           fmt.Sprintf(`{"siteId":"%s"}`, site.ID.String()),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			reqOrg:         org,
			user:           tenantUser,
			trayID:         trayID,
			body:           fmt.Sprintf(`{"siteId":"%s"}`, site.ID.String()),
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				resp := args.Get(1).(*flowv1.SubmitTaskResponse)
				if tt.mockTaskIDs != nil {
					resp.TaskIds = tt.mockTaskIDs
				}
			}).Return(nil)
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockWorkflowRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			path := fmt.Sprintf("/v2/org/%s/nico/tray/%s/firmware", tt.reqOrg, tt.trayID)

			req := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tt.reqOrg, tt.trayID)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handler.Handle(ec)

			if tt.expectedStatus != rec.Code {
				t.Errorf("UpdateTrayFirmwareHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}

			var apiResp model.APIUpdateFirmwareResponse
			err = json.Unmarshal(rec.Body.Bytes(), &apiResp)
			assert.NoError(t, err)
			assert.NotEmpty(t, apiResp.TaskIDs)
		})
	}
}

func TestBatchUpdateTrayFirmwareHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testTrayInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testTraySetupTestData(t, dbSession, org)

	providerUser := testTrayBuildUser(t, dbSession, "provider-user-fw-tray-batch", org, []string{authz.ProviderAdminRole})
	tenantUser := testTrayBuildUser(t, dbSession, "tenant-user-fw-tray-batch", org, []string{authz.TenantAdminRole})

	handler := NewBatchUpdateTrayFirmwareHandler(dbSession, nil, scp, cfg)

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	fwRackID := uuid.NewString()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		body           string
		mockTaskIDs    []*flowv1.UUID
		expectedStatus int
	}{
		{
			name:           "success - firmware update all trays (no filter)",
			reqOrg:         org,
			user:           providerUser,
			body:           fmt.Sprintf(`{"siteId":"%s"}`, site.ID.String()),
			mockTaskIDs:    []*flowv1.UUID{{Id: uuid.NewString()}, {Id: uuid.NewString()}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "success - firmware update with rackId filter and version",
			reqOrg:         org,
			user:           providerUser,
			body:           fmt.Sprintf(`{"siteId":"%s","filter":{"rackId":"%s"},"version":"24.11.0"}`, site.ID.String(), fwRackID),
			mockTaskIDs:    []*flowv1.UUID{{Id: uuid.NewString()}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "failure - missing siteId",
			reqOrg:         org,
			user:           providerUser,
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			reqOrg:         org,
			user:           tenantUser,
			body:           fmt.Sprintf(`{"siteId":"%s"}`, site.ID.String()),
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				resp := args.Get(1).(*flowv1.SubmitTaskResponse)
				if tt.mockTaskIDs != nil {
					resp.TaskIds = tt.mockTaskIDs
				}
			}).Return(nil)
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockWorkflowRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			path := fmt.Sprintf("/v2/org/%s/nico/tray/firmware", tt.reqOrg)

			req := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(tt.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(tt.reqOrg)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handler.Handle(ec)

			if tt.expectedStatus != rec.Code {
				t.Errorf("BatchUpdateTrayFirmwareHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}

			var apiResp model.APIUpdateFirmwareResponse
			err = json.Unmarshal(rec.Body.Bytes(), &apiResp)
			assert.NoError(t, err)
			assert.NotEmpty(t, apiResp.TaskIDs)
		})
	}
}
