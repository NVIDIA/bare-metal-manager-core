// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/api/internal/config"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller-rest/api/pkg/client/site"
	authz "github.com/NVIDIA/infra-controller-rest/auth/pkg/authorization"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbu "github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/uptrace/bun/extra/bundebug"
	tmocks "go.temporal.io/sdk/mocks"
)

// testExpectedSwitchInitDB initializes a test database session
func testExpectedSwitchInitDB(t *testing.T) *cdb.Session {
	dbSession := cdbu.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("BUNDEBUG"),
	))

	ctx := context.Background()

	err := dbSession.DB.ResetModel(ctx, (*cdbm.User)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.InfrastructureProvider)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.Tenant)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.Site)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.TenantAccount)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.ExpectedSwitch)(nil))
	assert.Nil(t, err)

	return dbSession
}

// testExpectedSwitchSetupTestData creates test infrastructure provider and site
func testExpectedSwitchSetupTestData(t *testing.T, dbSession *cdb.Session, org string) (*cdbm.InfrastructureProvider, *cdbm.Site) {
	ctx := context.Background()

	ip := &cdbm.InfrastructureProvider{
		ID:   uuid.New(),
		Name: "test-provider",
		Org:  org,
	}
	_, err := dbSession.DB.NewInsert().Model(ip).Exec(ctx)
	assert.Nil(t, err)

	site := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site",
		Org:                      org,
		InfrastructureProviderID: ip.ID,
		Status:                   cdbm.SiteStatusRegistered,
	}
	_, err = dbSession.DB.NewInsert().Model(site).Exec(ctx)
	assert.Nil(t, err)

	return ip, site
}

func TestCreateExpectedSwitchHandler_Handle(t *testing.T) {
	e := echo.New()

	dbSession := testExpectedSwitchInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()

	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	infraProv, site := testExpectedSwitchSetupTestData(t, dbSession, org)

	ctx := context.Background()
	unmanagedIP := &cdbm.InfrastructureProvider{
		ID:   uuid.New(),
		Name: "unmanaged-provider",
		Org:  "other-org",
	}
	_, err := dbSession.DB.NewInsert().Model(unmanagedIP).Exec(ctx)
	assert.Nil(t, err)

	unmanagedSite := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "unmanaged-site",
		Org:                      "other-org",
		InfrastructureProviderID: unmanagedIP.ID,
		Status:                   cdbm.SiteStatusRegistered,
	}
	_, err = dbSession.DB.NewInsert().Model(unmanagedSite).Exec(ctx)
	assert.Nil(t, err)

	// Create an existing Expected Switch with a specific MAC address for duplicate test
	esDAO := cdbm.NewExpectedSwitchDAO(dbSession)
	existingMAC := "AA:BB:CC:DD:EE:11"
	_, err = esDAO.Create(ctx, nil, cdbm.ExpectedSwitchCreateInput{
		ExpectedSwitchID:   uuid.New(),
		SiteID:             site.ID,
		BmcMacAddress:      existingMAC,
		SwitchSerialNumber: "EXISTING-SWITCH-001",
		Labels:             map[string]string{"env": "existing"},
	})
	assert.Nil(t, err)

	// Add mock temporal client for the site
	mockTemporalClient := &tmocks.Client{}
	mockWorkflowRun := &tmocks.WorkflowRun{}
	mockWorkflowRun.On("GetID").Return("test-workflow-id")
	mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Return(nil)
	mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "CreateExpectedSwitch", mock.Anything).Return(mockWorkflowRun, nil)
	scp.IDClientMap[site.ID.String()] = mockTemporalClient

	handler := NewCreateExpectedSwitchHandler(dbSession, scp, cfg)

	createMockUser := func(org string) *cdbm.User {
		return &cdbm.User{
			StarfleetID: cdb.GetStrPtr("test-user"),
			OrgData: cdbm.OrgData{
				org: cdbm.Org{
					ID:          123,
					Name:        org,
					DisplayName: org,
					OrgType:     "ENTERPRISE",
					Roles:       []string{authz.ProviderAdminRole},
				},
			},
		}
	}

	tests := []struct {
		name           string
		requestBody    model.APIExpectedSwitchCreateRequest
		setupContext   func(c echo.Context)
		expectedStatus int
	}{
		{
			name: "successful creation",
			requestBody: model.APIExpectedSwitchCreateRequest{
				SiteID:             site.ID.String(),
				BmcMacAddress:      "00:11:22:33:44:55",
				DefaultBmcUsername: cdb.GetStrPtr("admin"),
				DefaultBmcPassword: cdb.GetStrPtr("password"),
				SwitchSerialNumber: "SWITCH123",
				NvOsUsername:       cdb.GetStrPtr("nvos-admin"),
				NvOsPassword:       cdb.GetStrPtr("nvos-password"),
				BmcIpAddress:       cdb.GetStrPtr("192.168.1.10"),
				Labels:             map[string]string{"env": "test"},
			},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "missing user context",
			requestBody: model.APIExpectedSwitchCreateRequest{
				SiteID:             site.ID.String(),
				BmcMacAddress:      "00:11:22:33:44:77",
				DefaultBmcUsername: cdb.GetStrPtr("admin"),
				DefaultBmcPassword: cdb.GetStrPtr("password"),
				SwitchSerialNumber: "SWITCH125",
			},
			setupContext: func(c echo.Context) {
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "invalid mac address length",
			requestBody: model.APIExpectedSwitchCreateRequest{
				SiteID:             site.ID.String(),
				BmcMacAddress:      "00:11:22:33:44",
				DefaultBmcUsername: cdb.GetStrPtr("admin"),
				DefaultBmcPassword: cdb.GetStrPtr("password"),
				SwitchSerialNumber: "SWITCH126",
			},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "site not found",
			requestBody: model.APIExpectedSwitchCreateRequest{
				SiteID:             "12345678-1234-1234-1234-123456789099",
				BmcMacAddress:      "00:11:22:33:44:88",
				DefaultBmcUsername: cdb.GetStrPtr("admin"),
				DefaultBmcPassword: cdb.GetStrPtr("password"),
				SwitchSerialNumber: "SWITCH127",
			},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "cannot create on unmanaged site",
			requestBody: model.APIExpectedSwitchCreateRequest{
				SiteID:             unmanagedSite.ID.String(),
				BmcMacAddress:      "00:11:22:33:44:99",
				DefaultBmcUsername: cdb.GetStrPtr("admin"),
				DefaultBmcPassword: cdb.GetStrPtr("password"),
				SwitchSerialNumber: "SWITCH128",
			},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "duplicate MAC address should return 409",
			requestBody: model.APIExpectedSwitchCreateRequest{
				SiteID:             site.ID.String(),
				BmcMacAddress:      existingMAC,
				DefaultBmcUsername: cdb.GetStrPtr("admin"),
				DefaultBmcPassword: cdb.GetStrPtr("password"),
				SwitchSerialNumber: "DUPLICATE-SWITCH-999",
				Labels:             map[string]string{"env": "duplicate-test"},
			},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusConflict,
		},
	}

	_ = infraProv

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/v2/org/test-org/nico/expected-switch", bytes.NewReader(reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req = req.WithContext(context.Background())

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			tt.setupContext(c)

			err := handler.Handle(c)

			assert.Nil(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != rec.Code {
				t.Errorf("Response: %v", rec.Body.String())
			}

			if tt.expectedStatus == http.StatusCreated {
				var response model.APIExpectedSwitch
				err := json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Nil(t, err)
				if tt.requestBody.Labels != nil {
					assert.NotNil(t, response.Labels, "Labels should not be nil in response")
					assert.Equal(t, tt.requestBody.Labels, response.Labels, "Labels in response should match request")
				}
				if tt.requestBody.BmcIpAddress != nil {
					if assert.NotNil(t, response.BmcIpAddress, "BmcIpAddress should not be nil in response") {
						assert.Equal(t, *tt.requestBody.BmcIpAddress, *response.BmcIpAddress, "BmcIpAddress in response should match request")
					}
				}
			}
		})
	}
}

func TestGetAllExpectedSwitchHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testExpectedSwitchInitDB(t)
	defer dbSession.Close()

	ctx := context.Background()
	cfg := &config.Config{}
	handler := NewGetAllExpectedSwitchHandler(dbSession, cfg)

	org := "test-org"
	infraProv, site := testExpectedSwitchSetupTestData(t, dbSession, org)

	unmanagedIP := &cdbm.InfrastructureProvider{
		ID:   uuid.New(),
		Name: "unmanaged-provider",
		Org:  "other-org",
	}
	_, err := dbSession.DB.NewInsert().Model(unmanagedIP).Exec(ctx)
	assert.Nil(t, err)

	unmanagedSite := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "unmanaged-site",
		Org:                      "other-org",
		InfrastructureProviderID: unmanagedIP.ID,
		Status:                   cdbm.SiteStatusRegistered,
	}
	_, err = dbSession.DB.NewInsert().Model(unmanagedSite).Exec(ctx)
	assert.Nil(t, err)

	// Create expected switches - one on managed site, one on unmanaged site
	esDAO := cdbm.NewExpectedSwitchDAO(dbSession)
	managedES, err := esDAO.Create(ctx, nil, cdbm.ExpectedSwitchCreateInput{
		ExpectedSwitchID:   uuid.New(),
		SiteID:             site.ID,
		BmcMacAddress:      "00:11:22:33:44:AA",
		SwitchSerialNumber: "MANAGED-SWITCH",
		Labels:             map[string]string{"env": "test"},
	})
	assert.Nil(t, err)
	assert.NotNil(t, managedES)

	unmanagedES, err := esDAO.Create(ctx, nil, cdbm.ExpectedSwitchCreateInput{
		ExpectedSwitchID:   uuid.New(),
		SiteID:             unmanagedSite.ID,
		BmcMacAddress:      "00:11:22:33:44:BB",
		SwitchSerialNumber: "UNMANAGED-SWITCH",
	})
	assert.Nil(t, err)
	assert.NotNil(t, unmanagedES)

	createMockUser := func(org string) *cdbm.User {
		return &cdbm.User{
			StarfleetID: cdb.GetStrPtr("test-user"),
			OrgData: cdbm.OrgData{
				org: cdbm.Org{
					ID:          123,
					Name:        org,
					DisplayName: org,
					OrgType:     "ENTERPRISE",
					Roles:       []string{authz.ProviderViewerRole},
				},
			},
		}
	}

	tests := []struct {
		name                 string
		siteId               string
		includeRelations     []string
		setupContext         func(c echo.Context)
		expectedStatus       int
		checkResponseContent func(t *testing.T, body []byte)
	}{
		{
			name:   "successful GetAll without siteId (lists only managed sites)",
			siteId: "",
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []model.APIExpectedSwitch
				err := json.Unmarshal(body, &response)
				assert.Nil(t, err)
				for _, es := range response {
					assert.NotEqual(t, unmanagedES.ID, es.ID, "Unmanaged switch should not be in response")
				}
			},
		},
		{
			name:   "successful GetAll with valid siteId",
			siteId: site.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []model.APIExpectedSwitch
				err := json.Unmarshal(body, &response)
				assert.Nil(t, err)
				for _, es := range response {
					assert.Equal(t, site.ID, es.SiteID, "All results should be from the specified site")
				}
			},
		},
		{
			name:             "successful GetAll with includeRelation=Site",
			siteId:           "",
			includeRelations: []string{"Site"},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []model.APIExpectedSwitch
				err := json.Unmarshal(body, &response)
				assert.Nil(t, err)
				assert.Greater(t, len(response), 0, "Should return at least one expected switch")
				for _, es := range response {
					assert.NotNil(t, es.Site, "Site relation should be loaded")
					assert.Equal(t, es.SiteID.String(), es.Site.ID, "Site ID should match")
				}
			},
		},
		{
			name:   "cannot retrieve from unmanaged site",
			siteId: unmanagedSite.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	_ = infraProv

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/v2/org/" + org + "/nico/expected-switch"
			params := []string{}
			if tt.siteId != "" {
				params = append(params, "siteId="+tt.siteId)
			}
			for _, relation := range tt.includeRelations {
				params = append(params, "includeRelation="+relation)
			}
			if len(params) > 0 {
				url += "?" + params[0]
				for i := 1; i < len(params); i++ {
					url += "&" + params[i]
				}
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req = req.WithContext(context.Background())

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			tt.setupContext(c)

			err := handler.Handle(c)

			assert.Nil(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != rec.Code {
				t.Errorf("Response: %v", rec.Body.String())
			}

			if tt.checkResponseContent != nil && rec.Code == http.StatusOK {
				tt.checkResponseContent(t, rec.Body.Bytes())
			}
		})
	}
}

func TestGetExpectedSwitchHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testExpectedSwitchInitDB(t)
	defer dbSession.Close()

	ctx := context.Background()

	cfg := &config.Config{}
	handler := NewGetExpectedSwitchHandler(dbSession, cfg)

	org := "test-org"
	infraProv, site := testExpectedSwitchSetupTestData(t, dbSession, org)

	unmanagedIP := &cdbm.InfrastructureProvider{
		ID:   uuid.New(),
		Name: "unmanaged-provider",
		Org:  "other-org",
	}
	_, err := dbSession.DB.NewInsert().Model(unmanagedIP).Exec(ctx)
	assert.Nil(t, err)

	unmanagedSite := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "unmanaged-site",
		Org:                      "other-org",
		InfrastructureProviderID: unmanagedIP.ID,
		Status:                   cdbm.SiteStatusRegistered,
	}
	_, err = dbSession.DB.NewInsert().Model(unmanagedSite).Exec(ctx)
	assert.Nil(t, err)

	// Create a test ExpectedSwitch on managed site
	esDAO := cdbm.NewExpectedSwitchDAO(dbSession)
	testES, err := esDAO.Create(ctx, nil, cdbm.ExpectedSwitchCreateInput{
		ExpectedSwitchID:   uuid.New(),
		SiteID:             site.ID,
		BmcMacAddress:      "00:11:22:33:44:55",
		SwitchSerialNumber: "TEST-SWITCH-123",
		Labels:             map[string]string{"env": "test"},
	})
	assert.Nil(t, err)
	assert.NotNil(t, testES)

	// Create a test ExpectedSwitch on unmanaged site
	unmanagedES, err := esDAO.Create(ctx, nil, cdbm.ExpectedSwitchCreateInput{
		ExpectedSwitchID:   uuid.New(),
		SiteID:             unmanagedSite.ID,
		BmcMacAddress:      "00:11:22:33:44:CC",
		SwitchSerialNumber: "UNMANAGED-SWITCH-456",
		Labels:             map[string]string{"env": "unmanaged"},
	})
	assert.Nil(t, err)
	assert.NotNil(t, unmanagedES)

	createMockUser := func(org string) *cdbm.User {
		return &cdbm.User{
			StarfleetID: cdb.GetStrPtr("test-user"),
			OrgData: cdbm.OrgData{
				org: cdbm.Org{
					ID:          123,
					Name:        org,
					DisplayName: org,
					OrgType:     "ENTERPRISE",
					Roles:       []string{authz.ProviderAdminRole},
				},
			},
		}
	}

	tests := []struct {
		name           string
		id             string
		setupContext   func(c echo.Context)
		expectedStatus int
	}{
		{
			name: "invalid ID",
			id:   "invalid-id",
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, "invalid-id")
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "successful retrieval",
			id:   testES.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, testES.ID.String())
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "switch not found",
			id:   "12345678-1234-1234-1234-123456789099",
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, "12345678-1234-1234-1234-123456789099")
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "cannot retrieve from unmanaged site",
			id:   unmanagedES.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, unmanagedES.ID.String())
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	_ = infraProv

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/v2/org/" + org + "/nico/expected-switch/" + tt.id
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req = req.WithContext(context.Background())

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			tt.setupContext(c)

			err := handler.Handle(c)

			assert.Nil(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != rec.Code {
				t.Errorf("Response: %v", rec.Body.String())
			}

			if tt.expectedStatus == http.StatusOK && tt.name == "successful retrieval" {
				var response model.APIExpectedSwitch
				err := json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Nil(t, err)
				assert.NotNil(t, response.Labels, "Labels should not be nil in response")
				assert.Equal(t, "test", response.Labels["env"], "Labels in response should contain the 'env' label with value 'test'")
			}
		})
	}
}

func TestUpdateExpectedSwitchHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testExpectedSwitchInitDB(t)
	defer dbSession.Close()

	ctx := context.Background()
	cfg := common.GetTestConfig()

	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	infraProv, site := testExpectedSwitchSetupTestData(t, dbSession, org)

	unmanagedIP := &cdbm.InfrastructureProvider{
		ID:   uuid.New(),
		Name: "unmanaged-provider",
		Org:  "other-org",
	}
	_, err := dbSession.DB.NewInsert().Model(unmanagedIP).Exec(ctx)
	assert.Nil(t, err)

	unmanagedSite := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "unmanaged-site",
		Org:                      "other-org",
		InfrastructureProviderID: unmanagedIP.ID,
		Status:                   cdbm.SiteStatusRegistered,
	}
	_, err = dbSession.DB.NewInsert().Model(unmanagedSite).Exec(ctx)
	assert.Nil(t, err)

	// Create a test ExpectedSwitch on managed site
	esDAO := cdbm.NewExpectedSwitchDAO(dbSession)
	testES, err := esDAO.Create(ctx, nil, cdbm.ExpectedSwitchCreateInput{
		ExpectedSwitchID:   uuid.New(),
		SiteID:             site.ID,
		BmcMacAddress:      "00:11:22:33:44:DD",
		SwitchSerialNumber: "UPDATE-SWITCH-123",
		Labels:             map[string]string{"env": "test"},
	})
	assert.Nil(t, err)
	assert.NotNil(t, testES)

	// Create a test ExpectedSwitch on unmanaged site
	unmanagedES, err := esDAO.Create(ctx, nil, cdbm.ExpectedSwitchCreateInput{
		ExpectedSwitchID:   uuid.New(),
		SiteID:             unmanagedSite.ID,
		BmcMacAddress:      "00:11:22:33:44:EE",
		SwitchSerialNumber: "UNMANAGED-UPDATE-456",
		Labels:             map[string]string{"env": "unmanaged"},
	})
	assert.Nil(t, err)
	assert.NotNil(t, unmanagedES)

	// Add mock temporal client for the site
	mockTemporalClient := &tmocks.Client{}
	mockWorkflowRun := &tmocks.WorkflowRun{}
	mockWorkflowRun.On("GetID").Return("test-workflow-id")
	mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Return(nil)
	mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "UpdateExpectedSwitch", mock.Anything).Return(mockWorkflowRun, nil)
	scp.IDClientMap[site.ID.String()] = mockTemporalClient

	handler := NewUpdateExpectedSwitchHandler(dbSession, scp, cfg)

	createMockUser := func(org string) *cdbm.User {
		return &cdbm.User{
			StarfleetID: cdb.GetStrPtr("test-user"),
			OrgData: cdbm.OrgData{
				org: cdbm.Org{
					ID:          123,
					Name:        org,
					DisplayName: org,
					OrgType:     "ENTERPRISE",
					Roles:       []string{authz.ProviderAdminRole},
				},
			},
		}
	}

	tests := []struct {
		name           string
		id             string
		requestBody    model.APIExpectedSwitchUpdateRequest
		setupContext   func(c echo.Context)
		expectedStatus int
	}{
		{
			name: "successful update",
			id:   testES.ID.String(),
			requestBody: model.APIExpectedSwitchUpdateRequest{
				SwitchSerialNumber: cdb.GetStrPtr("UPDATED-SWITCH-123"),
				Labels:             map[string]string{"env": "updated"},
			},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, testES.ID.String())
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "successful update with BmcIpAddress",
			id:   testES.ID.String(),
			requestBody: model.APIExpectedSwitchUpdateRequest{
				BmcIpAddress: cdb.GetStrPtr("192.168.1.42"),
			},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, testES.ID.String())
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "body ID mismatch with URL should return 400",
			id:   testES.ID.String(),
			requestBody: model.APIExpectedSwitchUpdateRequest{
				ID:                 cdb.GetStrPtr(uuid.New().String()),
				SwitchSerialNumber: cdb.GetStrPtr("SHOULD-NOT-UPDATE"),
			},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, testES.ID.String())
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "cannot update on unmanaged site",
			id:   unmanagedES.ID.String(),
			requestBody: model.APIExpectedSwitchUpdateRequest{
				SwitchSerialNumber: cdb.GetStrPtr("SHOULD-NOT-UPDATE"),
				Labels:             map[string]string{"env": "fail"},
			},
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, unmanagedES.ID.String())
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	_ = infraProv

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(tt.requestBody)
			url := "/v2/org/" + org + "/nico/expected-switch/" + tt.id
			req := httptest.NewRequest(http.MethodPatch, url, bytes.NewReader(reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req = req.WithContext(context.Background())

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			tt.setupContext(c)

			err := handler.Handle(c)

			assert.Nil(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != rec.Code {
				t.Errorf("Response: %v", rec.Body.String())
			}

			// Verify BmcIpAddress round-trips through the update response when set
			if tt.expectedStatus == http.StatusOK && tt.requestBody.BmcIpAddress != nil {
				var response model.APIExpectedSwitch
				err := json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Nil(t, err)
				if assert.NotNil(t, response.BmcIpAddress, "BmcIpAddress should not be nil in response") {
					assert.Equal(t, *tt.requestBody.BmcIpAddress, *response.BmcIpAddress, "BmcIpAddress in response should match request")
				}
			}
		})
	}
}

func TestDeleteExpectedSwitchHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testExpectedSwitchInitDB(t)
	defer dbSession.Close()

	ctx := context.Background()
	cfg := common.GetTestConfig()

	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	infraProv, site := testExpectedSwitchSetupTestData(t, dbSession, org)

	unmanagedIP := &cdbm.InfrastructureProvider{
		ID:   uuid.New(),
		Name: "unmanaged-provider",
		Org:  "other-org",
	}
	_, err := dbSession.DB.NewInsert().Model(unmanagedIP).Exec(ctx)
	assert.Nil(t, err)

	unmanagedSite := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "unmanaged-site",
		Org:                      "other-org",
		InfrastructureProviderID: unmanagedIP.ID,
		Status:                   cdbm.SiteStatusRegistered,
	}
	_, err = dbSession.DB.NewInsert().Model(unmanagedSite).Exec(ctx)
	assert.Nil(t, err)

	// Create a test ExpectedSwitch on managed site (to be deleted)
	esDAO := cdbm.NewExpectedSwitchDAO(dbSession)
	testES, err := esDAO.Create(ctx, nil, cdbm.ExpectedSwitchCreateInput{
		ExpectedSwitchID:   uuid.New(),
		SiteID:             site.ID,
		BmcMacAddress:      "00:11:22:33:44:FF",
		SwitchSerialNumber: "DELETE-SWITCH-123",
	})
	assert.Nil(t, err)
	assert.NotNil(t, testES)

	// Create a test ExpectedSwitch on unmanaged site (should not be deletable)
	unmanagedES, err := esDAO.Create(ctx, nil, cdbm.ExpectedSwitchCreateInput{
		ExpectedSwitchID:   uuid.New(),
		SiteID:             unmanagedSite.ID,
		BmcMacAddress:      "00:11:22:33:55:00",
		SwitchSerialNumber: "UNMANAGED-DELETE-456",
	})
	assert.Nil(t, err)
	assert.NotNil(t, unmanagedES)

	// Add mock temporal client for the site
	mockTemporalClient := &tmocks.Client{}
	mockWorkflowRun := &tmocks.WorkflowRun{}
	mockWorkflowRun.On("GetID").Return("test-workflow-id")
	mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Return(nil)
	mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "DeleteExpectedSwitch", mock.Anything).Return(mockWorkflowRun, nil)
	scp.IDClientMap[site.ID.String()] = mockTemporalClient

	handler := NewDeleteExpectedSwitchHandler(dbSession, scp, cfg)

	createMockUser := func(org string) *cdbm.User {
		return &cdbm.User{
			StarfleetID: cdb.GetStrPtr("test-user"),
			OrgData: cdbm.OrgData{
				org: cdbm.Org{
					ID:          123,
					Name:        org,
					DisplayName: org,
					OrgType:     "ENTERPRISE",
					Roles:       []string{authz.ProviderAdminRole},
				},
			},
		}
	}

	tests := []struct {
		name           string
		id             string
		setupContext   func(c echo.Context)
		expectedStatus int
	}{
		{
			name: "successful delete",
			id:   testES.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, testES.ID.String())
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name: "cannot delete on unmanaged site",
			id:   unmanagedES.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, unmanagedES.ID.String())
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	_ = infraProv

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/v2/org/" + org + "/nico/expected-switch/" + tt.id
			req := httptest.NewRequest(http.MethodDelete, url, nil)
			req = req.WithContext(context.Background())

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			tt.setupContext(c)

			err := handler.Handle(c)

			assert.Nil(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != rec.Code {
				t.Errorf("Response: %v", rec.Body.String())
			}
		})
	}
}
