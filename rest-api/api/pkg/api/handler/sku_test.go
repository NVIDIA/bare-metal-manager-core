// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/api/internal/config"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	authz "github.com/NVIDIA/infra-controller-rest/auth/pkg/authorization"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbu "github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun/extra/bundebug"
)

// testSkuInitDB initializes a test database session (pattern from tenant_test.go)
func testSkuInitDB(t *testing.T) *cdb.Session {
	dbSession := cdbu.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("BUNDEBUG"),
	))
	return dbSession
}

// testSkuSetupSchema resets the required tables for SKU tests (pattern from tenant_test.go)
func testSkuSetupSchema(t *testing.T, dbSession *cdb.Session) {
	ctx := context.Background()

	// Reset child tables first
	err := dbSession.DB.ResetModel(ctx, (*cdbm.TenantAccount)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.SKU)(nil))
	assert.Nil(t, err)

	// Reset parent tables
	err = dbSession.DB.ResetModel(ctx, (*cdbm.Tenant)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.Site)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(ctx, (*cdbm.InfrastructureProvider)(nil))
	assert.Nil(t, err)
}

// testSkuSetupTestData creates test infrastructure provider, site, and SKUs
func testSkuSetupTestData(t *testing.T, dbSession *cdb.Session, org string) (*cdbm.InfrastructureProvider, *cdbm.Site, *cdbm.SKU, *cdbm.SKU) {
	ctx := context.Background()

	// Create infrastructure provider
	ip := &cdbm.InfrastructureProvider{
		ID:   uuid.New(),
		Name: "test-provider",
		Org:  org,
	}
	_, err := dbSession.DB.NewInsert().Model(ip).Exec(ctx)
	assert.Nil(t, err)

	// Create site
	site := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site",
		Org:                      org,
		InfrastructureProviderID: ip.ID,
		Status:                   cdbm.SiteStatusRegistered,
	}
	_, err = dbSession.DB.NewInsert().Model(site).Exec(ctx)
	assert.Nil(t, err)

	// Create test SKUs
	deviceType1 := "gpu-server"
	sku1 := &cdbm.SKU{
		ID:                   "test-sku-1",
		SiteID:               site.ID,
		DeviceType:           &deviceType1,
		AssociatedMachineIds: []string{"machine-1", "machine-2"},
	}
	_, err = dbSession.DB.NewInsert().Model(sku1).Exec(ctx)
	assert.Nil(t, err)

	deviceType2 := "cpu-server"
	sku2 := &cdbm.SKU{
		ID:                   "test-sku-2",
		SiteID:               site.ID,
		DeviceType:           &deviceType2,
		AssociatedMachineIds: []string{"machine-3"},
	}
	_, err = dbSession.DB.NewInsert().Model(sku2).Exec(ctx)
	assert.Nil(t, err)

	return ip, site, sku1, sku2
}

func TestGetAllSkuHandler_Handle(t *testing.T) {
	// Setup
	e := echo.New()
	dbSession := testSkuInitDB(t)
	defer dbSession.Close()

	testSkuSetupSchema(t, dbSession)

	ctx := context.Background()
	cfg := &config.Config{}
	handler := NewGetAllSkuHandler(dbSession, nil, cfg)

	org := "test-org"
	infraProv, site, sku1, sku2 := testSkuSetupTestData(t, dbSession, org)

	// Create an unmanaged site
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

	// Create SKU on unmanaged site
	deviceType := "storage-server"
	unmanagedSku := &cdbm.SKU{
		ID:         "unmanaged-sku",
		SiteID:     unmanagedSite.ID,
		DeviceType: &deviceType,
	}
	_, err = dbSession.DB.NewInsert().Model(unmanagedSku).Exec(ctx)
	assert.Nil(t, err)

	// Helper function to create mock user with provider role
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

	// Helper function to create mock user with tenant role
	createTenantMockUser := func(org string) *cdbm.User {
		return &cdbm.User{
			StarfleetID: cdb.GetStrPtr("test-tenant-user"),
			OrgData: cdbm.OrgData{
				org: cdbm.Org{
					ID:          456,
					Name:        org,
					DisplayName: org,
					OrgType:     "ENTERPRISE",
					Roles:       []string{authz.TenantAdminRole},
				},
			},
		}
	}

	// Create tenant with TargetedInstanceCreation capability
	tenantOrg := "test-tenant-org"
	tenantWithCapability := &cdbm.Tenant{
		ID:   uuid.New(),
		Name: "test-tenant",
		Org:  tenantOrg,
		Config: &cdbm.TenantConfig{
			TargetedInstanceCreation: true,
		},
	}
	_, err = dbSession.DB.NewInsert().Model(tenantWithCapability).Exec(ctx)
	assert.Nil(t, err)

	// Create tenant account linking tenant to infrastructure provider
	tenantAccount := &cdbm.TenantAccount{
		ID:                       uuid.New(),
		AccountNumber:            "test-account-123",
		TenantID:                 &tenantWithCapability.ID,
		TenantOrg:                tenantOrg,
		InfrastructureProviderID: infraProv.ID,
		Status:                   "active",
	}
	_, err = dbSession.DB.NewInsert().Model(tenantAccount).Exec(ctx)
	assert.Nil(t, err)

	// Create tenant WITHOUT TargetedInstanceCreation capability
	tenantOrgNoCapability := "test-tenant-org-no-capability"
	tenantWithoutCapability := &cdbm.Tenant{
		ID:   uuid.New(),
		Name: "test-tenant-no-capability",
		Org:  tenantOrgNoCapability,
		Config: &cdbm.TenantConfig{
			TargetedInstanceCreation: false,
		},
	}
	_, err = dbSession.DB.NewInsert().Model(tenantWithoutCapability).Exec(ctx)
	assert.Nil(t, err)

	// Create tenant with capability but NO tenant account
	tenantOrgNoAccount := "test-tenant-org-no-account"
	tenantWithoutAccount := &cdbm.Tenant{
		ID:   uuid.New(),
		Name: "test-tenant-no-account",
		Org:  tenantOrgNoAccount,
		Config: &cdbm.TenantConfig{
			TargetedInstanceCreation: true,
		},
	}
	_, err = dbSession.DB.NewInsert().Model(tenantWithoutAccount).Exec(ctx)
	assert.Nil(t, err)

	tests := []struct {
		name                 string
		siteId               string
		setupContext         func(c echo.Context)
		expectedStatus       int
		checkResponseContent func(t *testing.T, body []byte)
	}{
		{
			name:   "missing siteId returns bad request",
			siteId: "",
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusBadRequest,
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return bad request error
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
				var response []model.APISku
				err := json.Unmarshal(body, &response)
				assert.Nil(t, err)
				// Should return the 2 managed SKUs from the specified site
				assert.Len(t, response, 2)
				// Verify we get results from the specified site only
				for _, sku := range response {
					assert.Equal(t, site.ID.String(), sku.SiteID, "All results should be from the specified site")
					assert.NotEqual(t, unmanagedSku.ID, sku.ID, "Unmanaged SKU should not be in response")
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
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return forbidden error
			},
		},
		{
			name:   "missing user context",
			siteId: "",
			setupContext: func(c echo.Context) {
				// Don't set user in context - should cause error
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return internal server error
			},
		},
		{
			name:   "tenant with TargetedInstanceCreation capability can retrieve SKUs",
			siteId: site.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createTenantMockUser(tenantOrg))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrg)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []model.APISku
				err := json.Unmarshal(body, &response)
				assert.Nil(t, err)
				assert.Len(t, response, 2)
				for _, sku := range response {
					assert.Equal(t, site.ID.String(), sku.SiteID)
				}
			},
		},
		{
			name:   "tenant without TargetedInstanceCreation capability is denied",
			siteId: site.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createTenantMockUser(tenantOrgNoCapability))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrgNoCapability)
			},
			expectedStatus: http.StatusForbidden,
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return forbidden error
			},
		},
		{
			name:   "tenant without TenantAccount with Provider is denied",
			siteId: site.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createTenantMockUser(tenantOrgNoAccount))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrgNoAccount)
			},
			expectedStatus: http.StatusForbidden,
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return forbidden error
			},
		},
	}

	_ = infraProv               // Ensure infraProv is used to avoid compiler warning
	_ = sku1                    // Ensure sku1 is used to avoid compiler warning
	_ = sku2                    // Ensure sku2 is used to avoid compiler warning
	_ = tenantAccount           // Ensure tenantAccount is used to avoid compiler warning
	_ = tenantWithoutCapability // Ensure tenantWithoutCapability is used to avoid compiler warning
	_ = tenantWithoutAccount    // Ensure tenantWithoutAccount is used to avoid compiler warning

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/v2/org/" + org + "/nico/sku"
			if tt.siteId != "" {
				url += "?siteId=" + tt.siteId
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req = req.WithContext(context.Background())

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Setup context
			tt.setupContext(c)

			// Execute
			err := handler.Handle(c)

			// Assert
			assert.Nil(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != rec.Code {
				t.Errorf("Response: %v", rec.Body.String())
			}

			// Check response content if provided
			if tt.checkResponseContent != nil && rec.Code == http.StatusOK {
				tt.checkResponseContent(t, rec.Body.Bytes())
			}
		})
	}
}

func TestGetSkuHandler_Handle(t *testing.T) {
	// Setup
	e := echo.New()
	dbSession := testSkuInitDB(t)
	defer dbSession.Close()

	testSkuSetupSchema(t, dbSession)

	ctx := context.Background()

	cfg := &config.Config{}
	handler := NewGetSkuHandler(dbSession, nil, cfg)

	org := "test-org"
	infraProv, site, sku1, _ := testSkuSetupTestData(t, dbSession, org)

	// Create an unmanaged site
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

	// Create SKU on unmanaged site
	deviceType := "storage-server"
	unmanagedSku := &cdbm.SKU{
		ID:         "unmanaged-sku-get",
		SiteID:     unmanagedSite.ID,
		DeviceType: &deviceType,
	}
	_, err = dbSession.DB.NewInsert().Model(unmanagedSku).Exec(ctx)
	assert.Nil(t, err)

	// Helper function to create mock user with provider role
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

	// Helper function to create mock user with tenant role
	createTenantMockUser := func(org string) *cdbm.User {
		return &cdbm.User{
			StarfleetID: cdb.GetStrPtr("test-tenant-user"),
			OrgData: cdbm.OrgData{
				org: cdbm.Org{
					ID:          456,
					Name:        org,
					DisplayName: org,
					OrgType:     "ENTERPRISE",
					Roles:       []string{authz.TenantAdminRole},
				},
			},
		}
	}

	// Create tenant with TargetedInstanceCreation capability
	tenantOrg := "test-tenant-org"
	tenantWithCapability := &cdbm.Tenant{
		ID:   uuid.New(),
		Name: "test-tenant",
		Org:  tenantOrg,
		Config: &cdbm.TenantConfig{
			TargetedInstanceCreation: true,
		},
	}
	_, err = dbSession.DB.NewInsert().Model(tenantWithCapability).Exec(ctx)
	assert.Nil(t, err)

	// Create tenant account linking tenant to infrastructure provider
	tenantAccount := &cdbm.TenantAccount{
		ID:                       uuid.New(),
		AccountNumber:            "test-account-456",
		TenantID:                 &tenantWithCapability.ID,
		TenantOrg:                tenantOrg,
		InfrastructureProviderID: infraProv.ID,
		Status:                   "active",
	}
	_, err = dbSession.DB.NewInsert().Model(tenantAccount).Exec(ctx)
	assert.Nil(t, err)

	// Create tenant WITHOUT TargetedInstanceCreation capability
	tenantOrgNoCapability := "test-tenant-org-no-capability"
	tenantWithoutCapability := &cdbm.Tenant{
		ID:   uuid.New(),
		Name: "test-tenant-no-capability",
		Org:  tenantOrgNoCapability,
		Config: &cdbm.TenantConfig{
			TargetedInstanceCreation: false,
		},
	}
	_, err = dbSession.DB.NewInsert().Model(tenantWithoutCapability).Exec(ctx)
	assert.Nil(t, err)

	// Create tenant with capability but NO tenant account
	tenantOrgNoAccount := "test-tenant-org-no-account"
	tenantWithoutAccount := &cdbm.Tenant{
		ID:   uuid.New(),
		Name: "test-tenant-no-account",
		Org:  tenantOrgNoAccount,
		Config: &cdbm.TenantConfig{
			TargetedInstanceCreation: true,
		},
	}
	_, err = dbSession.DB.NewInsert().Model(tenantWithoutAccount).Exec(ctx)
	assert.Nil(t, err)

	tests := []struct {
		name                 string
		id                   string
		setupContext         func(c echo.Context)
		expectedStatus       int
		checkResponseContent func(t *testing.T, body []byte)
	}{
		{
			name: "successful retrieval",
			id:   sku1.ID,
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, sku1.ID)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response model.APISku
				err := json.Unmarshal(body, &response)
				assert.Nil(t, err)
				assert.Equal(t, sku1.ID, response.ID, "SKU ID should match")
				assert.Equal(t, site.ID.String(), response.SiteID, "Site ID should match")
			},
		},
		{
			name: "SKU not found",
			id:   "non-existent-sku-id",
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, "non-existent-sku-id")
			},
			expectedStatus: http.StatusNotFound,
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return not found error
			},
		},
		{
			name: "cannot retrieve from unmanaged site",
			id:   unmanagedSku.ID,
			setupContext: func(c echo.Context) {
				c.Set("user", createMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, unmanagedSku.ID)
			},
			expectedStatus: http.StatusForbidden,
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return forbidden error
			},
		},
		{
			name: "missing user context",
			id:   sku1.ID,
			setupContext: func(c echo.Context) {
				// Don't set user in context - should cause error
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, sku1.ID)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return internal server error
			},
		},
		{
			name: "tenant with TargetedInstanceCreation capability can retrieve SKU",
			id:   sku1.ID,
			setupContext: func(c echo.Context) {
				c.Set("user", createTenantMockUser(tenantOrg))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(tenantOrg, sku1.ID)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response model.APISku
				err := json.Unmarshal(body, &response)
				assert.Nil(t, err)
				assert.Equal(t, sku1.ID, response.ID)
				assert.Equal(t, site.ID.String(), response.SiteID)
			},
		},
		{
			name: "tenant without TargetedInstanceCreation capability is denied",
			id:   sku1.ID,
			setupContext: func(c echo.Context) {
				c.Set("user", createTenantMockUser(tenantOrgNoCapability))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(tenantOrgNoCapability, sku1.ID)
			},
			expectedStatus: http.StatusForbidden,
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return forbidden error
			},
		},
		{
			name: "tenant without TenantAccount with Provider is denied",
			id:   sku1.ID,
			setupContext: func(c echo.Context) {
				c.Set("user", createTenantMockUser(tenantOrgNoAccount))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(tenantOrgNoAccount, sku1.ID)
			},
			expectedStatus: http.StatusForbidden,
			checkResponseContent: func(t *testing.T, body []byte) {
				// Should return forbidden error
			},
		},
	}

	_ = infraProv               // Ensure infraProv is used to avoid compiler warning
	_ = tenantAccount           // Ensure tenantAccount is used to avoid compiler warning
	_ = tenantWithoutCapability // Ensure tenantWithoutCapability is used to avoid compiler warning
	_ = tenantWithoutAccount    // Ensure tenantWithoutAccount is used to avoid compiler warning

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/v2/org/" + org + "/nico/sku/" + tt.id
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req = req.WithContext(context.Background())

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Setup context
			tt.setupContext(c)

			// Execute
			err := handler.Handle(c)

			// Assert
			assert.Nil(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != rec.Code {
				t.Errorf("Response: %v", rec.Body.String())
			}

			// Check response content if provided
			if tt.checkResponseContent != nil && rec.Code == http.StatusOK {
				tt.checkResponseContent(t, rec.Body.Bytes())
			}
		})
	}
}
