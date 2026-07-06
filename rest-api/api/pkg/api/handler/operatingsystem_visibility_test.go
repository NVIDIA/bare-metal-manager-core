// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/otelecho"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tmocks "go.temporal.io/sdk/mocks"
)

// buildProviderOS creates a provider-owned OS (no tenant) for the given provider.
func buildProviderOS(t *testing.T, ctx context.Context, osDAO cdbm.OperatingSystemDAO, org string, providerID uuid.UUID, name string, createdBy uuid.UUID) *cdbm.OperatingSystem {
	os, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:                     name,
		Description:              cutil.GetPtr("test"),
		Org:                      org,
		InfrastructureProviderID: &providerID,
		OsType:                   cdbm.OperatingSystemTypeIPXE,
		IpxeScript:               cutil.GetPtr("ipxe"),
		Status:                   cdbm.OperatingSystemStatusReady,
		CreatedBy:                createdBy,
	})
	require.NoError(t, err)
	require.NotNil(t, os)
	return os
}

// buildTenantOS creates a tenant-owned OS for the given tenant.
func buildTenantOS(t *testing.T, ctx context.Context, osDAO cdbm.OperatingSystemDAO, org string, tenantID uuid.UUID, name string, createdBy uuid.UUID) *cdbm.OperatingSystem {
	os, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:          name,
		Description:   cutil.GetPtr("test"),
		Org:           org,
		TenantID:      &tenantID,
		OsType:        cdbm.OperatingSystemTypeIPXE,
		IpxeScript:    cutil.GetPtr("ipxe"),
		Status:        cdbm.OperatingSystemStatusReady,
		CreatedBy:     createdBy,
		AllowOverride: false,
	})
	require.NoError(t, err)
	require.NotNil(t, os)
	return os
}

// TestOperatingSystemHandler_GetAll_Visibility exercises provider-admin listing
// and tenant cross-visibility of provider-owned OSes at accessible sites.
func TestOperatingSystemHandler_GetAll_Visibility(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()
	common.TestSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()
	tempClient := &tmocks.Client{}
	osDAO := cdbm.NewOperatingSystemDAO(dbSession)

	// Provider-only org.
	provOrg := "vis-provider-org"
	provUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{provOrg}, []string{authz.ProviderAdminRole})
	ip := testMachineBuildInfrastructureProvider(t, dbSession, provOrg, "vis-ip")
	siteA := testMachineBuildSite(t, dbSession, ip, "vis-site-a", cdbm.SiteStatusRegistered)
	siteB := testMachineBuildSite(t, dbSession, ip, "vis-site-b", cdbm.SiteStatusRegistered)

	provOSA := buildProviderOS(t, ctx, osDAO, provOrg, ip.ID, "prov-os-a", provUser.ID)
	common.TestBuildOperatingSystemSiteAssociation(t, dbSession, provOSA.ID, siteA.ID, cutil.GetPtr("test"), cdbm.OperatingSystemSiteAssociationStatusSynced, provUser)
	provOSB := buildProviderOS(t, ctx, osDAO, provOrg, ip.ID, "prov-os-b", provUser.ID)
	common.TestBuildOperatingSystemSiteAssociation(t, dbSession, provOSB.ID, siteB.ID, cutil.GetPtr("test"), cdbm.OperatingSystemSiteAssociationStatusSynced, provUser)

	// Shared org that owns both an infrastructure provider and a tenant. The
	// user is only a tenant admin; provider-owned entries become visible only
	// when associated with a site the tenant can access.
	sharedOrg := "vis-shared-org"
	tnUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{sharedOrg}, []string{authz.TenantAdminRole})
	ip2 := testMachineBuildInfrastructureProvider(t, dbSession, sharedOrg, "vis-ip-2")
	siteC := testMachineBuildSite(t, dbSession, ip2, "vis-site-c", cdbm.SiteStatusRegistered)
	siteD := testMachineBuildSite(t, dbSession, ip2, "vis-site-d", cdbm.SiteStatusRegistered)
	tn := testMachineBuildTenant(t, dbSession, sharedOrg, "vis-tenant")
	tsC := testBuildTenantSiteAssociation(t, dbSession, sharedOrg, tn.ID, siteC.ID, tnUser.ID)
	assert.NotNil(t, tsC)

	buildTenantOS(t, ctx, osDAO, sharedOrg, tn.ID, "tenant-os-1", tnUser.ID)
	buildTenantOS(t, ctx, osDAO, sharedOrg, tn.ID, "tenant-os-2", tnUser.ID)
	provC := buildProviderOS(t, ctx, osDAO, sharedOrg, ip2.ID, "prov-os-c", tnUser.ID)
	common.TestBuildOperatingSystemSiteAssociation(t, dbSession, provC.ID, siteC.ID, cutil.GetPtr("test"), cdbm.OperatingSystemSiteAssociationStatusSynced, tnUser)
	provD := buildProviderOS(t, ctx, osDAO, sharedOrg, ip2.ID, "prov-os-d", tnUser.ID)
	common.TestBuildOperatingSystemSiteAssociation(t, dbSession, provD.ID, siteD.ID, cutil.GetPtr("test"), cdbm.OperatingSystemSiteAssociationStatusSynced, tnUser)

	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		name          string
		reqOrgName    string
		user          *cdbm.User
		expectedNames []string
	}{
		{
			name:          "provider admin sees only provider-owned OSes",
			reqOrgName:    provOrg,
			user:          provUser,
			expectedNames: []string{"prov-os-a", "prov-os-b"},
		},
		{
			name:          "tenant admin sees own OSes plus provider OSes at accessible sites",
			reqOrgName:    sharedOrg,
			user:          tnUser,
			expectedNames: []string{"tenant-os-1", "tenant-os-2", "prov-os-c"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(tc.reqOrgName)
			ec.Set("user", tc.user)

			reqCtx := context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(reqCtx))

			mh := GetAllOperatingSystemHandler{dbSession: dbSession, tc: tempClient, cfg: cfg}
			err := mh.Handle(ec)
			assert.Nil(t, err)
			require.Equal(t, http.StatusOK, rec.Code)

			rsp := []model.APIOperatingSystem{}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rsp))
			gotNames := make([]string, len(rsp))
			for i, os := range rsp {
				gotNames[i] = os.Name
			}
			assert.ElementsMatch(t, tc.expectedNames, gotNames)
		})
	}
}

// TestOperatingSystemHandler_GetByID_Visibility exercises role-based access to a
// single OS: provider admins may only read provider-owned entries, tenant admins
// may read own entries plus provider entries at accessible sites.
func TestOperatingSystemHandler_GetByID_Visibility(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()
	common.TestSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()
	tempClient := &tmocks.Client{}
	osDAO := cdbm.NewOperatingSystemDAO(dbSession)

	provOrg := "vis-provider-org"
	provUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{provOrg}, []string{authz.ProviderAdminRole})
	ip := testMachineBuildInfrastructureProvider(t, dbSession, provOrg, "vis-ip")
	siteA := testMachineBuildSite(t, dbSession, ip, "vis-site-a", cdbm.SiteStatusRegistered)
	provOSA := buildProviderOS(t, ctx, osDAO, provOrg, ip.ID, "prov-os-a", provUser.ID)
	common.TestBuildOperatingSystemSiteAssociation(t, dbSession, provOSA.ID, siteA.ID, cutil.GetPtr("test"), cdbm.OperatingSystemSiteAssociationStatusSynced, provUser)

	sharedOrg := "vis-shared-org"
	tnUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{sharedOrg}, []string{authz.TenantAdminRole})
	sharedProvUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{sharedOrg}, []string{authz.ProviderAdminRole})
	ip2 := testMachineBuildInfrastructureProvider(t, dbSession, sharedOrg, "vis-ip-2")
	siteC := testMachineBuildSite(t, dbSession, ip2, "vis-site-c", cdbm.SiteStatusRegistered)
	siteD := testMachineBuildSite(t, dbSession, ip2, "vis-site-d", cdbm.SiteStatusRegistered)
	tn := testMachineBuildTenant(t, dbSession, sharedOrg, "vis-tenant")
	testBuildTenantSiteAssociation(t, dbSession, sharedOrg, tn.ID, siteC.ID, tnUser.ID)

	tnOS := buildTenantOS(t, ctx, osDAO, sharedOrg, tn.ID, "tenant-os-1", tnUser.ID)
	provC := buildProviderOS(t, ctx, osDAO, sharedOrg, ip2.ID, "prov-os-c", tnUser.ID)
	common.TestBuildOperatingSystemSiteAssociation(t, dbSession, provC.ID, siteC.ID, cutil.GetPtr("test"), cdbm.OperatingSystemSiteAssociationStatusSynced, tnUser)
	provD := buildProviderOS(t, ctx, osDAO, sharedOrg, ip2.ID, "prov-os-d", tnUser.ID)
	common.TestBuildOperatingSystemSiteAssociation(t, dbSession, provD.ID, siteD.ID, cutil.GetPtr("test"), cdbm.OperatingSystemSiteAssociationStatusSynced, tnUser)

	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		name           string
		reqOrgName     string
		user           *cdbm.User
		os             *cdbm.OperatingSystem
		expectedStatus int
	}{
		{
			name:           "provider admin can read provider-owned OS",
			reqOrgName:     provOrg,
			user:           provUser,
			os:             provOSA,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "tenant admin can read provider OS at accessible site",
			reqOrgName:     sharedOrg,
			user:           tnUser,
			os:             provC,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "tenant admin cannot read provider OS at inaccessible site",
			reqOrgName:     sharedOrg,
			user:           tnUser,
			os:             provD,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "tenant admin can read own OS",
			reqOrgName:     sharedOrg,
			user:           tnUser,
			os:             tnOS,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "provider admin cannot read tenant-owned OS",
			reqOrgName:     sharedOrg,
			user:           sharedProvUser,
			os:             tnOS,
			expectedStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tc.reqOrgName, tc.os.ID.String())
			ec.Set("user", tc.user)

			reqCtx := context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(reqCtx))

			gh := GetOperatingSystemHandler{dbSession: dbSession, tc: tempClient, cfg: cfg}
			err := gh.Handle(ec)
			assert.Nil(t, err)
			require.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}
