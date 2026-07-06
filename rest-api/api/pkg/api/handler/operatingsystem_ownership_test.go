// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
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

// buildRawIpxeProviderOS creates a provider-owned raw iPXE OS (no site
// associations) via the DAO. Raw iPXE avoids any post-commit site sync, so the
// write handlers exercise ownership enforcement without Temporal/proxy mocks.
func buildRawIpxeProviderOS(t *testing.T, ctx context.Context, osDAO cdbm.OperatingSystemDAO, org string, providerID uuid.UUID, name string, createdBy uuid.UUID) *cdbm.OperatingSystem {
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

func buildRawIpxeTenantOS(t *testing.T, ctx context.Context, osDAO cdbm.OperatingSystemDAO, org string, tenantID uuid.UUID, name string, createdBy uuid.UUID) *cdbm.OperatingSystem {
	os, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:        name,
		Description: cutil.GetPtr("test"),
		Org:         org,
		TenantID:    &tenantID,
		OsType:      cdbm.OperatingSystemTypeIPXE,
		IpxeScript:  cutil.GetPtr("ipxe"),
		Status:      cdbm.OperatingSystemStatusReady,
		CreatedBy:   createdBy,
	})
	require.NoError(t, err)
	require.NotNil(t, os)
	return os
}

// TestOperatingSystemHandler_Create_Ownership asserts that a Provider Admin may
// only create iPXE Template-based Operating Systems.
func TestOperatingSystemHandler_Create_Ownership(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()
	common.TestSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)
	tempClient := &tmocks.Client{}

	provOrg := "own-provider-org"
	provUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{provOrg}, []string{authz.ProviderAdminRole})
	testMachineBuildInfrastructureProvider(t, dbSession, provOrg, "own-ip")

	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		name           string
		reqBody        model.APIOperatingSystemCreateRequest
		expectedStatus int
	}{
		{
			name:           "provider admin cannot create image OS",
			reqBody:        model.APIOperatingSystemCreateRequest{Name: "prov-image", Description: cutil.GetPtr("test"), ImageURL: cutil.GetPtr("https://example.com/img.iso")},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "provider admin cannot create raw ipxe OS",
			reqBody:        model.APIOperatingSystemCreateRequest{Name: "prov-ipxe", Description: cutil.GetPtr("test"), IpxeScript: cutil.GetPtr("ipxe")},
			expectedStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.reqBody)
			require.NoError(t, err)

			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(provOrg)
			ec.Set("user", provUser)
			ec.SetRequest(ec.Request().WithContext(context.WithValue(ctx, otelecho.TracerKey, tracer)))

			ch := CreateOperatingSystemHandler{dbSession: dbSession, tc: tempClient, cfg: cfg, scp: scp}
			require.NoError(t, ch.Handle(ec))
			require.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

// TestOperatingSystemHandler_Update_Ownership asserts ownership enforcement for
// updates across provider and tenant roles.
func TestOperatingSystemHandler_Update_Ownership(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()
	common.TestSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)
	tempClient := &tmocks.Client{}
	osDAO := cdbm.NewOperatingSystemDAO(dbSession)

	provOrg := "own-provider-org"
	provUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{provOrg}, []string{authz.ProviderAdminRole})
	ip := testMachineBuildInfrastructureProvider(t, dbSession, provOrg, "own-ip")
	provOS := buildRawIpxeProviderOS(t, ctx, osDAO, provOrg, ip.ID, "prov-os-update", provUser.ID)

	sharedOrg := "own-shared-org"
	tnUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{sharedOrg}, []string{authz.TenantAdminRole})
	sharedProvUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{sharedOrg}, []string{authz.ProviderAdminRole})
	ip2 := testMachineBuildInfrastructureProvider(t, dbSession, sharedOrg, "own-ip-2")
	tn := testMachineBuildTenant(t, dbSession, sharedOrg, "own-tenant")
	provOSShared := buildRawIpxeProviderOS(t, ctx, osDAO, sharedOrg, ip2.ID, "prov-os-shared-update", sharedProvUser.ID)
	tnOS := buildRawIpxeTenantOS(t, ctx, osDAO, sharedOrg, tn.ID, "tenant-os-update", tnUser.ID)

	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		name           string
		reqOrgName     string
		user           *cdbm.User
		os             *cdbm.OperatingSystem
		expectedStatus int
	}{
		{
			name:           "provider admin updates own provider OS",
			reqOrgName:     provOrg,
			user:           provUser,
			os:             provOS,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "tenant admin cannot update provider-owned OS",
			reqOrgName:     sharedOrg,
			user:           tnUser,
			os:             provOSShared,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "provider admin cannot update tenant-owned OS",
			reqOrgName:     sharedOrg,
			user:           sharedProvUser,
			os:             tnOS,
			expectedStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(model.APIOperatingSystemUpdateRequest{Description: cutil.GetPtr("updated description")})
			require.NoError(t, err)

			e := echo.New()
			req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(string(body)))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tc.reqOrgName, tc.os.ID.String())
			ec.Set("user", tc.user)
			ec.SetRequest(ec.Request().WithContext(context.WithValue(ctx, otelecho.TracerKey, tracer)))

			uh := UpdateOperatingSystemHandler{dbSession: dbSession, tc: tempClient, cfg: cfg, scp: scp}
			require.NoError(t, uh.Handle(ec))
			require.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

// TestOperatingSystemHandler_Delete_Ownership asserts ownership enforcement for
// deletes across provider and tenant roles.
func TestOperatingSystemHandler_Delete_Ownership(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()
	common.TestSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)
	tempClient := &tmocks.Client{}
	osDAO := cdbm.NewOperatingSystemDAO(dbSession)

	provOrg := "own-provider-org"
	provUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{provOrg}, []string{authz.ProviderAdminRole})
	ip := testMachineBuildInfrastructureProvider(t, dbSession, provOrg, "own-ip")
	provOS := buildRawIpxeProviderOS(t, ctx, osDAO, provOrg, ip.ID, "prov-os-delete", provUser.ID)

	sharedOrg := "own-shared-org"
	tnUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{sharedOrg}, []string{authz.TenantAdminRole})
	sharedProvUser := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{sharedOrg}, []string{authz.ProviderAdminRole})
	ip2 := testMachineBuildInfrastructureProvider(t, dbSession, sharedOrg, "own-ip-2")
	tn := testMachineBuildTenant(t, dbSession, sharedOrg, "own-tenant")
	provOSShared := buildRawIpxeProviderOS(t, ctx, osDAO, sharedOrg, ip2.ID, "prov-os-shared-delete", sharedProvUser.ID)
	tnOS := buildRawIpxeTenantOS(t, ctx, osDAO, sharedOrg, tn.ID, "tenant-os-delete", tnUser.ID)

	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		name           string
		reqOrgName     string
		user           *cdbm.User
		os             *cdbm.OperatingSystem
		expectedStatus int
	}{
		{
			name:           "tenant admin cannot delete provider-owned OS",
			reqOrgName:     sharedOrg,
			user:           tnUser,
			os:             provOSShared,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "provider admin cannot delete tenant-owned OS",
			reqOrgName:     sharedOrg,
			user:           sharedProvUser,
			os:             tnOS,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "provider admin deletes own provider OS",
			reqOrgName:     provOrg,
			user:           provUser,
			os:             provOS,
			expectedStatus: http.StatusAccepted,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodDelete, "/", nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tc.reqOrgName, tc.os.ID.String())
			ec.Set("user", tc.user)
			ec.SetRequest(ec.Request().WithContext(context.WithValue(ctx, otelecho.TracerKey, tracer)))

			dh := DeleteOperatingSystemHandler{dbSession: dbSession, tc: tempClient, cfg: cfg, scp: scp}
			require.NoError(t, dh.Handle(ec))
			require.Equal(t, tc.expectedStatus, rec.Code)
			assert.NotEqual(t, "", tc.name)
		})
	}
}
