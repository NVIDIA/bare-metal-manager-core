/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file extends operatingsystem_test.go with tests that validate the
// ownership model (TenantID vs InfrastructureProviderID) and role-based
// access-control enforcement introduced alongside the bi-directional sync
// feature.  Each test function is self-contained and uses a fresh schema.
//
// Roles under test
//   - ipUser  — FORGE_PROVIDER_ADMIN only
//   - tnUser  — FORGE_TENANT_ADMIN only
//   - dualUser — both roles (either role may authorize the operation)
//
// Ownership invariants verified
//   - Provider Admin → InfrastructureProviderID set, TenantID nil
//   - Tenant Admin  → TenantID set, InfrastructureProviderID nil
//   - Dual-role     → permitted if either role authorizes the action;
//                      when both allow it, Provider Admin takes priority
//                      for ownership assignment
//
// Cross-ownership visibility (GetAll / GetByID)
//   - Provider Admin sees only provider-owned OSes (none from tenants).
//   - Tenant Admin sees own OSes + provider-owned OSes that have site
//     associations at sites accessible to the tenant.
//
// Mutation enforcement (Update / Delete)
//   - Provider Admin can mutate only provider-owned OSes.
//   - Tenant Admin can mutate only tenant-owned OSes.
//   - Dual-role user is permitted if either role authorizes the action.

package handler

import (
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/otelecho"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	tmocks "go.temporal.io/sdk/mocks"
)

// ─── shared setup helpers ────────────────────────────────────────────────────

// ownershipTestEnv contains all DB fixtures that the ownership-related tests
// share.  Each test function calls newOwnershipTestEnv and receives a freshly
// reset schema.
type ownershipTestEnv struct {
	dbSession *cdb.Session
	// Shared org that has both an InfrastructureProvider and a Tenant.
	// Users in this org can carry either or both roles.
	sharedOrg string
	ip        *cdbm.InfrastructureProvider
	tenant    *cdbm.Tenant
	site      *cdbm.Site // registered site belonging to ip

	// Users
	ipUser   *cdbm.User // FORGE_PROVIDER_ADMIN only
	tnUser   *cdbm.User // FORGE_TENANT_ADMIN only
	dualUser *cdbm.User // both roles

	// Temporal mocks (permissive — match any workflow invocation)
	tempClient *tmocks.Client
	scp        *sc.ClientPool
}

func newOwnershipTestEnv(t *testing.T) *ownershipTestEnv {
	t.Helper()

	dbSession := testMachineInitDB(t)
	t.Cleanup(func() { dbSession.Close() })
	common.TestSetupSchema(t, dbSession)

	sharedOrg := "shared-org"

	ip := testMachineBuildInfrastructureProvider(t, dbSession, sharedOrg, "shared-ip")
	require.NotNil(t, ip)

	tenant := testMachineBuildTenant(t, dbSession, sharedOrg, "shared-tenant")
	require.NotNil(t, tenant)

	site := testMachineBuildSite(t, dbSession, ip, "shared-site", cdbm.SiteStatusRegistered)
	require.NotNil(t, site)

	// TenantSite so tenant users can reference the site.
	tnu := testMachineBuildUser(t, dbSession, uuid.NewString(),
		[]string{sharedOrg}, []string{"FORGE_TENANT_ADMIN"})
	ts := testBuildTenantSiteAssociation(t, dbSession, sharedOrg, tenant.ID, site.ID, tnu.ID)
	require.NotNil(t, ts)

	ipUser := testMachineBuildUser(t, dbSession, uuid.NewString(),
		[]string{sharedOrg}, []string{"FORGE_PROVIDER_ADMIN"})
	dualUser := testMachineBuildUser(t, dbSession, uuid.NewString(),
		[]string{sharedOrg}, []string{"FORGE_PROVIDER_ADMIN", "FORGE_TENANT_ADMIN"})

	// Permissive Temporal mock: accepts any ExecuteWorkflow call so that tests
	// exercising the success path don't have to enumerate every signature.
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return("test-wf-id")
	wrun.On("Get", mock.Anything, mock.Anything).Return(nil)

	tempClient := &tmocks.Client{}
	tempClient.On("ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(wrun, nil)

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	// Per-site Temporal client (permissive).
	siteMock := &tmocks.Client{}
	siteMock.On("ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything).Return(wrun, nil)
	siteMock.On("TerminateWorkflow", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything).Return(nil)
	scp.IDClientMap[site.ID.String()] = siteMock

	return &ownershipTestEnv{
		dbSession:  dbSession,
		sharedOrg:  sharedOrg,
		ip:         ip,
		tenant:     tenant,
		site:       site,
		ipUser:     ipUser,
		tnUser:     tnu,
		dualUser:   dualUser,
		tempClient: tempClient,
		scp:        scp,
	}
}

// execCreateOS posts a Create request and returns the response recorder.
func (e *ownershipTestEnv) execCreateOS(t *testing.T, user *cdbm.User, body interface{}) *httptest.ResponseRecorder {
	t.Helper()

	rawBody, err := json.Marshal(body)
	require.NoError(t, err)

	tracer, traceCtx := otelTraceCtx(t)

	eh := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(rawBody)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	ec := eh.NewContext(req, rec)
	ec.SetParamNames("orgName")
	ec.SetParamValues(e.sharedOrg)
	ec.Set("user", user)
	ec.SetRequest(ec.Request().WithContext(
		context.WithValue(traceCtx, otelecho.TracerKey, tracer),
	))

	cfg := common.GetTestConfig()
	h := CreateOperatingSystemHandler{
		dbSession: e.dbSession,
		tc:        e.tempClient,
		cfg:       cfg,
		scp:       e.scp,
	}
	require.NoError(t, h.Handle(ec))
	return rec
}

// otelTraceCtx returns a no-op tracer and a context for use in handler tests.
func otelTraceCtx(t *testing.T) (interface{}, context.Context) {
	t.Helper()
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, context.Background())
	return tracer, ctx
}

// ─── Create: ownership assignment ────────────────────────────────────────────

// TestOperatingSystemHandler_Create_ProviderAndTenantOwnership verifies that
// the Create handler assigns ownership correctly based on the caller's role:
//
//   - Provider Admin → InfrastructureProviderID = provider's ID, TenantID = nil
//   - Tenant Admin   → TenantID = tenant's ID, InfrastructureProviderID = nil
//   - Dual-role user → permitted if either role authorizes the action;
//     when both allow it, provider ownership takes priority
//
// The test also covers the "new" iPXE OS type (template-based with parameters
// and artifacts) to ensure those fields round-trip correctly.
func TestOperatingSystemHandler_Create_ProviderAndTenantOwnership(t *testing.T) {
	env := newOwnershipTestEnv(t)

	ipxeScript := "ipxe-script-content"
	templateName := "raw-ipxe"
	scopeGlobal := cdbm.OperatingSystemScopeGlobal

	// template-based request reused for several sub-tests.
	templateBody := model.APIOperatingSystemCreateRequest{
		Name:           "tmpl-os-" + uuid.NewString(),
		IpxeTemplateId: &templateName,
		Scope:          &scopeGlobal,
		IpxeTemplateParameters: []cdbm.OperatingSystemIpxeParameter{
			{Name: "kernel_params", Value: "ip=dhcp"},
		},
		IpxeTemplateArtifacts: []cdbm.OperatingSystemIpxeArtifact{
			{Name: "kernel", URL: "http://files.example.com/vmlinuz", CacheStrategy: "CACHE_AS_NEEDED"},
		},
	}

	tests := []struct {
		name            string
		user            *cdbm.User
		body            model.APIOperatingSystemCreateRequest
		wantStatus      int
		wantProviderID  *uuid.UUID // nil means we don't assert
		wantTenantID    *uuid.UUID // nil means we don't assert
		wantProviderNil bool
		wantTenantNil   bool
	}{
		{
			name: "provider admin raw iPXE → forbidden (must use template)",
			user: env.ipUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:       "prov-ipxe-" + uuid.NewString(),
				IpxeScript: &ipxeScript,
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:           "provider admin template iPXE → provider-owned",
			user:           env.ipUser,
			body:           templateBody,
			wantStatus:     http.StatusCreated,
			wantProviderID: &env.ip.ID,
			wantTenantNil:  true,
		},
		{
			name: "tenant admin raw iPXE → tenant-owned",
			user: env.tnUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:       "tn-ipxe-" + uuid.NewString(),
				IpxeScript: &ipxeScript,
			},
			wantStatus:      http.StatusCreated,
			wantTenantID:    &env.tenant.ID,
			wantProviderNil: true,
		},
		{
			name: "tenant admin template iPXE → tenant-owned",
			user: env.tnUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:           "tn-tmpl-" + uuid.NewString(),
				IpxeTemplateId: &templateName,
				Scope:          &scopeGlobal,
				IpxeTemplateParameters: []cdbm.OperatingSystemIpxeParameter{
					{Name: "kernel_params", Value: "ip=dhcp"},
				},
				IpxeTemplateArtifacts: []cdbm.OperatingSystemIpxeArtifact{
					{Name: "kernel", URL: "http://files.example.com/vmlinuz", CacheStrategy: "CACHE_AS_NEEDED"},
				},
			},
			wantStatus:      http.StatusCreated,
			wantTenantID:    &env.tenant.ID,
			wantProviderNil: true,
		},
		{
			name: "dual-role user raw iPXE → tenant-owned (tenant role authorizes)",
			user: env.dualUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:       "dual-ipxe-" + uuid.NewString(),
				IpxeScript: &ipxeScript,
			},
			wantStatus:      http.StatusCreated,
			wantTenantID:    &env.tenant.ID,
			wantProviderNil: true,
		},
		{
			name: "dual-role user template iPXE → provider-owned",
			user: env.dualUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:           "dual-tmpl-" + uuid.NewString(),
				IpxeTemplateId: &templateName,
				Scope:          &scopeGlobal,
				IpxeTemplateParameters: []cdbm.OperatingSystemIpxeParameter{
					{Name: "kernel_params", Value: "ip=dhcp"},
				},
				IpxeTemplateArtifacts: []cdbm.OperatingSystemIpxeArtifact{
					{Name: "kernel", URL: "http://files.example.com/vmlinuz", CacheStrategy: "CACHE_AS_NEEDED"},
				},
			},
			wantStatus:     http.StatusCreated,
			wantProviderID: &env.ip.ID,
			wantTenantNil:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.execCreateOS(t, tc.user, tc.body)
			assert.Equal(t, tc.wantStatus, rec.Code, "response body: %s", rec.Body.String())
			if rec.Code != http.StatusCreated {
				return
			}

			var rsp model.APIOperatingSystem
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rsp))

			if tc.wantProviderID != nil {
				require.NotNil(t, rsp.InfrastructureProviderID,
					"expected InfrastructureProviderID to be set")
				assert.Equal(t, tc.wantProviderID.String(), *rsp.InfrastructureProviderID)
			}
			if tc.wantProviderNil {
				assert.Nil(t, rsp.InfrastructureProviderID,
					"expected InfrastructureProviderID to be nil")
			}
			if tc.wantTenantID != nil {
				require.NotNil(t, rsp.TenantID, "expected TenantID to be set")
				assert.Equal(t, tc.wantTenantID.String(), *rsp.TenantID)
			}
			if tc.wantTenantNil {
				assert.Nil(t, rsp.TenantID, "expected TenantID to be nil")
			}

			// Verify iPXE parameters and artifacts round-trip for template OS.
			if tc.body.IpxeTemplateId != nil {
				assert.Equal(t, tc.body.IpxeTemplateId, rsp.IpxeTemplateId)
				if len(tc.body.IpxeTemplateParameters) > 0 {
					require.Len(t, rsp.IpxeTemplateParameters, len(tc.body.IpxeTemplateParameters))
					assert.Equal(t, tc.body.IpxeTemplateParameters[0].Name, rsp.IpxeTemplateParameters[0].Name)
				}
				if len(tc.body.IpxeTemplateArtifacts) > 0 {
					require.Len(t, rsp.IpxeTemplateArtifacts, len(tc.body.IpxeTemplateArtifacts))
					assert.Equal(t, tc.body.IpxeTemplateArtifacts[0].Name, rsp.IpxeTemplateArtifacts[0].Name)
					assert.Equal(t, tc.body.IpxeTemplateArtifacts[0].URL, rsp.IpxeTemplateArtifacts[0].URL)
				}
			}
		})
	}
}

// ─── GetAll: cross-ownership visibility ──────────────────────────────────────

// TestOperatingSystemHandler_GetAll_CrossOwnership verifies role-based
// visibility rules:
//   - Provider Admin sees only provider-owned OSes.
//   - Tenant Admin sees own OSes + provider-owned OSes at accessible sites.
//   - Dual-role user sees the union.
func TestOperatingSystemHandler_GetAll_CrossOwnership(t *testing.T) {
	env := newOwnershipTestEnv(t)
	ctx := context.Background()

	osDAO := cdbm.NewOperatingSystemDAO(env.dbSession)

	// Seed one provider-owned OS with a site association so the tenant can see it.
	provOS, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:                     "synced-from-core",
		Org:                      env.sharedOrg,
		TenantID:                 nil,
		InfrastructureProviderID: &env.ip.ID,
		OsType:                   cdbm.OperatingSystemTypeIPXE,
		IpxeScript:               cutil.GetPtr("#!ipxe\nchain http://boot.example.com"),
		IpxeOsScope:              cutil.GetPtr(cdbm.OperatingSystemScopeLocal),
		Status:                   cdbm.OperatingSystemStatusReady,
		CreatedBy:                env.ipUser.ID,
	})
	require.NoError(t, err)

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(env.dbSession)
	_, err = ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
		OperatingSystemID: provOS.ID,
		SiteID:            env.site.ID,
		Status:            cdbm.OperatingSystemSiteAssociationStatusSynced,
	})
	require.NoError(t, err)

	// Seed one tenant-owned OS.
	tnOS, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:        "tenant-os",
		Org:         env.sharedOrg,
		TenantID:    &env.tenant.ID,
		OsType:      cdbm.OperatingSystemTypeIPXE,
		IpxeScript:  cutil.GetPtr("#!ipxe\nboot"),
		IpxeOsScope: cutil.GetPtr(cdbm.OperatingSystemScopeGlobal),
		Status:      cdbm.OperatingSystemStatusReady,
		CreatedBy:   env.tnUser.ID,
	})
	require.NoError(t, err)

	execGetAll := func(t *testing.T, user *cdbm.User) []model.APIOperatingSystem {
		t.Helper()
		tracer, ctx := otelTraceCtx(t)

		eh := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		ec := eh.NewContext(req, rec)
		ec.SetParamNames("orgName")
		ec.SetParamValues(env.sharedOrg)
		ec.Set("user", user)
		ec.SetRequest(ec.Request().WithContext(
			context.WithValue(ctx, otelecho.TracerKey, tracer),
		))

		cfg := common.GetTestConfig()
		h := GetAllOperatingSystemHandler{
			dbSession: env.dbSession,
			tc:        env.tempClient,
			cfg:       cfg,
		}
		require.NoError(t, h.Handle(ec))
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var rsp []model.APIOperatingSystem
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rsp))
		return rsp
	}

	t.Run("provider admin sees only provider-owned OS", func(t *testing.T) {
		oss := execGetAll(t, env.ipUser)
		ids := make([]string, len(oss))
		for i, o := range oss {
			ids[i] = o.ID
		}
		assert.Contains(t, ids, provOS.ID.String())
		assert.NotContains(t, ids, tnOS.ID.String(), "provider admin must not see tenant-owned OS")
	})

	t.Run("tenant admin sees own and provider-owned OS at accessible site", func(t *testing.T) {
		oss := execGetAll(t, env.tnUser)
		assert.GreaterOrEqual(t, len(oss), 2)
		ids := make([]string, len(oss))
		for i, o := range oss {
			ids[i] = o.ID
		}
		assert.Contains(t, ids, provOS.ID.String(), "tenant should see provider OS at accessible site")
		assert.Contains(t, ids, tnOS.ID.String())
	})

	t.Run("dual-role user sees both provider-owned and tenant-owned OSes", func(t *testing.T) {
		oss := execGetAll(t, env.dualUser)
		assert.GreaterOrEqual(t, len(oss), 2)
	})
}

// ─── GetByID: cross-ownership visibility ─────────────────────────────────────

// TestOperatingSystemHandler_GetByID_CrossOwnership verifies role-based
// visibility for individual OS fetches:
//   - Provider Admin can fetch provider-owned OS, but NOT tenant-owned.
//   - Tenant Admin can fetch own OS + provider-owned OS at accessible sites.
func TestOperatingSystemHandler_GetByID_CrossOwnership(t *testing.T) {
	env := newOwnershipTestEnv(t)
	ctx := context.Background()

	osDAO := cdbm.NewOperatingSystemDAO(env.dbSession)

	// Provider-owned OS with site association (visible to tenant via site).
	provOS, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:                     "prov-single",
		Org:                      env.sharedOrg,
		TenantID:                 nil,
		InfrastructureProviderID: &env.ip.ID,
		OsType:                   cdbm.OperatingSystemTypeIPXE,
		IpxeScript:               cutil.GetPtr("#!ipxe"),
		IpxeOsScope:              cutil.GetPtr(cdbm.OperatingSystemScopeLocal),
		Status:                   cdbm.OperatingSystemStatusReady,
		CreatedBy:                env.ipUser.ID,
	})
	require.NoError(t, err)

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(env.dbSession)
	_, err = ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
		OperatingSystemID: provOS.ID,
		SiteID:            env.site.ID,
		Status:            cdbm.OperatingSystemSiteAssociationStatusSynced,
	})
	require.NoError(t, err)

	tnOS, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:        "tenant-single",
		Org:         env.sharedOrg,
		TenantID:    &env.tenant.ID,
		OsType:      cdbm.OperatingSystemTypeIPXE,
		IpxeScript:  cutil.GetPtr("#!ipxe"),
		IpxeOsScope: cutil.GetPtr(cdbm.OperatingSystemScopeGlobal),
		Status:      cdbm.OperatingSystemStatusReady,
		CreatedBy:   env.tnUser.ID,
	})
	require.NoError(t, err)

	execGetByID := func(t *testing.T, user *cdbm.User, osID string) *httptest.ResponseRecorder {
		t.Helper()
		tracer, ctx := otelTraceCtx(t)

		eh := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		ec := eh.NewContext(req, rec)
		ec.SetParamNames("orgName", "id")
		ec.SetParamValues(env.sharedOrg, osID)
		ec.Set("user", user)
		ec.SetRequest(ec.Request().WithContext(
			context.WithValue(ctx, otelecho.TracerKey, tracer),
		))

		cfg := common.GetTestConfig()
		h := GetOperatingSystemHandler{
			dbSession: env.dbSession,
			tc:        env.tempClient,
			cfg:       cfg,
		}
		require.NoError(t, h.Handle(ec))
		return rec
	}

	t.Run("provider admin gets provider-owned OS", func(t *testing.T) {
		rec := execGetByID(t, env.ipUser, provOS.ID.String())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("tenant admin gets provider-owned OS at accessible site", func(t *testing.T) {
		rec := execGetByID(t, env.tnUser, provOS.ID.String())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("provider admin cannot get tenant-owned OS", func(t *testing.T) {
		rec := execGetByID(t, env.ipUser, tnOS.ID.String())
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	})

	t.Run("tenant admin gets tenant-owned OS", func(t *testing.T) {
		rec := execGetByID(t, env.tnUser, tnOS.ID.String())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("dual-role user gets provider-owned OS", func(t *testing.T) {
		rec := execGetByID(t, env.dualUser, provOS.ID.String())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
}

// ─── Update: role-based ownership enforcement ─────────────────────────────────

// TestOperatingSystemHandler_Update_OwnershipEnforcement exercises the Update
// handler's role-based mutation rules:
//
//   - Provider Admin can update only provider-owned OSes → 200 / 403
//   - Tenant Admin can update only tenant-owned OSes    → 200 / 403
//   - Dual-role user is permitted if either role authorizes the action
func TestOperatingSystemHandler_Update_OwnershipEnforcement(t *testing.T) {
	env := newOwnershipTestEnv(t)
	ctx := context.Background()

	osDAO := cdbm.NewOperatingSystemDAO(env.dbSession)

	// Provider-owned iPXE OS (no site associations → no Temporal calls needed).
	provOS, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:                     "prov-update-target",
		Org:                      env.sharedOrg,
		TenantID:                 nil,
		InfrastructureProviderID: &env.ip.ID,
		OsType:                   cdbm.OperatingSystemTypeIPXE,
		IpxeScript:               cutil.GetPtr("#!ipxe\nboot"),
		Status:                   cdbm.OperatingSystemStatusReady,
		CreatedBy:                env.ipUser.ID,
	})
	require.NoError(t, err)

	// Tenant-owned iPXE OS (no site associations).
	tnOS, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:       "tn-update-target",
		Org:        env.sharedOrg,
		TenantID:   &env.tenant.ID,
		OsType:     cdbm.OperatingSystemTypeIPXE,
		IpxeScript: cutil.GetPtr("#!ipxe\nboot"),
		Status:     cdbm.OperatingSystemStatusReady,
		CreatedBy:  env.tnUser.ID,
	})
	require.NoError(t, err)

	newScript := "updated-ipxe-script"
	updateBody := model.APIOperatingSystemUpdateRequest{
		IpxeScript: &newScript,
	}
	rawUpdate, err := json.Marshal(updateBody)
	require.NoError(t, err)

	execUpdate := func(t *testing.T, user *cdbm.User, osID string) *httptest.ResponseRecorder {
		t.Helper()
		tracer, ctx := otelTraceCtx(t)

		eh := echo.New()
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(string(rawUpdate)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()

		ec := eh.NewContext(req, rec)
		ec.SetParamNames("orgName", "id")
		ec.SetParamValues(env.sharedOrg, osID)
		ec.Set("user", user)
		ec.SetRequest(ec.Request().WithContext(
			context.WithValue(ctx, otelecho.TracerKey, tracer),
		))

		cfg := common.GetTestConfig()
		h := UpdateOperatingSystemHandler{
			dbSession: env.dbSession,
			tc:        env.tempClient,
			cfg:       cfg,
			scp:       env.scp,
		}
		require.NoError(t, h.Handle(ec))
		return rec
	}

	t.Run("provider admin updates provider-owned OS → 200", func(t *testing.T) {
		rec := execUpdate(t, env.ipUser, provOS.ID.String())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("provider admin updates tenant-owned OS → 403", func(t *testing.T) {
		rec := execUpdate(t, env.ipUser, tnOS.ID.String())
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	})

	t.Run("tenant admin updates tenant-owned OS → 200", func(t *testing.T) {
		rec := execUpdate(t, env.tnUser, tnOS.ID.String())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("tenant admin updates provider-owned OS → 403", func(t *testing.T) {
		rec := execUpdate(t, env.tnUser, provOS.ID.String())
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	})

	t.Run("dual-role user updates provider-owned OS → 200 (provider role authorizes)", func(t *testing.T) {
		rec := execUpdate(t, env.dualUser, provOS.ID.String())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("dual-role user updates tenant-owned OS → 200 (tenant role authorizes)", func(t *testing.T) {
		rec := execUpdate(t, env.dualUser, tnOS.ID.String())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
}

// ─── Delete: role-based ownership enforcement ─────────────────────────────────

// TestOperatingSystemHandler_Delete_OwnershipEnforcement exercises the Delete
// handler's role-based mutation rules.  iPXE OSes without site associations
// are used so no Temporal workflow is invoked.
//
//   - Provider Admin deletes provider-owned OS → 202
//   - Provider Admin deletes tenant-owned OS   → 403
//   - Tenant Admin deletes tenant-owned OS     → 202
//   - Tenant Admin deletes provider-owned OS   → 403
//   - Dual-role user deletes provider-owned OS → 202 (provider role authorizes)
//   - Dual-role user deletes tenant-owned OS   → 202 (tenant role authorizes)
func TestOperatingSystemHandler_Delete_OwnershipEnforcement(t *testing.T) {
	env := newOwnershipTestEnv(t)
	ctx := context.Background()

	osDAO := cdbm.NewOperatingSystemDAO(env.dbSession)

	// helper: create a fresh provider-owned iPXE OS.
	newProvOS := func(suffix string) *cdbm.OperatingSystem {
		os, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
			Name:                     "prov-del-" + suffix,
			Org:                      env.sharedOrg,
			TenantID:                 nil,
			InfrastructureProviderID: &env.ip.ID,
			OsType:                   cdbm.OperatingSystemTypeIPXE,
			IpxeScript:               cutil.GetPtr("#!ipxe\nboot"),
			Status:                   cdbm.OperatingSystemStatusReady,
			CreatedBy:                env.ipUser.ID,
		})
		require.NoError(t, err)
		return os
	}

	// helper: create a fresh tenant-owned iPXE OS.
	newTnOS := func(suffix string) *cdbm.OperatingSystem {
		os, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
			Name:       "tn-del-" + suffix,
			Org:        env.sharedOrg,
			TenantID:   &env.tenant.ID,
			OsType:     cdbm.OperatingSystemTypeIPXE,
			IpxeScript: cutil.GetPtr("#!ipxe\nboot"),
			Status:     cdbm.OperatingSystemStatusReady,
			CreatedBy:  env.tnUser.ID,
		})
		require.NoError(t, err)
		return os
	}

	execDelete := func(t *testing.T, user *cdbm.User, osID string) *httptest.ResponseRecorder {
		t.Helper()
		tracer, ctx := otelTraceCtx(t)

		eh := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		rec := httptest.NewRecorder()

		ec := eh.NewContext(req, rec)
		ec.SetParamNames("orgName", "id")
		ec.SetParamValues(env.sharedOrg, osID)
		ec.Set("user", user)
		ec.SetRequest(ec.Request().WithContext(
			context.WithValue(ctx, otelecho.TracerKey, tracer),
		))

		cfg := common.GetTestConfig()
		h := DeleteOperatingSystemHandler{
			dbSession: env.dbSession,
			tc:        env.tempClient,
			cfg:       cfg,
			scp:       env.scp,
		}
		require.NoError(t, h.Handle(ec))
		return rec
	}

	t.Run("provider admin deletes provider-owned OS → 202", func(t *testing.T) {
		os := newProvOS(uuid.NewString())
		rec := execDelete(t, env.ipUser, os.ID.String())
		assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	})

	t.Run("provider admin deletes tenant-owned OS → 403", func(t *testing.T) {
		os := newTnOS(uuid.NewString())
		rec := execDelete(t, env.ipUser, os.ID.String())
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	})

	t.Run("tenant admin deletes tenant-owned OS → 202", func(t *testing.T) {
		os := newTnOS(uuid.NewString())
		rec := execDelete(t, env.tnUser, os.ID.String())
		assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	})

	t.Run("tenant admin deletes provider-owned OS → 403", func(t *testing.T) {
		os := newProvOS(uuid.NewString())
		rec := execDelete(t, env.tnUser, os.ID.String())
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	})

	t.Run("dual-role user deletes provider-owned OS → 202 (provider role authorizes)", func(t *testing.T) {
		os := newProvOS(uuid.NewString())
		rec := execDelete(t, env.dualUser, os.ID.String())
		assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	})

	t.Run("dual-role user deletes tenant-owned OS → 202 (tenant role authorizes)", func(t *testing.T) {
		os := newTnOS(uuid.NewString())
		rec := execDelete(t, env.dualUser, os.ID.String())
		assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	})
}

// ─── Create: scope and site-association behaviour ─────────────────────────────

// TestOperatingSystemHandler_Create_ScopeAndSiteAssociation verifies that:
//   - Templated iPXE with Global scope auto-associates with all registered provider sites
//   - Templated iPXE with Limited scope associates only with specified sites
//   - Raw iPXE auto-sets scope to Global and auto-associates with tenant-accessible sites
//   - Response includes correct scope, type, and site associations
func TestOperatingSystemHandler_Create_ScopeAndSiteAssociation(t *testing.T) {
	env := newOwnershipTestEnv(t)

	scopeGlobal := cdbm.OperatingSystemScopeGlobal
	scopeLimited := cdbm.OperatingSystemScopeLimited
	templateName := "test-template"

	tests := []struct {
		name              string
		user              *cdbm.User
		body              model.APIOperatingSystemCreateRequest
		wantStatus        int
		wantType          string
		wantScope         *string
		wantSiteCount     int
		wantProviderOwned bool
	}{
		{
			name: "provider admin template iPXE global scope → auto-associates with provider sites",
			user: env.ipUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:           "prov-global-" + uuid.NewString(),
				IpxeTemplateId: &templateName,
				Scope:          &scopeGlobal,
			},
			wantStatus:        http.StatusCreated,
			wantType:          cdbm.OperatingSystemTypeTemplatedIPXE,
			wantScope:         &scopeGlobal,
			wantSiteCount:     1, // one registered site in env
			wantProviderOwned: true,
		},
		{
			name: "provider admin template iPXE limited scope → associates with specified sites",
			user: env.ipUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:           "prov-limited-" + uuid.NewString(),
				IpxeTemplateId: &templateName,
				Scope:          &scopeLimited,
				SiteIDs:        []string{env.site.ID.String()},
			},
			wantStatus:        http.StatusCreated,
			wantType:          cdbm.OperatingSystemTypeTemplatedIPXE,
			wantScope:         &scopeLimited,
			wantSiteCount:     1,
			wantProviderOwned: true,
		},
		{
			name: "tenant admin raw iPXE → scope auto-set to Global, associates with tenant sites",
			user: env.tnUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:       "tn-raw-ipxe-" + uuid.NewString(),
				IpxeScript: cutil.GetPtr("#!ipxe\nboot"),
			},
			wantStatus:    http.StatusCreated,
			wantType:      cdbm.OperatingSystemTypeIPXE,
			wantScope:     &scopeGlobal,
			wantSiteCount: 1, // tenant has access to env.site
		},
		{
			name: "tenant admin template iPXE global scope → tenant-owned, associates with tenant sites",
			user: env.tnUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:           "tn-tmpl-global-" + uuid.NewString(),
				IpxeTemplateId: &templateName,
				Scope:          &scopeGlobal,
			},
			wantStatus:    http.StatusCreated,
			wantType:      cdbm.OperatingSystemTypeTemplatedIPXE,
			wantScope:     &scopeGlobal,
			wantSiteCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.execCreateOS(t, tc.user, tc.body)
			require.Equal(t, tc.wantStatus, rec.Code, "response body: %s", rec.Body.String())

			var rsp model.APIOperatingSystem
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rsp))

			require.NotNil(t, rsp.Type, "type must be set")
			assert.Equal(t, tc.wantType, *rsp.Type)

			if tc.wantScope != nil {
				require.NotNil(t, rsp.Scope, "scope must be set in response")
				assert.Equal(t, *tc.wantScope, *rsp.Scope)
			}

			assert.Len(t, rsp.SiteAssociations, tc.wantSiteCount,
				"expected %d site associations, got %d", tc.wantSiteCount, len(rsp.SiteAssociations))

			if tc.wantProviderOwned {
				assert.NotNil(t, rsp.InfrastructureProviderID)
				assert.Nil(t, rsp.TenantID)
			} else {
				assert.Nil(t, rsp.InfrastructureProviderID)
				assert.NotNil(t, rsp.TenantID)
			}

			assert.Equal(t, cdbm.OperatingSystemStatusSyncing, rsp.Status)
			assert.True(t, len(rsp.StatusHistory) >= 1, "expected at least one status history entry")
		})
	}
}

// ─── Create: validation error paths for scope ─────────────────────────────────

// TestOperatingSystemHandler_Create_ScopeValidationErrors verifies API-level
// rejection of invalid scope combinations that the model validation covers.
func TestOperatingSystemHandler_Create_ScopeValidationErrors(t *testing.T) {
	env := newOwnershipTestEnv(t)

	scopeLocal := cdbm.OperatingSystemScopeLocal
	scopeLimited := cdbm.OperatingSystemScopeLimited
	templateName := "test-template"

	tests := []struct {
		name       string
		user       *cdbm.User
		body       model.APIOperatingSystemCreateRequest
		wantStatus int
	}{
		{
			name: "template iPXE with Local scope → 400",
			user: env.ipUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:           "tmpl-local-" + uuid.NewString(),
				IpxeTemplateId: &templateName,
				Scope:          &scopeLocal,
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "template iPXE with Limited scope but no siteIds → 400",
			user: env.ipUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:           "tmpl-limited-nosites-" + uuid.NewString(),
				IpxeTemplateId: &templateName,
				Scope:          &scopeLimited,
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "template iPXE missing scope entirely → 400",
			user: env.ipUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:           "tmpl-noscope-" + uuid.NewString(),
				IpxeTemplateId: &templateName,
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "raw iPXE with scope specified → 400",
			user: env.tnUser,
			body: model.APIOperatingSystemCreateRequest{
				Name:       "raw-ipxe-scope-" + uuid.NewString(),
				IpxeScript: cutil.GetPtr("#!ipxe\nboot"),
				Scope:      &scopeLimited,
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.execCreateOS(t, tc.user, tc.body)
			assert.Equal(t, tc.wantStatus, rec.Code, "response body: %s", rec.Body.String())
		})
	}
}
