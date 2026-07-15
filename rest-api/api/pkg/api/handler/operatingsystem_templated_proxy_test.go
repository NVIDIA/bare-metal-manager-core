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
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/coreproxy"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/otelecho"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	tmocks "go.temporal.io/sdk/mocks"
)

// TestOperatingSystemHandler_TemplatedIPXE_Proxy exercises the full create /
// update / delete lifecycle of a Global-scope Templated iPXE Operating System,
// which is synchronized to its associated Sites through the generic NICo Core
// gRPC proxy (coreproxy.WorkflowName) rather than the dedicated OsImage
// workflows used by Image based Operating Systems.
func TestOperatingSystemHandler_TemplatedIPXE_Proxy(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()

	common.TestSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()

	ipOrg := "tmpl-proxy-ip-org"
	tnOrg := "tmpl-proxy-tn-org"

	// Tenant admin who owns the OS, plus a provider admin used only to build the
	// provider/site fixtures.
	ipu := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, []string{authz.ProviderAdminRole})
	_ = ipu
	tnu := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{tnOrg}, []string{authz.TenantAdminRole})

	ip := testMachineBuildInfrastructureProvider(t, dbSession, ipOrg, "tmpl-proxy-provider")
	site := testMachineBuildSite(t, dbSession, ip, "tmpl-proxy-site", cdbm.SiteStatusRegistered)

	tenant := testMachineBuildTenant(t, dbSession, tnOrg, "tmpl-proxy-tenant")
	testBuildTenantSiteAssociation(t, dbSession, tnOrg, tenant.ID, site.ID, tnu.ID)

	// A Public template available at the tenant's site.
	templateDAO := cdbm.NewIpxeTemplateDAO(dbSession)
	tmpl, err := templateDAO.Create(ctx, nil, cdbm.IpxeTemplateCreateInput{
		ID:         uuid.New(),
		Name:       "tmpl-proxy-template",
		Template:   "#!ipxe\n",
		Visibility: "Public",
	})
	require.NoError(t, err)
	itsaDAO := cdbm.NewIpxeTemplateSiteAssociationDAO(dbSession)
	_, err = itsaDAO.Create(ctx, nil, cdbm.IpxeTemplateSiteAssociationCreateInput{IpxeTemplateID: tmpl.ID, SiteID: site.ID})
	require.NoError(t, err)

	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	// Site client pool whose site client answers the Core gRPC proxy workflow
	// with success (Get returns nil).
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)
	tsc := &tmocks.Client{}
	scp.IDClientMap[site.ID.String()] = tsc

	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return("tmpl-proxy-wf-id")
	wrun.Mock.On("Get", mock.Anything, mock.Anything).Return(nil)
	tsc.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		coreproxy.WorkflowName, mock.Anything).Return(wrun, nil)

	tc := &tmocks.Client{}

	newEchoContext := func(method, body string, params map[string]string) (echo.Context, *httptest.ResponseRecorder) {
		e := echo.New()
		req := httptest.NewRequest(method, "/", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ec := e.NewContext(req, rec)
		names := make([]string, 0, len(params))
		values := make([]string, 0, len(params))
		for k, v := range params {
			names = append(names, k)
			values = append(values, v)
		}
		ec.SetParamNames(names...)
		ec.SetParamValues(values...)
		ec.Set("user", tnu)
		reqCtx := context.WithValue(ctx, otelecho.TracerKey, tracer)
		ec.SetRequest(ec.Request().WithContext(reqCtx))
		return ec, rec
	}

	var osID string

	t.Run("create Global Templated iPXE syncs to sites via proxy", func(t *testing.T) {
		createReq := model.APIOperatingSystemCreateRequest{
			Name:           "tmpl-proxy-os",
			Description:    cutil.GetPtr("templated via proxy"),
			IpxeTemplateId: cutil.GetPtr(tmpl.ID.String()),
			Scope:          cutil.GetPtr(cdbm.OperatingSystemScopeGlobal),
			IpxeTemplateParameters: []cdbm.OperatingSystemIpxeParameter{
				{Name: "version", Value: "22.04"},
			},
		}
		body, merr := json.Marshal(createReq)
		require.NoError(t, merr)

		ec, rec := newEchoContext(http.MethodPost, string(body), map[string]string{"orgName": tnOrg})
		h := CreateOperatingSystemHandler{dbSession: dbSession, tc: tc, scp: scp, cfg: cfg}
		require.NoError(t, h.Handle(ec))
		require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

		rsp := &model.APIOperatingSystem{}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), rsp))
		require.NotNil(t, rsp.Type)
		assert.Equal(t, cdbm.OperatingSystemTypeTemplatedIPXE, *rsp.Type)
		require.NotNil(t, rsp.Scope)
		assert.Equal(t, cdbm.OperatingSystemScopeGlobal, *rsp.Scope)
		// The proxy sync succeeded for the single site, so the aggregate status is Ready.
		assert.Equal(t, cdbm.OperatingSystemStatusReady, rsp.Status)
		require.Len(t, rsp.SiteAssociations, 1)
		assert.Equal(t, cdbm.OperatingSystemSiteAssociationStatusSynced, rsp.SiteAssociations[0].Status)

		osID = rsp.ID
		require.NotEmpty(t, osID)
	})

	t.Run("update Templated iPXE re-syncs to sites via proxy", func(t *testing.T) {
		require.NotEmpty(t, osID, "create subtest must run first")
		updateReq := model.APIOperatingSystemUpdateRequest{
			Description: cutil.GetPtr("templated via proxy - updated"),
			IpxeTemplateParameters: &[]cdbm.OperatingSystemIpxeParameter{
				{Name: "version", Value: "24.04"},
			},
		}
		body, merr := json.Marshal(updateReq)
		require.NoError(t, merr)

		ec, rec := newEchoContext(http.MethodPatch, string(body), map[string]string{"orgName": tnOrg, "id": osID})
		h := UpdateOperatingSystemHandler{dbSession: dbSession, tc: tc, scp: scp, cfg: cfg}
		require.NoError(t, h.Handle(ec))
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		rsp := &model.APIOperatingSystem{}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), rsp))
		require.NotNil(t, rsp.Description)
		assert.Equal(t, "templated via proxy - updated", *rsp.Description)
	})

	t.Run("delete Templated iPXE pushes delete via proxy and soft-deletes OS", func(t *testing.T) {
		require.NotEmpty(t, osID, "create subtest must run first")
		ec, rec := newEchoContext(http.MethodDelete, "", map[string]string{"orgName": tnOrg, "id": osID})
		h := DeleteOperatingSystemHandler{dbSession: dbSession, tc: tc, scp: scp, cfg: cfg}
		require.NoError(t, h.Handle(ec))
		require.Equal(t, http.StatusAccepted, rec.Code, "body: %s", rec.Body.String())

		parsedID, perr := uuid.Parse(osID)
		require.NoError(t, perr)
		osDAO := cdbm.NewOperatingSystemDAO(dbSession)
		_, gerr := osDAO.GetByID(ctx, nil, parsedID, nil)
		assert.ErrorIs(t, gerr, cdb.ErrDoesNotExist, "OS should be soft-deleted once every site is cleaned up")
	})
}
