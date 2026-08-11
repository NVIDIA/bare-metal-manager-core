// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	tmocks "go.temporal.io/sdk/mocks"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/pagination"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/grpcproxy"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

func TestGetAllExploredEndpointHandler_Handle(t *testing.T) {
	tests := []struct {
		name               string
		roles              []string
		injectSiteID       bool
		extraQuery         string
		rawQuery           string
		ids                *corev1.ExploredEndpointIdList
		endpoints          *corev1.ExploredEndpointList
		expectFindByIDs    bool
		expectFindByIDVals []string
		wantStatus         int
		wantCount          int
		wantTotal          int
		wantAddresses      []string
		wantProxyCalls     int
	}{
		{
			name:         "success returns page of endpoints",
			roles:        []string{authz.ProviderAdminRole},
			injectSiteID: true,
			extraQuery:   "",
			ids:          &corev1.ExploredEndpointIdList{EndpointIds: []string{"10.0.0.1", "10.0.0.2"}},
			endpoints: &corev1.ExploredEndpointList{
				Endpoints: []*corev1.ExploredEndpoint{
					{Address: "10.0.0.1", ReportVersion: "1"},
					{Address: "10.0.0.2", ReportVersion: "2"},
				},
			},
			expectFindByIDs:    true,
			expectFindByIDVals: []string{"10.0.0.1", "10.0.0.2"},
			wantStatus:         http.StatusOK,
			wantCount:          2,
			wantTotal:          2,
			wantAddresses:      []string{"10.0.0.1", "10.0.0.2"},
			wantProxyCalls:     2,
		},
		{
			name:         "success paginates second page",
			roles:        []string{authz.ProviderAdminRole},
			injectSiteID: true,
			extraQuery:   "pageNumber=2&pageSize=1",
			ids:          &corev1.ExploredEndpointIdList{EndpointIds: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
			endpoints: &corev1.ExploredEndpointList{
				Endpoints: []*corev1.ExploredEndpoint{
					{Address: "10.0.0.2", ReportVersion: "2"},
				},
			},
			expectFindByIDs:    true,
			expectFindByIDVals: []string{"10.0.0.2"},
			wantStatus:         http.StatusOK,
			wantCount:          1,
			wantTotal:          3,
			wantAddresses:      []string{"10.0.0.2"},
			wantProxyCalls:     2,
		},
		{
			name:           "success empty site skips FindByIds",
			roles:          []string{authz.ProviderAdminRole},
			injectSiteID:   true,
			ids:            &corev1.ExploredEndpointIdList{EndpointIds: []string{}},
			wantStatus:     http.StatusOK,
			wantCount:      0,
			wantTotal:      0,
			wantProxyCalls: 1,
		},
		{
			name:           "success past-end page skips FindByIds",
			roles:          []string{authz.ProviderAdminRole},
			injectSiteID:   true,
			extraQuery:     "pageNumber=5&pageSize=10",
			ids:            &corev1.ExploredEndpointIdList{EndpointIds: []string{"10.0.0.1"}},
			wantStatus:     http.StatusOK,
			wantCount:      0,
			wantTotal:      1,
			wantProxyCalls: 1,
		},
		{
			name:         "rejects non provider admin",
			roles:        nil,
			injectSiteID: true,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:       "rejects missing siteId",
			roles:      []string{authz.ProviderAdminRole},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejects invalid siteId",
			roles:      []string{authz.ProviderAdminRole},
			rawQuery:   "siteId=not-a-uuid",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "rejects invalid pagination",
			roles:        []string{authz.ProviderAdminRole},
			injectSiteID: true,
			extraQuery:   "pageNumber=-1",
			wantStatus:   http.StatusBadRequest,
		},
		{
			name:         "rejects unknown query params",
			roles:        []string{authz.ProviderAdminRole},
			injectSiteID: true,
			extraQuery:   "foo=bar",
			wantStatus:   http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newGetAllExploredEndpointHandlerFixture(t, tt.roles)
			query := "/"
			switch {
			case tt.rawQuery != "":
				query = "/?" + tt.rawQuery
			case tt.injectSiteID:
				query = "/?siteId=" + fixture.siteID
				if tt.extraQuery != "" {
					query += "&" + tt.extraQuery
				}
			}

			if tt.ids != nil {
				fixture.expectProxyResponse(t, tt.ids)
			}
			if tt.expectFindByIDs {
				fixture.expectProxyResponse(t, tt.endpoints)
			}

			rec := fixture.request(t, query)
			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Len(t, fixture.proxiedReqs, tt.wantProxyCalls)

			if tt.wantStatus != http.StatusOK {
				return
			}

			var resp []*model.APIExploredEndpoint
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			assert.Len(t, resp, tt.wantCount)
			for i, addr := range tt.wantAddresses {
				assert.Equal(t, addr, resp[i].Address)
			}

			ph := rec.Header().Get(pagination.ResponseHeaderName)
			require.NotEmpty(t, ph)
			var pageResp pagination.PageResponse
			require.NoError(t, json.Unmarshal([]byte(ph), &pageResp))
			assert.Equal(t, tt.wantTotal, pageResp.Total)

			if tt.expectFindByIDs {
				require.Len(t, fixture.proxiedReqs, 2)
				assert.Equal(t, corev1.Forge_FindExploredEndpointIds_FullMethodName, fixture.proxiedReqs[0].FullMethod)
				assert.Equal(t, corev1.Forge_FindExploredEndpointsByIds_FullMethodName, fixture.proxiedReqs[1].FullMethod)
				var byIDs corev1.ExploredEndpointsByIdsRequest
				require.NoError(t, protojson.Unmarshal(fixture.proxiedReqs[1].RequestJSON, &byIDs))
				assert.Equal(t, tt.expectFindByIDVals, byIDs.GetEndpointIds())
			} else if tt.wantProxyCalls == 1 {
				assert.Equal(t, corev1.Forge_FindExploredEndpointIds_FullMethodName, fixture.proxiedReqs[0].FullMethod)
			}
		})
	}
}

type getAllExploredEndpointHandlerFixture struct {
	org         string
	siteID      string
	user        interface{}
	handler     GetAllExploredEndpointHandler
	tsc         *tmocks.Client
	proxiedReqs []grpcproxy.Request
}

func newGetAllExploredEndpointHandlerFixture(t *testing.T, roles []string) *getAllExploredEndpointHandlerFixture {
	t.Helper()

	dbSession := common.TestInitDB(t)
	t.Cleanup(dbSession.Close)
	common.TestSetupSchema(t, dbSession)

	org := "test-org-" + uuid.NewString()
	user := common.TestBuildUser(t, dbSession, "test-starfleet-id-"+uuid.NewString(), org, roles)
	ip := common.TestBuildInfrastructureProvider(t, dbSession, "Test Infrastructure Provider", org, user)
	site := common.TestBuildSite(t, dbSession, ip, "Test Site", user)
	sDAO := cdbm.NewSiteDAO(dbSession)
	_, err := sDAO.Update(context.Background(), nil, cdbm.SiteUpdateInput{
		SiteID: site.ID,
		Status: cutil.GetPtr(cdbm.SiteStatusRegistered),
	})
	require.NoError(t, err)

	tsc := &tmocks.Client{}
	scp := sc.NewClientPool(nil)
	scp.IDClientMap[site.ID.String()] = tsc

	return &getAllExploredEndpointHandlerFixture{
		org:     org,
		siteID:  site.ID.String(),
		user:    user,
		handler: NewGetAllExploredEndpointHandler(dbSession, scp, common.GetTestConfig()),
		tsc:     tsc,
	}
}

func (f *getAllExploredEndpointHandlerFixture) expectProxyResponse(t *testing.T, resp proto.Message) {
	t.Helper()

	wrun := &tmocks.WorkflowRun{}
	wrun.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if resp == nil {
			return
		}
		out := args.Get(1).(*grpcproxy.Response)
		responseJSON, err := protojson.Marshal(resp)
		require.NoError(t, err)
		out.ResponseJSON = responseJSON
	}).Return(nil).Once()

	f.tsc.On(
		"ExecuteWorkflow",
		mock.Anything,
		mock.Anything,
		grpcproxy.Core.WorkflowName,
		mock.Anything,
	).Run(func(args mock.Arguments) {
		f.proxiedReqs = append(f.proxiedReqs, args.Get(3).(grpcproxy.Request))
	}).Return(wrun, nil).Once()
}

func (f *getAllExploredEndpointHandlerFixture) request(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	ec := e.NewContext(req, rec)
	ec.SetParamNames("orgName")
	ec.SetParamValues(f.org)
	ec.Set("user", f.user)

	require.NoError(t, f.handler.Handle(ec))
	return rec
}
