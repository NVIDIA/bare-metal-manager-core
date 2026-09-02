// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	tmocks "go.temporal.io/sdk/mocks"
	tp "go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/grpcproxy"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
)

func TestCreateDomainHandler(t *testing.T) {
	fixture := newDomainHandlerFixture(t, nil)
	controllerDomainID := uuid.New()
	proxiedRequest := fixture.expectCore(t, corev1.Forge_CreateDomain_FullMethodName, &corev1.Domain{
		Id:   &corev1.DomainId{Value: controllerDomainID.String()},
		Name: "tenant.example.com",
	}, nil)

	recorder := fixture.request(t, NewCreateDomainHandler(fixture.dbSession, fixture.scp).Handle, http.MethodPost, "/", "", model.APIDomainCreateRequest{
		Name:   "tenant.example.com",
		SiteID: fixture.site.ID.String(),
	})
	require.Equal(t, http.StatusCreated, recorder.Code, recorder.Body.String())

	var response model.APIDomain
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.NotEqual(t, controllerDomainID.String(), response.ID)
	assert.Equal(t, fixture.site.ID.String(), response.SiteID)
	assert.Equal(t, "tenant.example.com", response.Name)

	var coreRequest corev1.CreateDomainRequest
	require.NoError(t, protojson.Unmarshal(proxiedRequest.RequestJSON, &coreRequest))
	assert.Equal(t, "tenant.example.com", coreRequest.GetName())

	persisted, err := cdbm.NewDomainDAO(fixture.dbSession).GetByID(context.Background(), nil, uuid.MustParse(response.ID), nil)
	require.NoError(t, err)
	assert.Equal(t, &fixture.tenant.ID, persisted.TenantID)
	assert.Equal(t, &fixture.site.ID, persisted.SiteID)
	assert.Equal(t, &controllerDomainID, persisted.ControllerDomainID)
	assert.Equal(t, cdbm.DomainStatusReady, persisted.Status)
}

func TestCreateDomainHandlerValidationAndAuthorization(t *testing.T) {
	fixture := newDomainHandlerFixture(t, nil)
	handler := NewCreateDomainHandler(fixture.dbSession, fixture.scp)

	recorder := fixture.request(t, handler.Handle, http.MethodPost, "/", "", "{")
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "Failed to parse request data, potentially invalid structure")

	recorder = fixture.request(t, handler.Handle, http.MethodPost, "/", "", model.APIDomainCreateRequest{SiteID: fixture.site.ID.String()})
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "Error validating Domain creation request data")

	otherSite := common.TestBuildSite(t, fixture.dbSession, fixture.provider, "Unauthorized Site", fixture.user)
	_, err := cdbm.NewSiteDAO(fixture.dbSession).Update(context.Background(), nil, cdbm.SiteUpdateInput{
		SiteID: otherSite.ID,
		Status: cutil.GetPtr(cdbm.SiteStatusRegistered),
	})
	require.NoError(t, err)
	recorder = fixture.request(t, handler.Handle, http.MethodPost, "/", "", model.APIDomainCreateRequest{
		Name:   "tenant.example.com",
		SiteID: otherSite.ID.String(),
	})
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	fixture.siteClient.AssertNotCalled(t, "ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestCreateDomainHandlerCompensatesCoreAfterDatabaseFailure(t *testing.T) {
	fixture := newDomainHandlerFixture(t, nil)
	controllerDomainID := uuid.New()
	_, err := fixture.dbSession.DB.ExecContext(context.Background(), `
		ALTER TABLE domain ADD CONSTRAINT domain_test_reject_hostname
		CHECK (hostname <> 'db-fail.example.com')
	`)
	require.NoError(t, err)

	fixture.expectCore(t, corev1.Forge_CreateDomain_FullMethodName, &corev1.Domain{
		Id: &corev1.DomainId{Value: controllerDomainID.String()},
	}, nil)
	deleteRequest := fixture.expectCore(t, corev1.Forge_DeleteDomain_FullMethodName, nil, nil)

	recorder := fixture.request(t, NewCreateDomainHandler(fixture.dbSession, fixture.scp).Handle, http.MethodPost, "/", "", model.APIDomainCreateRequest{
		Name:   "db-fail.example.com",
		SiteID: fixture.site.ID.String(),
	})
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)

	var coreDeleteRequest corev1.DomainDeletionRequest
	require.NoError(t, protojson.Unmarshal(deleteRequest.RequestJSON, &coreDeleteRequest))
	assert.Equal(t, controllerDomainID.String(), coreDeleteRequest.GetId().GetValue())

	domains, err := cdbm.NewDomainDAO(fixture.dbSession).GetAll(context.Background(), nil, cdbm.DomainFilterInput{}, nil)
	require.NoError(t, err)
	assert.Empty(t, domains)
}

func TestGetDomainHandlersHideUnownedAndCrossTenantRows(t *testing.T) {
	fixture := newDomainHandlerFixture(t, nil)
	otherSite := common.TestBuildSite(t, fixture.dbSession, fixture.provider, "Other Site", fixture.user)
	common.TestBuildTenantSite(t, fixture.dbSession, fixture.tenant, otherSite, fixture.user)

	ownedSiteOne := fixture.createDomain(t, "one.example.com", &fixture.tenant.ID, &fixture.site.ID)
	ownedSiteTwo := fixture.createDomain(t, "two.example.com", &fixture.tenant.ID, &otherSite.ID)
	otherTenantID := uuid.New()
	crossTenant := fixture.createDomain(t, "other.example.com", &otherTenantID, &fixture.site.ID)
	legacy := fixture.createDomain(t, "legacy.example.com", nil, nil)

	listHandler := NewGetAllDomainHandler(fixture.dbSession)
	recorder := fixture.request(t, listHandler.Handle, http.MethodGet, "/", "", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var listResponse []*model.APIDomain
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &listResponse))
	require.Len(t, listResponse, 2)
	assert.ElementsMatch(t, []string{ownedSiteOne.ID.String(), ownedSiteTwo.ID.String()}, []string{listResponse[0].ID, listResponse[1].ID})

	recorder = fixture.request(t, listHandler.Handle, http.MethodGet, "/?siteId="+fixture.site.ID.String(), "", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &listResponse))
	require.Len(t, listResponse, 1)
	assert.Equal(t, ownedSiteOne.ID.String(), listResponse[0].ID)

	getHandler := NewGetDomainHandler(fixture.dbSession)
	recorder = fixture.request(t, getHandler.Handle, http.MethodGet, "/", ownedSiteOne.ID.String(), nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	for _, hiddenID := range []uuid.UUID{crossTenant.ID, legacy.ID} {
		recorder = fixture.request(t, getHandler.Handle, http.MethodGet, "/", hiddenID.String(), nil)
		assert.Equal(t, http.StatusNotFound, recorder.Code)
	}
}

func TestDeleteDomainHandler(t *testing.T) {
	tests := []struct {
		name            string
		coreError       error
		expectedStatus  int
		expectedDeleted bool
	}{
		{
			name:            "success",
			expectedStatus:  http.StatusNoContent,
			expectedDeleted: true,
		},
		{
			name: "Core failed precondition preserves projection",
			coreError: tp.NewNonRetryableApplicationError(
				"Domain is in use",
				swe.ErrTypeNICoFailedPrecondition,
				errors.New("Domain is in use"),
			),
			expectedStatus: http.StatusPreconditionFailed,
		},
		{
			name: "Core not found reconciles projection",
			coreError: tp.NewNonRetryableApplicationError(
				"Domain not found",
				swe.ErrTypeNICoObjectNotFound,
				errors.New("Domain not found"),
			),
			expectedStatus:  http.StatusNoContent,
			expectedDeleted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newDomainHandlerFixture(t, nil)
			controllerDomainID := uuid.New()
			domain := fixture.createDomainWithControllerID(t, "delete.example.com", &fixture.tenant.ID, &fixture.site.ID, controllerDomainID)
			proxiedRequest := fixture.expectCore(t, corev1.Forge_DeleteDomain_FullMethodName, nil, tt.coreError)

			recorder := fixture.request(t, NewDeleteDomainHandler(fixture.dbSession, fixture.scp).Handle, http.MethodDelete, "/", domain.ID.String(), nil)
			assert.Equal(t, tt.expectedStatus, recorder.Code, recorder.Body.String())

			var coreRequest corev1.DomainDeletionRequest
			require.NoError(t, protojson.Unmarshal(proxiedRequest.RequestJSON, &coreRequest))
			assert.Equal(t, controllerDomainID.String(), coreRequest.GetId().GetValue())
			assert.NotEqual(t, domain.ID.String(), coreRequest.GetId().GetValue())

			persisted, err := cdbm.NewDomainDAO(fixture.dbSession).GetByID(context.Background(), nil, domain.ID, nil)
			if tt.expectedDeleted {
				assert.ErrorIs(t, err, cdb.ErrDoesNotExist)
				assert.Nil(t, persisted)
			} else {
				require.NoError(t, err)
				assert.Equal(t, domain.ID, persisted.ID)
			}
		})
	}
}

func TestDeleteDomainHandlerRejectsLocalSubnetReference(t *testing.T) {
	fixture := newDomainHandlerFixture(t, nil)
	domain := fixture.createDomain(t, "in-use.example.com", &fixture.tenant.ID, &fixture.site.ID)
	vpc := common.TestBuildVPC(t, fixture.dbSession, "test-vpc", fixture.provider, fixture.tenant, fixture.site, cutil.GetPtr(uuid.New()), nil, nil, cdbm.VpcStatusReady, fixture.user)
	subnet := common.TestBuildSubnet(t, fixture.dbSession, "test-subnet", fixture.tenant, vpc, cutil.GetPtr(uuid.New()), cdbm.SubnetStatusReady, fixture.user)
	_, err := cdbm.NewSubnetDAO(fixture.dbSession).Update(context.Background(), nil, cdbm.SubnetUpdateInput{
		SubnetId: subnet.ID,
		DomainID: &domain.ID,
	})
	require.NoError(t, err)

	recorder := fixture.request(t, NewDeleteDomainHandler(fixture.dbSession, fixture.scp).Handle, http.MethodDelete, "/", domain.ID.String(), nil)
	assert.Equal(t, http.StatusPreconditionFailed, recorder.Code, recorder.Body.String())
	fixture.siteClient.AssertNotCalled(t, "ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	persisted, err := cdbm.NewDomainDAO(fixture.dbSession).GetByID(context.Background(), nil, domain.ID, nil)
	require.NoError(t, err)
	assert.Equal(t, domain.ID, persisted.ID)
}

type domainHandlerFixture struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	siteClient *tmocks.Client
	org        string
	user       *cdbm.User
	provider   *cdbm.InfrastructureProvider
	tenant     *cdbm.Tenant
	site       *cdbm.Site
}

func newDomainHandlerFixture(t *testing.T, roles []string) *domainHandlerFixture {
	t.Helper()

	dbSession := common.TestInitDB(t)
	t.Cleanup(dbSession.Close)
	common.TestSetupSchema(t, dbSession)
	if roles == nil {
		roles = []string{authz.TenantAdminRole}
	}

	org := "domain-test-tenant-org"
	user := common.TestBuildUser(t, dbSession, uuid.NewString(), org, roles)
	providerUser := common.TestBuildUser(t, dbSession, uuid.NewString(), "domain-test-provider-org", []string{authz.ProviderAdminRole})
	provider := common.TestBuildInfrastructureProvider(t, dbSession, "Domain Test Provider", "domain-test-provider-org", providerUser)
	site := common.TestBuildSite(t, dbSession, provider, "Domain Test Site", providerUser)
	_, err := cdbm.NewSiteDAO(dbSession).Update(context.Background(), nil, cdbm.SiteUpdateInput{
		SiteID: site.ID,
		Status: cutil.GetPtr(cdbm.SiteStatusRegistered),
	})
	require.NoError(t, err)
	site.Status = cdbm.SiteStatusRegistered
	tenant := common.TestBuildTenant(t, dbSession, "Domain Test Tenant", org, user)
	common.TestBuildTenantSite(t, dbSession, tenant, site, user)

	siteClient := &tmocks.Client{}
	scp := sc.NewClientPool(nil)
	scp.IDClientMap[site.ID.String()] = siteClient

	return &domainHandlerFixture{
		dbSession: dbSession, scp: scp, siteClient: siteClient, org: org, user: user,
		provider: provider, tenant: tenant, site: site,
	}
}

func (f *domainHandlerFixture) expectCore(t *testing.T, fullMethod string, response proto.Message, resultErr error) *grpcproxy.Request {
	t.Helper()

	proxiedRequest := &grpcproxy.Request{}
	workflowRun := &tmocks.WorkflowRun{}
	workflowRun.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if response == nil {
			return
		}
		responseJSON, err := protojson.Marshal(response)
		require.NoError(t, err)
		args.Get(1).(*grpcproxy.Response).ResponseJSON = responseJSON
	}).Return(resultErr).Once()
	f.siteClient.On("ExecuteWorkflow", mock.Anything, mock.Anything, grpcproxy.Core.WorkflowName, mock.MatchedBy(func(request grpcproxy.Request) bool {
		if request.FullMethod != fullMethod {
			return false
		}
		*proxiedRequest = request
		return true
	})).Return(workflowRun, nil).Once()
	return proxiedRequest
}

func (f *domainHandlerFixture) createDomain(t *testing.T, name string, tenantID, siteID *uuid.UUID) *cdbm.Domain {
	t.Helper()
	return f.createDomainWithControllerID(t, name, tenantID, siteID, uuid.New())
}

func (f *domainHandlerFixture) createDomainWithControllerID(t *testing.T, name string, tenantID, siteID *uuid.UUID, controllerDomainID uuid.UUID) *cdbm.Domain {
	t.Helper()
	domain, err := cdbm.NewDomainDAO(f.dbSession).Create(context.Background(), nil, cdbm.DomainCreateInput{
		Hostname:           name,
		Org:                f.org,
		TenantID:           tenantID,
		SiteID:             siteID,
		ControllerDomainID: &controllerDomainID,
		Status:             cdbm.DomainStatusReady,
		CreatedBy:          f.user.ID,
	})
	require.NoError(t, err)
	return domain
}

func (f *domainHandlerFixture) request(
	t *testing.T,
	handler func(echo.Context) error,
	method string,
	target string,
	id string,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()

	requestBody := ""
	if rawBody, ok := body.(string); ok {
		requestBody = rawBody
	} else if body != nil {
		encodedBody, err := json.Marshal(body)
		require.NoError(t, err)
		requestBody = string(encodedBody)
	}

	request := httptest.NewRequest(method, target, strings.NewReader(requestBody))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recorder := httptest.NewRecorder()
	e := echo.New()
	echoContext := e.NewContext(request, recorder)
	echoContext.SetParamNames("orgName", "id")
	echoContext.SetParamValues(f.org, id)
	echoContext.Set("user", f.user)
	require.NoError(t, handler(echoContext))
	return recorder
}
