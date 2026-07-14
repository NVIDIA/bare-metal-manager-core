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

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	tmocks "go.temporal.io/sdk/mocks"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/coreproxy"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

func TestCreateMeasurementTrustedMachineHandler(t *testing.T) {
	record := &corev1.MeasurementApprovedMachineRecordPb{
		ApprovalId:   &corev1.MeasurementApprovedMachineId{Value: "00000000-0000-0000-0000-000000000010"},
		MachineId:    "*",
		ApprovalType: corev1.MeasurementApprovedTypePb_Persist,
	}
	fixture := newMeasurementTrustHandlerFixture(t, &corev1.AddMeasurementTrustedMachineResponse{ApprovalRecord: record}, nil)
	handler := NewCreateMeasurementTrustedMachineHandler(fixture.dbSession, fixture.scp)

	rec := fixture.request(t, handler.Handle, http.MethodPost, "/", "", model.APIMeasurementTrustedMachineCreateRequest{
		SiteID:       fixture.siteID,
		MachineID:    "*",
		ApprovalType: model.MeasurementTrustApprovalTypePersist,
	})
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, corev1.Forge_AddMeasurementTrustedMachine_FullMethodName, fixture.proxiedReq.FullMethod)

	var coreReq corev1.AddMeasurementTrustedMachineRequest
	require.NoError(t, protojson.Unmarshal(fixture.proxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, "*", coreReq.GetMachineId())
	assert.Equal(t, corev1.MeasurementApprovedTypePb_Persist, coreReq.GetApprovalType())

	var resp model.APIMeasurementTrustedMachine
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, record.GetApprovalId().GetValue(), resp.ApprovalID)
}

func TestListMeasurementTrustedMachinesHandler(t *testing.T) {
	record := &corev1.MeasurementApprovedMachineRecordPb{
		ApprovalId: &corev1.MeasurementApprovedMachineId{Value: "00000000-0000-0000-0000-000000000010"},
		MachineId:  "00000000-0000-0000-0000-000000000011",
	}
	fixture := newMeasurementTrustHandlerFixture(t, &corev1.ListMeasurementTrustedMachinesResponse{ApprovalRecords: []*corev1.MeasurementApprovedMachineRecordPb{record}}, nil)
	handler := NewListMeasurementTrustedMachinesHandler(fixture.dbSession, fixture.scp)

	rec := fixture.request(t, handler.Handle, http.MethodGet, "/?siteId="+fixture.siteID, "", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, corev1.Forge_ListMeasurementTrustedMachines_FullMethodName, fixture.proxiedReq.FullMethod)

	var resp []*model.APIMeasurementTrustedMachine
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp, 1)
	assert.Equal(t, record.GetMachineId(), resp[0].MachineID)
}

func TestDeleteMeasurementTrustedMachineHandler(t *testing.T) {
	record := &corev1.MeasurementApprovedMachineRecordPb{
		ApprovalId: &corev1.MeasurementApprovedMachineId{Value: "00000000-0000-0000-0000-000000000010"},
		MachineId:  "00000000-0000-0000-0000-000000000011",
	}
	fixture := newMeasurementTrustHandlerFixture(t, &corev1.RemoveMeasurementTrustedMachineResponse{ApprovalRecord: record}, nil)
	handler := NewDeleteMeasurementTrustedMachineHandler(fixture.dbSession, fixture.scp)

	target := "/?siteId=" + fixture.siteID + "&selector=" + model.MeasurementTrustedMachineSelectorMachineID
	rec := fixture.request(t, handler.Handle, http.MethodDelete, target, record.GetMachineId(), nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, corev1.Forge_RemoveMeasurementTrustedMachine_FullMethodName, fixture.proxiedReq.FullMethod)

	var coreReq corev1.RemoveMeasurementTrustedMachineRequest
	require.NoError(t, protojson.Unmarshal(fixture.proxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, record.GetMachineId(), coreReq.GetMachineId())
}

func TestCreateMeasurementTrustedProfileHandler(t *testing.T) {
	record := &corev1.MeasurementApprovedProfileRecordPb{
		ApprovalId: &corev1.MeasurementApprovedProfileId{Value: "00000000-0000-0000-0000-000000000010"},
		ProfileId:  &corev1.MeasurementSystemProfileId{Value: "00000000-0000-0000-0000-000000000012"},
	}
	fixture := newMeasurementTrustHandlerFixture(t, &corev1.AddMeasurementTrustedProfileResponse{ApprovalRecord: record}, nil)
	handler := NewCreateMeasurementTrustedProfileHandler(fixture.dbSession, fixture.scp)

	rec := fixture.request(t, handler.Handle, http.MethodPost, "/", "", model.APIMeasurementTrustedProfileCreateRequest{
		SiteID:       fixture.siteID,
		ProfileID:    record.GetProfileId().GetValue(),
		ApprovalType: model.MeasurementTrustApprovalTypeOneshot,
	})
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, corev1.Forge_AddMeasurementTrustedProfile_FullMethodName, fixture.proxiedReq.FullMethod)
}

func TestListMeasurementTrustedProfilesHandler(t *testing.T) {
	record := &corev1.MeasurementApprovedProfileRecordPb{
		ApprovalId: &corev1.MeasurementApprovedProfileId{Value: "00000000-0000-0000-0000-000000000010"},
		ProfileId:  &corev1.MeasurementSystemProfileId{Value: "00000000-0000-0000-0000-000000000012"},
	}
	fixture := newMeasurementTrustHandlerFixture(t, &corev1.ListMeasurementTrustedProfilesResponse{ApprovalRecords: []*corev1.MeasurementApprovedProfileRecordPb{record}}, nil)
	handler := NewListMeasurementTrustedProfilesHandler(fixture.dbSession, fixture.scp)

	rec := fixture.request(t, handler.Handle, http.MethodGet, "/?siteId="+fixture.siteID, "", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, corev1.Forge_ListMeasurementTrustedProfiles_FullMethodName, fixture.proxiedReq.FullMethod)
}

func TestDeleteMeasurementTrustedProfileHandler(t *testing.T) {
	record := &corev1.MeasurementApprovedProfileRecordPb{
		ApprovalId: &corev1.MeasurementApprovedProfileId{Value: "00000000-0000-0000-0000-000000000010"},
		ProfileId:  &corev1.MeasurementSystemProfileId{Value: "00000000-0000-0000-0000-000000000012"},
	}
	fixture := newMeasurementTrustHandlerFixture(t, &corev1.RemoveMeasurementTrustedProfileResponse{ApprovalRecord: record}, nil)
	handler := NewDeleteMeasurementTrustedProfileHandler(fixture.dbSession, fixture.scp)

	target := "/?siteId=" + fixture.siteID + "&selector=" + model.MeasurementTrustedProfileSelectorApprovalID
	rec := fixture.request(t, handler.Handle, http.MethodDelete, target, record.GetApprovalId().GetValue(), nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, corev1.Forge_RemoveMeasurementTrustedProfile_FullMethodName, fixture.proxiedReq.FullMethod)
}

func TestMeasurementTrustHandlersRejectInvalidInput(t *testing.T) {
	fixture := newMeasurementTrustHandlerFixture(t, nil, nil)
	createHandler := NewCreateMeasurementTrustedMachineHandler(fixture.dbSession, fixture.scp)
	deleteHandler := NewDeleteMeasurementTrustedProfileHandler(fixture.dbSession, fixture.scp)

	rec := fixture.request(t, createHandler.Handle, http.MethodPost, "/", "", model.APIMeasurementTrustedMachineCreateRequest{
		SiteID:       fixture.siteID,
		MachineID:    "invalid",
		ApprovalType: model.MeasurementTrustApprovalTypeOneshot,
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	rec = fixture.request(t, deleteHandler.Handle, http.MethodDelete, "/?siteId="+fixture.siteID+"&selector=invalid", "invalid", nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMeasurementTrustHandlerRequiresProviderAdmin(t *testing.T) {
	fixture := newMeasurementTrustHandlerFixture(t, nil, []string{authz.TenantAdminRole})
	handler := NewListMeasurementTrustedMachinesHandler(fixture.dbSession, fixture.scp)

	rec := fixture.request(t, handler.Handle, http.MethodGet, "/?siteId="+fixture.siteID, "", nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

type measurementTrustHandlerFixture struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	org        string
	siteID     string
	user       *cdbm.User
	proxiedReq *coreproxy.Request
}

func newMeasurementTrustHandlerFixture(t *testing.T, response proto.Message, roles []string) measurementTrustHandlerFixture {
	t.Helper()

	dbSession := common.TestInitDB(t)
	t.Cleanup(dbSession.Close)
	common.TestSetupSchema(t, dbSession)

	if roles == nil {
		roles = []string{authz.ProviderAdminRole}
	}
	org := "test-org"
	user := common.TestBuildUser(t, dbSession, "test-starfleet-id", org, roles)
	ip := common.TestBuildInfrastructureProvider(t, dbSession, "Test Infrastructure Provider", org, user)
	site := common.TestBuildSite(t, dbSession, ip, "Test Site", user)
	sDAO := cdbm.NewSiteDAO(dbSession)
	_, err := sDAO.Update(context.Background(), nil, cdbm.SiteUpdateInput{SiteID: site.ID, Status: cutil.GetPtr(cdbm.SiteStatusRegistered)})
	require.NoError(t, err)

	proxiedReq := &coreproxy.Request{}
	wrun := &tmocks.WorkflowRun{}
	wrun.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if response == nil {
			return
		}
		responseJSON, err := protojson.Marshal(response)
		require.NoError(t, err)
		args.Get(1).(*coreproxy.Response).ResponseJSON = responseJSON
	}).Return(nil)

	tsc := &tmocks.Client{}
	tsc.On("ExecuteWorkflow", mock.Anything, mock.Anything, coreproxy.WorkflowName, mock.MatchedBy(func(req coreproxy.Request) bool {
		*proxiedReq = req
		return true
	})).Return(wrun, nil)

	scp := sc.NewClientPool(nil)
	scp.IDClientMap[site.ID.String()] = tsc

	return measurementTrustHandlerFixture{
		dbSession: dbSession, scp: scp, org: org, siteID: site.ID.String(), user: user, proxiedReq: proxiedReq,
	}
}

func (f measurementTrustHandlerFixture) request(t *testing.T, handler func(echo.Context) error, method, target, id string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var requestBody string
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		requestBody = string(data)
	}
	req := httptest.NewRequest(method, target, strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e := echo.New()
	ec := e.NewContext(req, rec)
	ec.SetParamNames("orgName", "id")
	ec.SetParamValues(f.org, id)
	ec.Set("user", f.user)

	require.NoError(t, handler(ec))
	return rec
}
