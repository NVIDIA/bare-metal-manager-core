// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	oteltrace "go.opentelemetry.io/otel/trace"
	tmocks "go.temporal.io/sdk/mocks"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/otelecho"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/proto/flow/gen/v1"
)

// testRunSampleCreateRequest returns a minimal valid create-task-run body.
func testRunSampleCreateRequest(siteID string) model.APITaskRunCreateRequest {
	return model.APITaskRunCreateRequest{
		SiteID:      siteID,
		Name:        "fw-rollout",
		Description: "test run",
		Options:     model.APITaskRunOptions{MaxConcurrentTargets: 2},
		Operation: model.APITaskRunOperation{
			Firmware: &model.APITaskRunFirmwareOperation{Version: "1.2.3"},
		},
	}
}

func TestCreateTaskRunHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testRackInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testRackSetupTestData(t, dbSession, org)

	siteNoFlow := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site-no-flow-run-create",
		Org:                      org,
		InfrastructureProviderID: site.InfrastructureProviderID,
		Status:                   cdbm.SiteStatusRegistered,
		Config:                   &cdbm.SiteConfig{},
	}
	_, err := dbSession.DB.NewInsert().Model(siteNoFlow).Exec(context.Background())
	require.NoError(t, err)

	providerUser := testRackBuildUser(t, dbSession, "provider-user-run-create", org, []string{authz.ProviderAdminRole})
	tenantUser := testRackBuildUser(t, dbSession, "tenant-user-run-create", org, []string{authz.TenantAdminRole})

	handler := NewCreateTaskRunHandler(dbSession, nil, scp, cfg)
	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")

	tests := []struct {
		name           string
		user           *cdbm.User
		body           any
		mockResp       *flowv1.CreateOperationRunResponse
		mockExecErr    error
		expectedStatus int
	}{
		{
			name:           "success - 201 pending run",
			user:           providerUser,
			body:           testRunSampleCreateRequest(site.ID.String()),
			mockResp:       &flowv1.CreateOperationRunResponse{Id: &flowv1.UUID{Id: uuid.New().String()}},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "failure - Flow not enabled on site",
			user:           providerUser,
			body:           testRunSampleCreateRequest(siteNoFlow.ID.String()),
			expectedStatus: http.StatusPreconditionFailed,
		},
		{
			name: "failure - missing siteId",
			user: providerUser,
			body: func() model.APITaskRunCreateRequest {
				r := testRunSampleCreateRequest(site.ID.String())
				r.SiteID = ""
				return r
			}(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "failure - missing firmware operation",
			user: providerUser,
			body: func() model.APITaskRunCreateRequest {
				r := testRunSampleCreateRequest(site.ID.String())
				r.Operation.Firmware = nil
				return r
			}(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			user:           tenantUser,
			body:           testRunSampleCreateRequest(site.ID.String()),
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "failure - workflow scheduling error",
			user:           providerUser,
			body:           testRunSampleCreateRequest(site.ID.String()),
			mockExecErr:    errors.New("temporal scheduling failed"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTC := &tmocks.Client{}
			mockRun := &tmocks.WorkflowRun{}
			mockRun.On("GetID").Return("test-workflow-id")
			if tt.mockResp != nil {
				mockRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.CreateOperationRunResponse)
					resp.Id = tt.mockResp.Id
				}).Return(nil)
			}
			mockTC.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "CreateTaskRun", mock.Anything).Return(mockRun, tt.mockExecErr)
			scp.IDClientMap[site.ID.String()] = mockTC

			bodyBytes, err := json.Marshal(tt.body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v2/org/%s/nico/task/run", org), bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(org)
			ec.Set("user", tt.user)
			ctx := context.WithValue(context.Background(), otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			_ = handler.Handle(ec)
			require.Equal(t, tt.expectedStatus, rec.Code, "body=%s", rec.Body.String())

			if tt.expectedStatus != http.StatusCreated {
				return
			}
			var got model.APITaskRun
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, tt.mockResp.GetId().GetId(), got.ID)
			assert.Equal(t, "fw-rollout", got.Name)
			assert.Equal(t, model.APIOperationTypeFirmwareControl, got.OperationType)
			assert.Equal(t, model.TaskRunStatusPending, got.Status)
		})
	}
}

func TestGetTaskRunHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testRackInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testRackSetupTestData(t, dbSession, org)
	providerUser := testRackBuildUser(t, dbSession, "provider-user-run-get", org, []string{authz.ProviderAdminRole})
	tenantUser := testRackBuildUser(t, dbSession, "tenant-user-run-get", org, []string{authz.TenantAdminRole})

	handler := NewGetTaskRunHandler(dbSession, nil, scp, cfg)
	runID := uuid.New().String()
	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")

	found := &flowv1.OperationRun{
		Summary: &flowv1.OperationRunSummary{
			Id:    &flowv1.UUID{Id: runID},
			Name:  "fw-rollout",
			State: &flowv1.OperationRunState{Status: flowv1.OperationRunStatus_OPERATION_RUN_STATUS_RUNNING},
		},
	}

	tests := []struct {
		name           string
		user           *cdbm.User
		runID          string
		queryParams    map[string]string
		mockRun        *flowv1.OperationRun
		expectedStatus int
	}{
		{
			name:           "success - 200 with run",
			user:           providerUser,
			runID:          runID,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			mockRun:        found,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "failure - run not found",
			user:           providerUser,
			runID:          runID,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			mockRun:        &flowv1.OperationRun{},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "failure - missing siteId",
			user:           providerUser,
			runID:          runID,
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - invalid run UUID",
			user:           providerUser,
			runID:          "not-a-uuid",
			queryParams:    map[string]string{"siteId": site.ID.String()},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			user:           tenantUser,
			runID:          runID,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTC := &tmocks.Client{}
			mockRun := &tmocks.WorkflowRun{}
			mockRun.On("GetID").Return("test-workflow-id")
			if tt.mockRun != nil {
				src := tt.mockRun
				mockRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.GetOperationRunResponse)
					resp.OperationRun = src
				}).Return(nil)
			}
			mockTC.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "GetTaskRun", mock.Anything).Return(mockRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTC

			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			path := fmt.Sprintf("/v2/org/%s/nico/task/run/%s?%s", org, tt.runID, q.Encode())
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(org, tt.runID)
			ec.Set("user", tt.user)
			ctx := context.WithValue(context.Background(), otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			_ = handler.Handle(ec)
			require.Equal(t, tt.expectedStatus, rec.Code, "body=%s", rec.Body.String())

			if tt.expectedStatus != http.StatusOK {
				return
			}
			var got model.APITaskRun
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, runID, got.ID)
			assert.Equal(t, "fw-rollout", got.Name)
			assert.Equal(t, model.TaskRunStatusRunning, got.Status)
		})
	}
}

func TestGetAllTaskRunHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testRackInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testRackSetupTestData(t, dbSession, org)
	providerUser := testRackBuildUser(t, dbSession, "provider-user-run-list", org, []string{authz.ProviderAdminRole})
	tenantUser := testRackBuildUser(t, dbSession, "tenant-user-run-list", org, []string{authz.TenantAdminRole})

	handler := NewGetAllTaskRunHandler(dbSession, nil, scp, cfg)
	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")

	listed := []*flowv1.OperationRunSummary{
		{
			Id:    &flowv1.UUID{Id: uuid.New().String()},
			Name:  "fw-rollout",
			State: &flowv1.OperationRunState{Status: flowv1.OperationRunStatus_OPERATION_RUN_STATUS_RUNNING},
		},
	}

	tests := []struct {
		name           string
		user           *cdbm.User
		queryParams    map[string]string
		mockRuns       []*flowv1.OperationRunSummary
		expectedStatus int
	}{
		{
			name:           "success - list",
			user:           providerUser,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			mockRuns:       listed,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "success - filters pass through",
			user:           providerUser,
			queryParams:    map[string]string{"siteId": site.ID.String(), "status": "Running", "operationType": string(model.APIOperationTypeFirmwareControl)},
			mockRuns:       listed,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "failure - missing siteId",
			user:           providerUser,
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - invalid status",
			user:           providerUser,
			queryParams:    map[string]string{"siteId": site.ID.String(), "status": "bogus"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			user:           tenantUser,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTC := &tmocks.Client{}
			mockRun := &tmocks.WorkflowRun{}
			mockRun.On("GetID").Return("test-workflow-id")
			if tt.mockRuns != nil {
				mockRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.ListOperationRunsResponse)
					resp.OperationRuns = tt.mockRuns
					resp.Total = int32(len(tt.mockRuns))
				}).Return(nil)
			}
			mockTC.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "GetAllTaskRuns", mock.Anything).Return(mockRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTC

			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			path := fmt.Sprintf("/v2/org/%s/nico/task/run?%s", org, q.Encode())
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(org)
			ec.Set("user", tt.user)
			ctx := context.WithValue(context.Background(), otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			_ = handler.Handle(ec)
			require.Equal(t, tt.expectedStatus, rec.Code, "body=%s", rec.Body.String())

			if tt.expectedStatus != http.StatusOK {
				return
			}
			var got []*model.APITaskRun
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			require.Len(t, got, len(tt.mockRuns))
			require.NotEmpty(t, rec.Header().Get("X-Pagination"))
		})
	}
}

func TestGetAllTaskRunTargetHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testRackInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testRackSetupTestData(t, dbSession, org)
	providerUser := testRackBuildUser(t, dbSession, "provider-user-run-targets", org, []string{authz.ProviderAdminRole})
	tenantUser := testRackBuildUser(t, dbSession, "tenant-user-run-targets", org, []string{authz.TenantAdminRole})

	handler := NewGetAllTaskRunTargetHandler(dbSession, nil, scp, cfg)
	runID := uuid.New().String()
	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")

	listed := []*flowv1.OperationRunTarget{
		{
			Id:             &flowv1.UUID{Id: uuid.New().String()},
			OperationRunId: &flowv1.UUID{Id: runID},
			RackId:         &flowv1.UUID{Id: uuid.New().String()},
			Status:         flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_SUBMITTED,
		},
	}

	tests := []struct {
		name           string
		user           *cdbm.User
		runID          string
		queryParams    map[string]string
		mockTargets    []*flowv1.OperationRunTarget
		expectedStatus int
	}{
		{
			name:           "success - list targets",
			user:           providerUser,
			runID:          runID,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			mockTargets:    listed,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "failure - invalid run UUID",
			user:           providerUser,
			runID:          "not-a-uuid",
			queryParams:    map[string]string{"siteId": site.ID.String()},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - missing siteId",
			user:           providerUser,
			runID:          runID,
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - invalid phaseScope",
			user:           providerUser,
			runID:          runID,
			queryParams:    map[string]string{"siteId": site.ID.String(), "phaseScope": "bogus"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			user:           tenantUser,
			runID:          runID,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTC := &tmocks.Client{}
			mockRun := &tmocks.WorkflowRun{}
			mockRun.On("GetID").Return("test-workflow-id")
			if tt.mockTargets != nil {
				mockRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.ListOperationRunTargetsResponse)
					resp.Targets = tt.mockTargets
					resp.Total = int32(len(tt.mockTargets))
				}).Return(nil)
			}
			mockTC.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "GetAllTaskRunTargets", mock.Anything).Return(mockRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTC

			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			path := fmt.Sprintf("/v2/org/%s/nico/task/run/%s/target?%s", org, tt.runID, q.Encode())
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(org, tt.runID)
			ec.Set("user", tt.user)
			ctx := context.WithValue(context.Background(), otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			_ = handler.Handle(ec)
			require.Equal(t, tt.expectedStatus, rec.Code, "body=%s", rec.Body.String())

			if tt.expectedStatus != http.StatusOK {
				return
			}
			var got []*model.APITaskRunTarget
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			require.Len(t, got, len(tt.mockTargets))
			require.NotEmpty(t, rec.Header().Get("X-Pagination"))
		})
	}
}

// TestRunLifecycleHandlers_Handle covers the pause/resume/advance/cancel
// actions, which share a shape: POST with a siteId body, 202 with the
// run's last known state on success.
func TestRunLifecycleHandlers_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testRackInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testRackSetupTestData(t, dbSession, org)
	providerUser := testRackBuildUser(t, dbSession, "provider-user-run-lifecycle", org, []string{authz.ProviderAdminRole})
	tenantUser := testRackBuildUser(t, dbSession, "tenant-user-run-lifecycle", org, []string{authz.TenantAdminRole})

	runID := uuid.New().String()
	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")

	validBody := func(action string) any {
		switch action {
		case "advance":
			return model.APITaskRunAdvanceRequest{SiteID: site.ID.String()}
		case "cancel":
			return model.APITaskRunCancelRequest{SiteID: site.ID.String(), Reason: "operator"}
		default:
			return model.APITaskRunSiteRequest{SiteID: site.ID.String()}
		}
	}
	emptySiteBody := func(action string) any {
		switch action {
		case "advance":
			return model.APITaskRunAdvanceRequest{}
		case "cancel":
			return model.APITaskRunCancelRequest{}
		default:
			return model.APITaskRunSiteRequest{}
		}
	}

	actions := []struct {
		action   string
		workflow string
		handle   func(echo.Context) error
	}{
		{"pause", "PauseTaskRun", NewPauseTaskRunHandler(dbSession, nil, scp, cfg).Handle},
		{"resume", "ResumeTaskRun", NewResumeTaskRunHandler(dbSession, nil, scp, cfg).Handle},
		{"advance", "AdvanceTaskRunPhase", NewAdvanceTaskRunPhaseHandler(dbSession, nil, scp, cfg).Handle},
		{"cancel", "CancelTaskRun", NewCancelTaskRunHandler(dbSession, nil, scp, cfg).Handle},
	}

	for _, act := range actions {
		cases := []struct {
			name           string
			user           *cdbm.User
			runID          string
			body           any
			mockExecErr    error
			expectedStatus int
		}{
			{name: "success - 202", user: providerUser, runID: runID, body: validBody(act.action), expectedStatus: http.StatusAccepted},
			{name: "failure - invalid run UUID", user: providerUser, runID: "not-a-uuid", body: validBody(act.action), expectedStatus: http.StatusBadRequest},
			{name: "failure - missing siteId", user: providerUser, runID: runID, body: emptySiteBody(act.action), expectedStatus: http.StatusBadRequest},
			{name: "failure - tenant access denied", user: tenantUser, runID: runID, body: validBody(act.action), expectedStatus: http.StatusForbidden},
			{name: "failure - workflow scheduling error", user: providerUser, runID: runID, body: validBody(act.action), mockExecErr: errors.New("temporal scheduling failed"), expectedStatus: http.StatusInternalServerError},
		}

		for _, tt := range cases {
			t.Run(fmt.Sprintf("%s/%s", act.action, tt.name), func(t *testing.T) {
				mockTC := &tmocks.Client{}
				mockRun := &tmocks.WorkflowRun{}
				mockRun.On("GetID").Return("test-workflow-id")
				mockRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.OperationRun)
					resp.Summary = &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: runID}}
				}).Return(nil)
				mockTC.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, act.workflow, mock.Anything).Return(mockRun, tt.mockExecErr)
				scp.IDClientMap[site.ID.String()] = mockTC

				bodyBytes, err := json.Marshal(tt.body)
				require.NoError(t, err)
				path := fmt.Sprintf("/v2/org/%s/nico/task/run/%s/%s", org, tt.runID, act.action)
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(bodyBytes))
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
				rec := httptest.NewRecorder()
				ec := e.NewContext(req, rec)
				ec.SetParamNames("orgName", "id")
				ec.SetParamValues(org, tt.runID)
				ec.Set("user", tt.user)
				ctx := context.WithValue(context.Background(), otelecho.TracerKey, tracer)
				ec.SetRequest(ec.Request().WithContext(ctx))

				_ = act.handle(ec)
				require.Equal(t, tt.expectedStatus, rec.Code, "body=%s", rec.Body.String())

				if tt.expectedStatus != http.StatusAccepted {
					return
				}
				var got model.APITaskRun
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
				assert.Equal(t, runID, got.ID)
			})
		}
	}
}
