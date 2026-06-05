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
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

func TestGetTaskHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testRackInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testRackSetupTestData(t, dbSession, org)

	siteNoRLA := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site-no-flow",
		Org:                      org,
		InfrastructureProviderID: site.InfrastructureProviderID,
		Status:                   cdbm.SiteStatusRegistered,
		Config:                   &cdbm.SiteConfig{},
	}
	_, err := dbSession.DB.NewInsert().Model(siteNoRLA).Exec(context.Background())
	assert.Nil(t, err)

	providerUser := testRackBuildUser(t, dbSession, "provider-user-task-get", org, []string{authz.ProviderAdminRole})
	tenantUser := testRackBuildUser(t, dbSession, "tenant-user-task-get", org, []string{authz.TenantAdminRole})

	handler := NewGetTaskHandler(dbSession, nil, scp, cfg)

	taskUUID := uuid.New().String()

	mockTask := &flowv1.Task{
		Id:          &flowv1.UUID{Id: taskUUID},
		Operation:   "power_on",
		RackId:      &flowv1.UUID{Id: uuid.New().String()},
		Description: "Power on rack",
		Status:      flowv1.TaskStatus_TASK_STATUS_RUNNING,
		Message:     "Processing",
	}

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		taskUUID       string
		queryParams    map[string]string
		mockTasks      []*flowv1.Task
		expectedStatus int
	}{
		{
			name:     "success - get task by ID",
			reqOrg:   org,
			user:     providerUser,
			taskUUID: taskUUID,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			mockTasks:      []*flowv1.Task{mockTask},
			expectedStatus: http.StatusOK,
		},
		{
			name:     "failure - task not found (empty result)",
			reqOrg:   org,
			user:     providerUser,
			taskUUID: taskUUID,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			mockTasks:      []*flowv1.Task{},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:     "failure - Flow not enabled on site",
			reqOrg:   org,
			user:     providerUser,
			taskUUID: taskUUID,
			queryParams: map[string]string{
				"siteId": siteNoRLA.ID.String(),
			},
			expectedStatus: http.StatusPreconditionFailed,
		},
		{
			name:        "failure - missing siteId",
			reqOrg:      org,
			user:        providerUser,
			taskUUID:    taskUUID,
			queryParams: map[string]string{
				// no siteId
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:     "failure - invalid siteId",
			reqOrg:   org,
			user:     providerUser,
			taskUUID: taskUUID,
			queryParams: map[string]string{
				"siteId": uuid.New().String(),
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:     "failure - tenant access denied",
			reqOrg:   org,
			user:     tenantUser,
			taskUUID: taskUUID,
			queryParams: map[string]string{
				"siteId": site.ID.String(),
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			if tt.mockTasks != nil {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.GetTasksByIDsResponse)
					resp.Tasks = tt.mockTasks
				}).Return(nil)
			}
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "GetTask", mock.Anything).Return(mockWorkflowRun, nil)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			path := fmt.Sprintf("/v2/org/%s/nico/rack/task/%s?%s", tt.reqOrg, tt.taskUUID, q.Encode())

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tt.reqOrg, tt.taskUUID)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handler.Handle(ec)

			if tt.expectedStatus != rec.Code {
				t.Errorf("GetTaskHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}

			var apiTask model.APIRackTask
			err = json.Unmarshal(rec.Body.Bytes(), &apiTask)
			assert.NoError(t, err)
			assert.Equal(t, taskUUID, apiTask.ID)
			assert.Equal(t, "Running", apiTask.Status)
			assert.Equal(t, "Power on rack", apiTask.Description)
			assert.Equal(t, "Processing", apiTask.Message)
		})
	}
}

// ExecuteGetTasksHandlerTestCases exercises GetRackTasksHandler and GetTrayTasksHandler
// with a shared case matrix. pathFmt and the path parameter differ per handler;
// both invoke the GetTasks workflow and use the same Temporal mock expectation.
type GetTasksHandlerTestCase struct {
	name           string
	reqOrg         string
	user           *cdbm.User
	pathParam      string
	queryParams    map[string]string
	mockTasks      []*flowv1.Task
	expectedStatus int
	assertFlowReq  func(t *testing.T, req *flowv1.ListTasksRequest, pathParam string)
}

func ExecuteGetTasksHandlerTestCases(t *testing.T, pathFmt string, handle func(echo.Context) error, scp *sc.ClientPool, siteID string, testCases []GetTasksHandlerTestCase) {
	t.Helper()
	e := echo.New()
	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			if tt.mockTasks != nil {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.ListTasksResponse)
					resp.Tasks = tt.mockTasks
					resp.Total = int32(len(tt.mockTasks))
				}).Return(nil)
			}
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "GetTasks", mock.Anything).
				Run(func(args mock.Arguments) {
					if tt.assertFlowReq != nil {
						req, ok := args.Get(3).(*flowv1.ListTasksRequest)
						require.True(t, ok, "workflow arg must be *flowv1.ListTasksRequest")
						tt.assertFlowReq(t, req, tt.pathParam)
					}
				}).
				Return(mockWorkflowRun, nil)
			scp.IDClientMap[siteID] = mockTemporalClient

			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}
			path := fmt.Sprintf(pathFmt, tt.reqOrg, tt.pathParam) + "?" + q.Encode()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tt.reqOrg, tt.pathParam)
			ec.Set("user", tt.user)

			ctx := context.WithValue(context.Background(), otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err := handle(ec)
			require.Equal(t, tt.expectedStatus, rec.Code, "body=%s err=%v", rec.Body.String(), err)

			if tt.expectedStatus != http.StatusOK {
				return
			}
			var tasks []model.APIRackTask
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tasks))
			require.Len(t, tasks, len(tt.mockTasks))
			require.NotEmpty(t, rec.Header().Get("X-Pagination"), "X-Pagination")
		})
	}
}

func TestGetRackTasksHandler_Handle(t *testing.T) {
	dbSession := testRackInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testRackSetupTestData(t, dbSession, org)

	providerUser := testRackBuildUser(t, dbSession, "provider-user-task-list-rack", org, []string{authz.ProviderAdminRole})
	tenantUser := testRackBuildUser(t, dbSession, "tenant-user-task-list-rack", org, []string{authz.TenantAdminRole})

	handler := NewGetRackTasksHandler(dbSession, nil, scp, cfg)
	rackID := uuid.New().String()
	taskUUID := uuid.New().String()
	listed := []*flowv1.Task{{
		Id:          &flowv1.UUID{Id: taskUUID},
		RackId:      &flowv1.UUID{Id: rackID},
		Description: "Power on rack",
		Status:      flowv1.TaskStatus_TASK_STATUS_RUNNING,
	}}

	cases := []GetTasksHandlerTestCase{
		{
			name:           "success - list rack tasks",
			reqOrg:         org,
			user:           providerUser,
			pathParam:      rackID,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			mockTasks:      listed,
			expectedStatus: http.StatusOK,
			assertFlowReq: func(t *testing.T, req *flowv1.ListTasksRequest, pathParam string) {
				t.Helper()
				require.NotNil(t, req.GetRackId())
				assert.Equal(t, pathParam, req.GetRackId().GetId())
				assert.Nil(t, req.GetComponentId())
				assert.False(t, req.GetActiveOnly())
			},
		},
		{
			name:           "success - active-only filter pass-through",
			reqOrg:         org,
			user:           providerUser,
			pathParam:      rackID,
			queryParams:    map[string]string{"siteId": site.ID.String(), "activeOnly": "true"},
			mockTasks:      listed,
			expectedStatus: http.StatusOK,
			assertFlowReq: func(t *testing.T, req *flowv1.ListTasksRequest, pathParam string) {
				t.Helper()
				require.NotNil(t, req.GetRackId())
				assert.Equal(t, pathParam, req.GetRackId().GetId())
				assert.True(t, req.GetActiveOnly())
			},
		},
		{
			name:           "failure - invalid rack UUID",
			reqOrg:         org,
			user:           providerUser,
			pathParam:      "not-a-uuid",
			queryParams:    map[string]string{"siteId": site.ID.String()},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - missing siteId",
			reqOrg:         org,
			user:           providerUser,
			pathParam:      rackID,
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			reqOrg:         org,
			user:           tenantUser,
			pathParam:      rackID,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			expectedStatus: http.StatusForbidden,
		},
	}

	ExecuteGetTasksHandlerTestCases(t, "/v2/org/%s/nico/rack/%s/task", handler.Handle, scp, site.ID.String(), cases)
}

func TestGetTrayTasksHandler_Handle(t *testing.T) {
	dbSession := testRackInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testRackSetupTestData(t, dbSession, org)

	providerUser := testRackBuildUser(t, dbSession, "provider-user-task-list-tray", org, []string{authz.ProviderAdminRole})
	tenantUser := testRackBuildUser(t, dbSession, "tenant-user-task-list-tray", org, []string{authz.TenantAdminRole})

	handler := NewGetTrayTasksHandler(dbSession, nil, scp, cfg)
	trayID := uuid.New().String()
	taskUUID := uuid.New().String()
	listed := []*flowv1.Task{{
		Id:          &flowv1.UUID{Id: taskUUID},
		RackId:      &flowv1.UUID{Id: uuid.New().String()},
		Description: "Update tray firmware",
		Status:      flowv1.TaskStatus_TASK_STATUS_PENDING,
	}}

	cases := []GetTasksHandlerTestCase{
		{
			name:           "success - list tray tasks",
			reqOrg:         org,
			user:           providerUser,
			pathParam:      trayID,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			mockTasks:      listed,
			expectedStatus: http.StatusOK,
			assertFlowReq: func(t *testing.T, req *flowv1.ListTasksRequest, pathParam string) {
				t.Helper()
				require.NotNil(t, req.GetComponentId())
				assert.Equal(t, pathParam, req.GetComponentId().GetId())
				assert.Nil(t, req.GetRackId())
			},
		},
		{
			name:           "failure - invalid tray UUID",
			reqOrg:         org,
			user:           providerUser,
			pathParam:      "not-a-uuid",
			queryParams:    map[string]string{"siteId": site.ID.String()},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - missing siteId",
			reqOrg:         org,
			user:           providerUser,
			pathParam:      trayID,
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			reqOrg:         org,
			user:           tenantUser,
			pathParam:      trayID,
			queryParams:    map[string]string{"siteId": site.ID.String()},
			expectedStatus: http.StatusForbidden,
		},
	}

	ExecuteGetTasksHandlerTestCases(t, "/v2/org/%s/nico/tray/%s/task", handler.Handle, scp, site.ID.String(), cases)
}

func TestCancelTaskHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testRackInitDB(t)
	defer dbSession.Close()

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	org := "test-org"
	_, site, _ := testRackSetupTestData(t, dbSession, org)

	siteNoRLA := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site-no-flow-cancel",
		Org:                      org,
		InfrastructureProviderID: site.InfrastructureProviderID,
		Status:                   cdbm.SiteStatusRegistered,
		Config:                   &cdbm.SiteConfig{},
	}
	_, err := dbSession.DB.NewInsert().Model(siteNoRLA).Exec(context.Background())
	assert.Nil(t, err)

	providerUser := testRackBuildUser(t, dbSession, "provider-user-task-cancel", org, []string{authz.ProviderAdminRole})
	tenantUser := testRackBuildUser(t, dbSession, "tenant-user-task-cancel", org, []string{authz.TenantAdminRole})

	handler := NewCancelTaskHandler(dbSession, nil, scp, cfg)

	taskUUID := uuid.New().String()

	cancelledTask := &flowv1.Task{
		Id:          &flowv1.UUID{Id: taskUUID},
		Operation:   "power_on",
		RackId:      &flowv1.UUID{Id: uuid.New().String()},
		Description: "Power on rack",
		Status:      flowv1.TaskStatus_TASK_STATUS_TERMINATED,
		Message:     "Cancelled by user",
	}

	tracer := oteltrace.NewNoopTracerProvider().Tracer("test")
	ctx := context.Background()

	tests := []struct {
		name           string
		reqOrg         string
		user           *cdbm.User
		taskUUID       string
		body           any
		mockTask       *flowv1.Task
		mockExecErr    error
		expectedStatus int
	}{
		{
			name:           "success - cancel task returns 202 Accepted",
			reqOrg:         org,
			user:           providerUser,
			taskUUID:       taskUUID,
			body:           model.APICancelTaskRequest{SiteID: site.ID.String()},
			mockTask:       cancelledTask,
			expectedStatus: http.StatusAccepted,
		},
		{
			name:           "failure - Flow not enabled on site",
			reqOrg:         org,
			user:           providerUser,
			taskUUID:       taskUUID,
			body:           model.APICancelTaskRequest{SiteID: siteNoRLA.ID.String()},
			expectedStatus: http.StatusPreconditionFailed,
		},
		{
			name:           "failure - missing siteId",
			reqOrg:         org,
			user:           providerUser,
			taskUUID:       taskUUID,
			body:           model.APICancelTaskRequest{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - invalid siteId",
			reqOrg:         org,
			user:           providerUser,
			taskUUID:       taskUUID,
			body:           model.APICancelTaskRequest{SiteID: uuid.New().String()},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - invalid task UUID",
			reqOrg:         org,
			user:           providerUser,
			taskUUID:       "not-a-uuid",
			body:           model.APICancelTaskRequest{SiteID: site.ID.String()},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "failure - tenant access denied",
			reqOrg:         org,
			user:           tenantUser,
			taskUUID:       taskUUID,
			body:           model.APICancelTaskRequest{SiteID: site.ID.String()},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "failure - workflow scheduling error",
			reqOrg:         org,
			user:           providerUser,
			taskUUID:       taskUUID,
			body:           model.APICancelTaskRequest{SiteID: site.ID.String()},
			mockExecErr:    errors.New("temporal scheduling failed"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTemporalClient := &tmocks.Client{}
			mockWorkflowRun := &tmocks.WorkflowRun{}
			mockWorkflowRun.On("GetID").Return("test-workflow-id")
			if tt.mockTask != nil {
				mockWorkflowRun.Mock.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					resp := args.Get(1).(*flowv1.CancelTaskResponse)
					resp.Task = tt.mockTask
				}).Return(nil)
			}
			mockTemporalClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.Anything, "CancelTask", mock.Anything).Return(mockWorkflowRun, tt.mockExecErr)
			scp.IDClientMap[site.ID.String()] = mockTemporalClient

			path := fmt.Sprintf("/v2/org/%s/nico/rack/task/%s/cancel", tt.reqOrg, tt.taskUUID)

			bodyBytes, err := json.Marshal(tt.body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(bodyBytes))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "id")
			ec.SetParamValues(tt.reqOrg, tt.taskUUID)
			ec.Set("user", tt.user)

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			err = handler.Handle(ec)

			if tt.expectedStatus != rec.Code {
				t.Errorf("CancelTaskHandler.Handle() status = %v, want %v, response: %v, err: %v", rec.Code, tt.expectedStatus, rec.Body.String(), err)
			}

			require.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != http.StatusAccepted {
				return
			}

			var apiTask model.APIRackTask
			err = json.Unmarshal(rec.Body.Bytes(), &apiTask)
			assert.NoError(t, err)
			assert.Equal(t, taskUUID, apiTask.ID)
			assert.Equal(t, "Terminated", apiTask.Status)
			assert.Equal(t, "Cancelled by user", apiTask.Message)
		})
	}
}
