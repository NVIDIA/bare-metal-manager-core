// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/pagination"
)

func TestNewAPIRackTask(t *testing.T) {
	tests := []struct {
		name     string
		task     *flowv1.Task
		expected *APIRackTask
	}{
		{
			name:     "nil task returns empty APIRackTask",
			task:     nil,
			expected: &APIRackTask{},
		},
		{
			name: "task with all fields",
			task: &flowv1.Task{
				Id:          &flowv1.UUID{Id: "task-123"},
				Operation:   "power_on",
				RackId:      &flowv1.UUID{Id: "rack-456"},
				Description: "Power on rack components",
				Status:      flowv1.TaskStatus_TASK_STATUS_RUNNING,
				Message:     "Processing 3 of 5 components",
			},
			expected: &APIRackTask{
				ID:          "task-123",
				Status:      "Running",
				Description: "Power on rack components",
				Message:     "Processing 3 of 5 components",
			},
		},
		{
			name: "task with pending status",
			task: &flowv1.Task{
				Id:          &flowv1.UUID{Id: "task-001"},
				Description: "Firmware upgrade",
				Status:      flowv1.TaskStatus_TASK_STATUS_PENDING,
			},
			expected: &APIRackTask{
				ID:          "task-001",
				Status:      "Pending",
				Description: "Firmware upgrade",
			},
		},
		{
			name: "task with completed status maps to succeeded",
			task: &flowv1.Task{
				Id:          &flowv1.UUID{Id: "task-002"},
				Description: "Bring up rack",
				Status:      flowv1.TaskStatus_TASK_STATUS_COMPLETED,
				Message:     "All components ready",
			},
			expected: &APIRackTask{
				ID:          "task-002",
				Status:      "Succeeded",
				Description: "Bring up rack",
				Message:     "All components ready",
			},
		},
		{
			name: "task with failed status",
			task: &flowv1.Task{
				Id:          &flowv1.UUID{Id: "task-003"},
				Description: "Power off rack",
				Status:      flowv1.TaskStatus_TASK_STATUS_FAILED,
				Message:     "BMC unreachable",
			},
			expected: &APIRackTask{
				ID:          "task-003",
				Status:      "Failed",
				Description: "Power off rack",
				Message:     "BMC unreachable",
			},
		},
		{
			name: "task with unknown status",
			task: &flowv1.Task{
				Id:     &flowv1.UUID{Id: "task-004"},
				Status: flowv1.TaskStatus_TASK_STATUS_UNKNOWN,
			},
			expected: &APIRackTask{
				ID:     "task-004",
				Status: "Unknown",
			},
		},
		{
			name: "task with nil ID",
			task: &flowv1.Task{
				Description: "Orphan task",
				Status:      flowv1.TaskStatus_TASK_STATUS_PENDING,
			},
			expected: &APIRackTask{
				Status:      "Pending",
				Description: "Orphan task",
			},
		},
		{
			name: "task with terminated status",
			task: &flowv1.Task{
				Id:      &flowv1.UUID{Id: "task-005"},
				Status:  flowv1.TaskStatus_TASK_STATUS_TERMINATED,
				Message: "Expired: queue timeout reached",
			},
			expected: &APIRackTask{
				ID:      "task-005",
				Status:  "Terminated",
				Message: "Expired: queue timeout reached",
			},
		},
		{
			name: "task with waiting status",
			task: &flowv1.Task{
				Id:     &flowv1.UUID{Id: "task-006"},
				Status: flowv1.TaskStatus_TASK_STATUS_WAITING,
			},
			expected: &APIRackTask{
				ID:     "task-006",
				Status: "Waiting",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewAPIRackTask(tt.task)
			assert.NotNil(t, result)
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.Status, result.Status)
			assert.Equal(t, tt.expected.Description, result.Description)
			assert.Equal(t, tt.expected.Message, result.Message)
			assert.Nil(t, result.Started)
			assert.Nil(t, result.Finished)
		})
	}
}

func TestNewAPIRackTask_Timestamps(t *testing.T) {
	createdTime := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	updatedTime := time.Date(2026, 1, 1, 9, 30, 0, 0, time.UTC)
	startTime := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	endTime := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)

	task := &flowv1.Task{
		Id:         &flowv1.UUID{Id: "task-ts"},
		Status:     flowv1.TaskStatus_TASK_STATUS_COMPLETED,
		CreatedAt:  timestamppb.New(createdTime),
		UpdatedAt:  timestamppb.New(updatedTime),
		StartedAt:  timestamppb.New(startTime),
		FinishedAt: timestamppb.New(endTime),
	}

	result := NewAPIRackTask(task)

	assert.True(t, result.Created.Equal(createdTime))
	assert.True(t, result.Updated.Equal(updatedTime))
	assert.NotNil(t, result.Started)
	assert.NotNil(t, result.Finished)
	assert.True(t, result.Started.Equal(startTime))
	assert.True(t, result.Finished.Equal(endTime))
}

func TestNewAPIRackTask_Report(t *testing.T) {
	t.Run("report omitted by default", func(t *testing.T) {
		task := &flowv1.Task{
			Id:     &flowv1.UUID{Id: "task-rep-1"},
			Status: flowv1.TaskStatus_TASK_STATUS_RUNNING,
			Report: `{"version":1,"stages":[]}`,
		}

		result := NewAPIRackTask(task)

		assert.Nil(t, result.Report, "Report must default to nil so the JSON field is omitted")
	})

	t.Run("WithReport populates from non-empty proto report", func(t *testing.T) {
		body := `{"version":1,"stages":[{"name":"reset","status":"Succeeded"}]}`
		task := &flowv1.Task{
			Id:     &flowv1.UUID{Id: "task-rep-2"},
			Status: flowv1.TaskStatus_TASK_STATUS_RUNNING,
			Report: body,
		}

		result := NewAPIRackTask(task, WithReport())

		assert.NotNil(t, result.Report)
		assert.JSONEq(t, body, string(*result.Report))
	})

	t.Run("WithReport on empty proto report still yields nil", func(t *testing.T) {
		task := &flowv1.Task{
			Id:     &flowv1.UUID{Id: "task-rep-3"},
			Status: flowv1.TaskStatus_TASK_STATUS_PENDING,
		}

		result := NewAPIRackTask(task, WithReport())

		assert.Nil(t, result.Report, "Empty proto report must not surface as an empty JSON value")
	})
}

func TestBuildAPIRackTaskOptions(t *testing.T) {
	t.Run("default request yields no options", func(t *testing.T) {
		opts := BuildAPIRackTaskOptions(APIGetTasksRequest{SiteID: "s"})
		assert.Empty(t, opts)
	})

	t.Run("withReport=true yields WithReport()", func(t *testing.T) {
		opts := BuildAPIRackTaskOptions(APIGetTasksRequest{SiteID: "s", WithReport: true})
		require.Len(t, opts, 1)

		// The option must surface APIRackTask.Report when the proto report is non-empty.
		task := &flowv1.Task{
			Id:     &flowv1.UUID{Id: "task-built"},
			Status: flowv1.TaskStatus_TASK_STATUS_RUNNING,
			Report: `{"version":1}`,
		}
		got := NewAPIRackTask(task, opts...)
		require.NotNil(t, got.Report)
		assert.JSONEq(t, `{"version":1}`, string(*got.Report))
	})
}

func TestAPIGetTasksRequest_QueryValues(t *testing.T) {
	t.Run("withReport=true surfaces in query values", func(t *testing.T) {
		req := APIGetTasksRequest{SiteID: "site-x", WithReport: true}
		v := req.QueryValues(pagination.PageRequest{})

		assert.Equal(t, "true", v.Get("withReport"))
		assert.Equal(t, "site-x", v.Get("siteId"))
	})

	t.Run("withReport=false is omitted from query values", func(t *testing.T) {
		req := APIGetTasksRequest{SiteID: "site-y"}
		v := req.QueryValues(pagination.PageRequest{})

		assert.Empty(t, v.Get("withReport"))
		assert.False(t, v.Has("withReport"), "Default-false withReport must not affect deterministic workflow ID hashing")
	})
}

func TestAPIGetTaskRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		request APIGetTaskRequest
		wantErr bool
	}{
		{
			name:    "valid request",
			request: APIGetTaskRequest{SiteID: "550e8400-e29b-41d4-a716-446655440000"},
			wantErr: false,
		},
		{
			name:    "missing siteId",
			request: APIGetTaskRequest{},
			wantErr: true,
		},
		{
			name:    "empty siteId",
			request: APIGetTaskRequest{SiteID: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
