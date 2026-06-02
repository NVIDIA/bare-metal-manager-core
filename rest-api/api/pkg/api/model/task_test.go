// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
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
