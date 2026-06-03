// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	"github.com/stretchr/testify/assert"
)

func TestManageTask_GetTaskFromFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.GetTasksByIDsRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty get task request",
		},
		{
			name: "request with empty task IDs returns error",
			request: &flowv1.GetTasksByIDsRequest{
				TaskIds: []*flowv1.UUID{},
			},
			wantErr:     true,
			errContains: "without task IDs",
		},
		{
			name: "successful request - single task",
			request: &flowv1.GetTasksByIDsRequest{
				TaskIds: []*flowv1.UUID{{Id: "test-task-id"}},
			},
			wantErr: false,
		},
		{
			name: "successful request - multiple task IDs",
			request: &flowv1.GetTasksByIDsRequest{
				TaskIds: []*flowv1.UUID{
					{Id: "task-1"},
					{Id: "task-2"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
			manageTask := NewManageTask(flowGrpcAtomicClient)

			ctx := context.Background()
			result, err := manageTask.GetTaskFromFlow(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, len(tt.request.GetTaskIds()), len(result.GetTasks()))
		})
	}
}

func TestManageTask_CancelTaskOnFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.CancelTaskRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty cancel task request",
		},
		{
			name:        "request with nil task ID returns error",
			request:     &flowv1.CancelTaskRequest{},
			wantErr:     true,
			errContains: "without task ID",
		},
		{
			name: "request with empty task ID returns error",
			request: &flowv1.CancelTaskRequest{
				TaskId: &flowv1.UUID{Id: ""},
			},
			wantErr:     true,
			errContains: "without task ID",
		},
		{
			name: "successful request",
			request: &flowv1.CancelTaskRequest{
				TaskId: &flowv1.UUID{Id: "test-task-id"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
			manageTask := NewManageTask(flowGrpcAtomicClient)

			ctx := context.Background()
			result, err := manageTask.CancelTaskOnFlow(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotNil(t, result.GetTask())
			assert.Equal(t, tt.request.GetTaskId().GetId(), result.GetTask().GetId().GetId())
			assert.Equal(t, flowv1.TaskStatus_TASK_STATUS_TERMINATED, result.GetTask().GetStatus())
		})
	}
}

func TestManageTask_GetTasksFromFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.ListTasksRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty list tasks request",
		},
		{
			name:    "successful request",
			request: &flowv1.ListTasksRequest{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
			manageTask := NewManageTask(flowGrpcAtomicClient)

			ctx := context.Background()
			result, err := manageTask.GetTasksFromFlow(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}
