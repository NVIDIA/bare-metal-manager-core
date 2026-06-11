// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

func ptrOperationType(v flowv1.OperationType) *flowv1.OperationType { return &v }

func newManageRuleForTest() ManageTaskRule {
	mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
	flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
	flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
	return NewManageRule(flowGrpcAtomicClient)
}

func TestManageRule_CreateOperationRuleOnFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.CreateOperationRuleRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty create operation rule request",
		},
		{
			name: "successful request",
			request: &flowv1.CreateOperationRuleRequest{
				Name:               "test-rule",
				OperationType:      flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL,
				OperationCode:      "power_on",
				RuleDefinitionJson: `{"stages":[]}`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := newManageRuleForTest()
			result, err := mr.CreateTaskRuleOnFlow(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.GetId().GetId())
		})
	}
}

func TestManageRule_GetOperationRuleFromFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.GetOperationRuleRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty get operation rule request",
		},
		{
			name:        "missing rule ID returns error",
			request:     &flowv1.GetOperationRuleRequest{},
			wantErr:     true,
			errContains: "without rule ID",
		},
		{
			name: "empty rule ID returns error",
			request: &flowv1.GetOperationRuleRequest{
				RuleId: &flowv1.UUID{Id: ""},
			},
			wantErr:     true,
			errContains: "without rule ID",
		},
		{
			name: "successful request",
			request: &flowv1.GetOperationRuleRequest{
				RuleId: &flowv1.UUID{Id: "test-rule-id"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := newManageRuleForTest()
			result, err := mr.GetTaskRuleFromFlow(context.Background(), tt.request)

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

func TestManageRule_ListOperationRulesFromFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.ListOperationRulesRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty list operation rules request",
		},
		{
			name:    "successful request",
			request: &flowv1.ListOperationRulesRequest{},
		},
		{
			name: "successful request with filters",
			request: &flowv1.ListOperationRulesRequest{
				OperationType: ptrOperationType(flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := newManageRuleForTest()
			result, err := mr.GetAllTaskRulesFromFlow(context.Background(), tt.request)

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

func TestManageRule_UpdateOperationRuleOnFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.UpdateOperationRuleRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty update operation rule request",
		},
		{
			name:        "missing rule ID returns error",
			request:     &flowv1.UpdateOperationRuleRequest{},
			wantErr:     true,
			errContains: "without rule ID",
		},
		{
			name: "successful request",
			request: &flowv1.UpdateOperationRuleRequest{
				RuleId: &flowv1.UUID{Id: "test-rule-id"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := newManageRuleForTest()
			err := mr.UpdateTaskRuleOnFlow(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestManageRule_DeleteOperationRuleOnFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.DeleteOperationRuleRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty delete operation rule request",
		},
		{
			name:        "missing rule ID returns error",
			request:     &flowv1.DeleteOperationRuleRequest{},
			wantErr:     true,
			errContains: "without rule ID",
		},
		{
			name: "successful request",
			request: &flowv1.DeleteOperationRuleRequest{
				RuleId: &flowv1.UUID{Id: "test-rule-id"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := newManageRuleForTest()
			err := mr.DeleteTaskRuleOnFlow(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}
