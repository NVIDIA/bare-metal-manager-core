// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowv1 "github.com/NVIDIA/infra-controller/rest-api/proto/flow/gen/v1"
	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
)

func newManageCampaignForTest() ManageCampaign {
	mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
	flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
	flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
	return NewManageCampaign(flowGrpcAtomicClient)
}

func TestManageCampaign_CreateCampaignOnFlow(t *testing.T) {
	mc := newManageCampaignForTest()

	_, err := mc.CreateCampaignOnFlow(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty create operation run request")

	resp, err := mc.CreateCampaignOnFlow(context.Background(), &flowv1.CreateOperationRunRequest{Name: "fw-rollout"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.GetId().GetId())
}

func TestManageCampaign_GetCampaignFromFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.GetOperationRunRequest
		wantErr     bool
		errContains string
	}{
		{name: "nil request", request: nil, wantErr: true, errContains: "empty get operation run request"},
		{name: "missing id", request: &flowv1.GetOperationRunRequest{}, wantErr: true, errContains: "without operation run ID"},
		{name: "empty id", request: &flowv1.GetOperationRunRequest{Id: &flowv1.UUID{Id: ""}}, wantErr: true, errContains: "without operation run ID"},
		{name: "success", request: &flowv1.GetOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := newManageCampaignForTest()
			resp, err := mc.GetCampaignFromFlow(context.Background(), tt.request)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, resp)
		})
	}
}

func TestManageCampaign_GetAllCampaignsFromFlow(t *testing.T) {
	mc := newManageCampaignForTest()

	_, err := mc.GetAllCampaignsFromFlow(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty list operation runs request")

	resp, err := mc.GetAllCampaignsFromFlow(context.Background(), &flowv1.ListOperationRunsRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestManageCampaign_GetCampaignTargetsFromFlow(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.ListOperationRunTargetsRequest
		wantErr     bool
		errContains string
	}{
		{name: "nil request", request: nil, wantErr: true, errContains: "empty list operation run targets request"},
		{name: "missing id", request: &flowv1.ListOperationRunTargetsRequest{}, wantErr: true, errContains: "without operation run ID"},
		{name: "success", request: &flowv1.ListOperationRunTargetsRequest{OperationRunId: &flowv1.UUID{Id: "campaign-id"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := newManageCampaignForTest()
			resp, err := mc.GetCampaignTargetsFromFlow(context.Background(), tt.request)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, resp)
		})
	}
}

func TestManageCampaign_PauseCampaignOnFlow(t *testing.T) {
	mc := newManageCampaignForTest()

	_, err := mc.PauseCampaignOnFlow(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty pause operation run request")

	_, err = mc.PauseCampaignOnFlow(context.Background(), &flowv1.PauseOperationRunRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "without operation run ID")

	resp, err := mc.PauseCampaignOnFlow(context.Background(), &flowv1.PauseOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	require.NoError(t, err)
	assert.Equal(t, "campaign-id", resp.GetSummary().GetId().GetId())
}

func TestManageCampaign_ResumeCampaignOnFlow(t *testing.T) {
	mc := newManageCampaignForTest()

	_, err := mc.ResumeCampaignOnFlow(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty resume operation run request")

	_, err = mc.ResumeCampaignOnFlow(context.Background(), &flowv1.ResumeOperationRunRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "without operation run ID")

	resp, err := mc.ResumeCampaignOnFlow(context.Background(), &flowv1.ResumeOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	require.NoError(t, err)
	assert.Equal(t, "campaign-id", resp.GetSummary().GetId().GetId())
}

func TestManageCampaign_AdvanceCampaignPhaseOnFlow(t *testing.T) {
	mc := newManageCampaignForTest()

	_, err := mc.AdvanceCampaignPhaseOnFlow(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty advance operation run phase request")

	_, err = mc.AdvanceCampaignPhaseOnFlow(context.Background(), &flowv1.AdvanceOperationRunPhaseRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "without operation run ID")

	resp, err := mc.AdvanceCampaignPhaseOnFlow(context.Background(), &flowv1.AdvanceOperationRunPhaseRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	require.NoError(t, err)
	assert.Equal(t, "campaign-id", resp.GetSummary().GetId().GetId())
}

func TestManageCampaign_CancelCampaignOnFlow(t *testing.T) {
	mc := newManageCampaignForTest()

	_, err := mc.CancelCampaignOnFlow(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty cancel operation run request")

	_, err = mc.CancelCampaignOnFlow(context.Background(), &flowv1.CancelOperationRunRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "without operation run ID")

	resp, err := mc.CancelCampaignOnFlow(context.Background(), &flowv1.CancelOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}, Reason: "operator"})
	require.NoError(t, err)
	assert.Equal(t, "campaign-id", resp.GetSummary().GetId().GetId())
}
