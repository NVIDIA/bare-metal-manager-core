// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	tClient "go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
)

func TestManageSiteConfigInventory_DiscoverSiteConfigInventory(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()
	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	wid := "test-workflow-id"
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return(wid)

	siteID := uuid.New()
	siteFabricPrefixes := []string{"10.0.0.0/16", "2001:db8::/64"}
	tc := &tmocks.Client{}
	tc.Mock.On(
		"ExecuteWorkflow",
		mock.Anything,
		mock.AnythingOfType("internal.StartWorkflowOptions"),
		updateSiteConfigInventoryWorkflowName,
		siteID.String(),
		mock.Anything,
	).Return(wrun, nil)

	manageSiteConfigInventory := NewManageSiteConfigInventory(ManageInventoryConfig{
		SiteID:                siteID,
		CoreGrpcAtomicClient:  coreGrpcAtomicClient,
		TemporalPublishClient: tc,
		TemporalPublishQueue:  "test-queue",
	})

	ctx := context.WithValue(context.Background(), "siteFabricPrefixes", siteFabricPrefixes)
	err := manageSiteConfigInventory.DiscoverSiteConfigInventory(ctx)
	require.NoError(t, err)

	tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 1)
	executeCtx, ok := tc.Calls[0].Arguments[0].(context.Context)
	require.True(t, ok)
	assert.Same(t, ctx, executeCtx)

	workflowOptions, ok := tc.Calls[0].Arguments[1].(tClient.StartWorkflowOptions)
	require.True(t, ok)
	assert.Equal(t, "update-site-config-inventory-"+siteID.String(), workflowOptions.ID)
	assert.Equal(t, "test-queue", workflowOptions.TaskQueue)

	buildInfo, ok := tc.Calls[0].Arguments[4].(*cwssaws.BuildInfo)
	require.True(t, ok)
	assert.Equal(t, siteFabricPrefixes, buildInfo.GetRuntimeConfig().GetSiteFabricPrefixes())
}

func TestManageSiteConfigInventory_DiscoverSiteConfigInventory_NoCoreClient(t *testing.T) {
	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	manageSiteConfigInventory := NewManageSiteConfigInventory(ManageInventoryConfig{
		SiteID:               uuid.New(),
		CoreGrpcAtomicClient: coreGrpcAtomicClient,
	})

	err := manageSiteConfigInventory.DiscoverSiteConfigInventory(context.Background())
	assert.ErrorIs(t, err, cClient.ErrCoreGrpcClientNotConnected)
}
