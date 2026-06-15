// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	tClient "go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
)

func TestManageSiteIPBlockInventory_DiscoverSiteIPBlockInventory(t *testing.T) {
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
		updateSiteIPBlockInventoryWorkflowName,
		siteID.String(),
		siteFabricPrefixes,
	).Return(wrun, nil)

	manageSiteIPBlockInventory := NewManageSiteIPBlockInventory(ManageInventoryConfig{
		SiteID:                siteID,
		CoreGrpcAtomicClient:  coreGrpcAtomicClient,
		TemporalPublishClient: tc,
		TemporalPublishQueue:  "test-queue",
	})

	ctx := context.WithValue(context.Background(), "siteFabricPrefixes", siteFabricPrefixes)
	err := manageSiteIPBlockInventory.DiscoverSiteIPBlockInventory(ctx)
	require.NoError(t, err)

	tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 1)
	executeCtx, ok := tc.Calls[0].Arguments[0].(context.Context)
	require.True(t, ok)
	assert.Same(t, ctx, executeCtx)

	workflowOptions, ok := tc.Calls[0].Arguments[1].(tClient.StartWorkflowOptions)
	require.True(t, ok)
	assert.Equal(t, "update-site-ip-block-inventory-"+siteID.String(), workflowOptions.ID)
	assert.Equal(t, "test-queue", workflowOptions.TaskQueue)
}

func TestManageSiteIPBlockInventory_DiscoverSiteIPBlockInventory_NoCoreClient(t *testing.T) {
	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	manageSiteIPBlockInventory := NewManageSiteIPBlockInventory(ManageInventoryConfig{
		SiteID:               uuid.New(),
		CoreGrpcAtomicClient: coreGrpcAtomicClient,
	})

	err := manageSiteIPBlockInventory.DiscoverSiteIPBlockInventory(context.Background())
	assert.ErrorIs(t, err, cClient.ErrCoreGrpcClientNotConnected)
}
