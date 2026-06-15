/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package activity

import (
	"context"
	"testing"

	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	tmocks "go.temporal.io/sdk/mocks"
)

func TestManageIpxeTemplateInventory_DiscoverIpxeTemplateInventory_NilClient(t *testing.T) {
	// Simulate the case where the gRPC client is not yet connected (nil).
	// Before the fix this caused a nil pointer dereference panic.
	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	// deliberately do NOT swap in a real client — value stays nil

	tc := &tmocks.Client{}

	manageInstance := NewManageIpxeTemplateInventory(ManageInventoryConfig{
		SiteID:                uuid.New(),
		CoreGrpcAtomicClient:   coreGrpcAtomicClient,
		TemporalPublishClient: tc,
		TemporalPublishQueue:  "test-queue",
	})

	err := manageInstance.DiscoverIpxeTemplateInventory(context.Background())
	assert.ErrorIs(t, err, cClient.ErrCoreGrpcClientNotConnected)
	tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 0)
}

func TestManageIpxeTemplateInventory_DiscoverIpxeTemplateInventory(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	wid := "test-workflow-id"
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return(wid)

	tests := []struct {
		name          string
		siteID        uuid.UUID
		wantCount     int
		expectedCalls int
	}{
		{
			name:          "empty iPXE template inventory",
			siteID:        uuid.New(),
			wantCount:     0,
			expectedCalls: 1,
		},
		{
			name:          "non-empty iPXE template inventory",
			siteID:        uuid.New(),
			wantCount:     3,
			expectedCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &tmocks.Client{}
			tc.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
				mock.AnythingOfType("string"), mock.AnythingOfType("uuid.UUID"), mock.Anything).Return(wrun, nil)

			manageInstance := NewManageIpxeTemplateInventory(ManageInventoryConfig{
				SiteID:                tt.siteID,
				CoreGrpcAtomicClient:   coreGrpcAtomicClient,
				TemporalPublishClient: tc,
				TemporalPublishQueue:  "test-queue",
			})

			ctx := context.Background()
			ctx = context.WithValue(ctx, "wantCount", tt.wantCount)

			err := manageInstance.DiscoverIpxeTemplateInventory(ctx)
			assert.NoError(t, err)

			tc.AssertNumberOfCalls(t, "ExecuteWorkflow", tt.expectedCalls)

			// Validate the inventory payload
			inventory, ok := tc.Calls[0].Arguments[4].(*cwssaws.IpxeTemplateInventory)
			assert.True(t, ok)
			assert.Equal(t, cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS, inventory.InventoryStatus)
			assert.Equal(t, tt.wantCount, len(inventory.Templates))
		})
	}
}
