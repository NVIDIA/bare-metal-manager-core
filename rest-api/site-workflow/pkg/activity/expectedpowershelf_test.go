// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	tmocks "go.temporal.io/sdk/mocks"
)

func TestManageExpectedPowerShelfInventory_DiscoverExpectedPowerShelfInventory(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	wid := "test-workflow-id"
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return(wid)

	type fields struct {
		siteID               uuid.UUID
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
		temporalPublishQueue string
		sitePageSize         int
		cloudPageSize        int
	}
	type args struct {
		wantTotalItems int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "test collecting and publishing expected power shelf inventory, empty inventory",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems: 0,
			},
		},
		{
			name: "test collecting and publishing expected power shelf inventory, normal inventory",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems: 195,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &tmocks.Client{}
			tc.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
				mock.AnythingOfType("string"), mock.AnythingOfType("uuid.UUID"), mock.Anything).Return(wrun, nil)
			tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 0)

			manageInstance := NewManageExpectedPowerShelfInventory(
				tt.fields.siteID,
				tt.fields.coreGrpcAtomicClient,
				tc,
				tt.fields.temporalPublishQueue,
				tt.fields.cloudPageSize,
			)

			ctx := context.Background()
			ctx = context.WithValue(ctx, "wantCount", tt.args.wantTotalItems)

			totalPages := tt.args.wantTotalItems / tt.fields.cloudPageSize
			if tt.args.wantTotalItems%tt.fields.cloudPageSize > 0 {
				totalPages++
			}

			err := manageInstance.DiscoverExpectedPowerShelfInventory(ctx)
			assert.NoError(t, err)

			if tt.args.wantTotalItems == 0 {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 1)
			} else {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", totalPages)
			}

			inventory, ok := tc.Calls[0].Arguments[4].(*cwssaws.ExpectedPowerShelfInventory)
			assert.True(t, ok)

			if tt.args.wantTotalItems == 0 {
				assert.Equal(t, 0, len(inventory.ExpectedPowerShelves))
			} else {
				assert.Equal(t, tt.fields.cloudPageSize, len(inventory.ExpectedPowerShelves))
			}

			assert.Equal(t, cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS, inventory.InventoryStatus)
			assert.Equal(t, totalPages, int(inventory.InventoryPage.TotalPages))
			assert.Equal(t, 1, int(inventory.InventoryPage.CurrentPage))
			assert.Equal(t, tt.fields.cloudPageSize, int(inventory.InventoryPage.PageSize))
			assert.Equal(t, tt.args.wantTotalItems, int(inventory.InventoryPage.TotalItems))
			assert.Equal(t, tt.args.wantTotalItems, len(inventory.InventoryPage.ItemIds))
		})
	}
}

func TestManageExpectedPowerShelf_CreateExpectedPowerShelfOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedPowerShelf
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test create expected power shelf success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-powershelf-001"},
					BmcMacAddress:        "00:11:22:33:44:55",
					ShelfSerialNumber:    "SHELF-123456789",
				},
			},
			wantErr: false,
		},
		{
			name: "test create expected power shelf fail on missing MAC address",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-powershelf-002"},
					BmcMacAddress:        "",
					ShelfSerialNumber:    "SHELF-123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected power shelf fail on missing serial number",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-powershelf-003"},
					BmcMacAddress:        "00:11:22:33:44:55",
					ShelfSerialNumber:    "",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected power shelf fail on missing id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: nil,
					BmcMacAddress:        "00:11:22:33:44:55",
					ShelfSerialNumber:    "SHELF-123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected power shelf fail on missing identifying information",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-powershelf-004"},
					BmcMacAddress:        "",
					ShelfSerialNumber:    "",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected power shelf fail on missing request",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx:     context.Background(),
				request: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageExpectedPowerShelf(tt.fields.coreGrpcAtomicClient, nil)
			err := mm.CreateExpectedPowerShelfOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedPowerShelf_UpdateExpectedPowerShelfOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedPowerShelf
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test update expected power shelf success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-update-001"},
					BmcMacAddress:        "00:11:22:33:44:55",
					ShelfSerialNumber:    "SHELF-123456789",
				},
			},
			wantErr: false,
		},
		{
			name: "test update expected power shelf fail on missing id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: nil,
					BmcMacAddress:        "00:11:22:33:44:55",
					ShelfSerialNumber:    "SHELF-123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected power shelf fail on missing MAC address",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-update-002"},
					BmcMacAddress:        "",
					ShelfSerialNumber:    "SHELF-123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected power shelf fail on missing serial number",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-update-003"},
					BmcMacAddress:        "00:11:22:33:44:55",
					ShelfSerialNumber:    "",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected power shelf fail on missing both MAC and serial",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelf{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-update-004"},
					BmcMacAddress:        "",
					ShelfSerialNumber:    "",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected power shelf fail on missing request",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx:     context.Background(),
				request: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageExpectedPowerShelf(tt.fields.coreGrpcAtomicClient, nil)
			err := mm.UpdateExpectedPowerShelfOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedPowerShelf_DeleteExpectedPowerShelfOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedPowerShelfRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test delete expected power shelf success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelfRequest{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-delete-001"},
					BmcMacAddress:        "00:11:22:33:44:55",
				},
			},
			wantErr: false,
		},
		{
			name: "test delete expected power shelf fail on missing id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelfRequest{
					ExpectedPowerShelfId: nil,
					BmcMacAddress:        "00:11:22:33:44:55",
				},
			},
			wantErr: true,
		},
		{
			name: "test delete expected power shelf success with missing BMC MAC address",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedPowerShelfRequest{
					ExpectedPowerShelfId: &cwssaws.UUID{Value: "test-delete-002"},
					BmcMacAddress:        "",
				},
			},
			wantErr: false,
		},
		{
			name: "test delete expected power shelf fail on missing request",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx:     context.Background(),
				request: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageExpectedPowerShelf(tt.fields.coreGrpcAtomicClient, nil)
			err := mm.DeleteExpectedPowerShelfOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedPowerShelf_CreateExpectedPowerShelfOnFlow(t *testing.T) {
	t.Run("nil Flow client skips gracefully", func(t *testing.T) {
		mm := ManageExpectedPowerShelf{flowGrpcAtomicClient: nil}
		err := mm.CreateExpectedPowerShelfOnFlow(context.Background(), &cwssaws.ExpectedPowerShelf{
			ExpectedPowerShelfId: &cwssaws.UUID{Value: uuid.NewString()}, BmcMacAddress: "00:11:22:33:44:55", ShelfSerialNumber: "SHELF001",
		})
		assert.NoError(t, err)
	})

	t.Run("nil Flow client connection skips gracefully", func(t *testing.T) {
		mm := ManageExpectedPowerShelf{flowGrpcAtomicClient: cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})}
		err := mm.CreateExpectedPowerShelfOnFlow(context.Background(), &cwssaws.ExpectedPowerShelf{
			ExpectedPowerShelfId: &cwssaws.UUID{Value: uuid.NewString()}, BmcMacAddress: "00:11:22:33:44:55", ShelfSerialNumber: "SHELF001",
		})
		assert.NoError(t, err)
	})
}

func Test_expectedPowerShelfToFlowComponent(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	int32Ptr := func(i int32) *int32 { return &i }

	t.Run("maps all fields correctly", func(t *testing.T) {
		eps := &cwssaws.ExpectedPowerShelf{
			ExpectedPowerShelfId: &cwssaws.UUID{Value: "eps-001"},
			BmcMacAddress:        "AA:BB:CC:DD:EE:FF",
			ShelfSerialNumber:    "SHELF-001",
			BmcIpAddress:         "10.0.0.1",
			RackId:               &cwssaws.RackId{Id: "rack-001"},
			Name:                 strPtr("pdu-shelf-1"),
			Manufacturer:         strPtr("Vertiv"),
			Model:                strPtr("GXT5-3000"),
			Description:          strPtr("Power distribution shelf"),
			SlotId:               int32Ptr(10),
			TrayIdx:              int32Ptr(0),
			HostId:               int32Ptr(0),
		}
		component := expectedPowerShelfToFlowComponent(eps)
		assert.Equal(t, flowv1.ComponentType_COMPONENT_TYPE_POWERSHELF, component.Type)
		assert.Equal(t, "eps-001", component.Info.Id.Id)
		assert.Equal(t, "SHELF-001", component.Info.SerialNumber)
		assert.Equal(t, "pdu-shelf-1", component.Info.Name)
		assert.Equal(t, "Vertiv", component.Info.Manufacturer)
		assert.Equal(t, "GXT5-3000", *component.Info.Model)
		assert.Equal(t, "Power distribution shelf", *component.Info.Description)
		assert.Equal(t, "eps-001", component.ComponentId)
		assert.NotNil(t, component.Position)
		assert.Equal(t, int32(10), component.Position.SlotId)
		if assert.Len(t, component.Bmcs, 1) {
			assert.Equal(t, "AA:BB:CC:DD:EE:FF", component.Bmcs[0].MacAddress)
			assert.NotNil(t, component.Bmcs[0].IpAddress)
			assert.Equal(t, "10.0.0.1", *component.Bmcs[0].IpAddress)
		}
		assert.NotNil(t, component.RackId)
		assert.Equal(t, "rack-001", component.RackId.Id)
	})

	t.Run("handles minimal fields (nil optionals)", func(t *testing.T) {
		eps := &cwssaws.ExpectedPowerShelf{
			ExpectedPowerShelfId: &cwssaws.UUID{Value: "eps-002"}, BmcMacAddress: "11:22:33:44:55:66",
			ShelfSerialNumber: "SHELF-002",
		}
		component := expectedPowerShelfToFlowComponent(eps)
		assert.Equal(t, flowv1.ComponentType_COMPONENT_TYPE_POWERSHELF, component.Type)
		assert.Empty(t, component.Info.Name)
		assert.Empty(t, component.Info.Manufacturer)
		assert.Nil(t, component.Info.Model)
		assert.Nil(t, component.Position)
		assert.Nil(t, component.RackId)
		if assert.Len(t, component.Bmcs, 1) {
			assert.Nil(t, component.Bmcs[0].IpAddress)
		}
	})
}
