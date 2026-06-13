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

func TestManageExpectedSwitchInventory_DiscoverExpectedSwitchInventory(t *testing.T) {
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
			name: "test collecting and publishing expected switch inventory, empty inventory",
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
			name: "test collecting and publishing expected switch inventory, normal inventory",
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

			manageInstance := NewManageExpectedSwitchInventory(
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

			err := manageInstance.DiscoverExpectedSwitchInventory(ctx)
			assert.NoError(t, err)

			if tt.args.wantTotalItems == 0 {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 1)
			} else {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", totalPages)
			}

			inventory, ok := tc.Calls[0].Arguments[4].(*cwssaws.ExpectedSwitchInventory)
			assert.True(t, ok)

			if tt.args.wantTotalItems == 0 {
				assert.Equal(t, 0, len(inventory.ExpectedSwitches))
			} else {
				assert.Equal(t, tt.fields.cloudPageSize, len(inventory.ExpectedSwitches))
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

func TestManageExpectedSwitch_CreateExpectedSwitchOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedSwitch
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test create expected switch success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   &cwssaws.UUID{Value: "test-switch-001"},
					BmcMacAddress:      "00:11:22:33:44:55",
					SwitchSerialNumber: "SWITCH-123456789",
				},
			},
			wantErr: false,
		},
		{
			name: "test create expected switch fail on missing MAC address",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   &cwssaws.UUID{Value: "test-switch-002"},
					BmcMacAddress:      "",
					SwitchSerialNumber: "SWITCH-123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected switch fail on missing serial number",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   &cwssaws.UUID{Value: "test-switch-003"},
					BmcMacAddress:      "00:11:22:33:44:55",
					SwitchSerialNumber: "",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected switch fail on missing id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   nil,
					BmcMacAddress:      "00:11:22:33:44:55",
					SwitchSerialNumber: "SWITCH-123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected switch fail on missing identifying information",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   &cwssaws.UUID{Value: "test-switch-004"},
					BmcMacAddress:      "",
					SwitchSerialNumber: "",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected switch fail on missing request",
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
			mm := NewManageExpectedSwitch(tt.fields.coreGrpcAtomicClient, nil)
			err := mm.CreateExpectedSwitchOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedSwitch_UpdateExpectedSwitchOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedSwitch
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test update expected switch success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   &cwssaws.UUID{Value: "test-update-001"},
					BmcMacAddress:      "00:11:22:33:44:55",
					SwitchSerialNumber: "SWITCH-123456789",
				},
			},
			wantErr: false,
		},
		{
			name: "test update expected switch fail on missing id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   nil,
					BmcMacAddress:      "00:11:22:33:44:55",
					SwitchSerialNumber: "SWITCH-123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected switch fail on missing MAC address",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   &cwssaws.UUID{Value: "test-update-002"},
					BmcMacAddress:      "",
					SwitchSerialNumber: "SWITCH-123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected switch fail on missing serial number",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   &cwssaws.UUID{Value: "test-update-003"},
					BmcMacAddress:      "00:11:22:33:44:55",
					SwitchSerialNumber: "",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected switch fail on missing both MAC and serial",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitch{
					ExpectedSwitchId:   &cwssaws.UUID{Value: "test-update-004"},
					BmcMacAddress:      "",
					SwitchSerialNumber: "",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected switch fail on missing request",
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
			mm := NewManageExpectedSwitch(tt.fields.coreGrpcAtomicClient, nil)
			err := mm.UpdateExpectedSwitchOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedSwitch_DeleteExpectedSwitchOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedSwitchRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test delete expected switch success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitchRequest{
					ExpectedSwitchId: &cwssaws.UUID{Value: "test-delete-001"},
					BmcMacAddress:    "00:11:22:33:44:55",
				},
			},
			wantErr: false,
		},
		{
			name: "test delete expected switch fail on missing id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitchRequest{
					ExpectedSwitchId: nil,
					BmcMacAddress:    "00:11:22:33:44:55",
				},
			},
			wantErr: true,
		},
		{
			name: "test delete expected switch success with missing BMC MAC address",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedSwitchRequest{
					ExpectedSwitchId: &cwssaws.UUID{Value: "test-delete-002"},
					BmcMacAddress:    "",
				},
			},
			wantErr: false,
		},
		{
			name: "test delete expected switch fail on missing request",
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
			mm := NewManageExpectedSwitch(tt.fields.coreGrpcAtomicClient, nil)
			err := mm.DeleteExpectedSwitchOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedSwitch_CreateExpectedSwitchOnFlow(t *testing.T) {
	t.Run("nil Flow client skips gracefully", func(t *testing.T) {
		mm := ManageExpectedSwitch{flowGrpcAtomicClient: nil}
		err := mm.CreateExpectedSwitchOnFlow(context.Background(), &cwssaws.ExpectedSwitch{
			ExpectedSwitchId: &cwssaws.UUID{Value: uuid.NewString()}, BmcMacAddress: "00:11:22:33:44:55", SwitchSerialNumber: "SW001",
		})
		assert.NoError(t, err)
	})

	t.Run("nil Flow client connection skips gracefully", func(t *testing.T) {
		mm := ManageExpectedSwitch{flowGrpcAtomicClient: cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})}
		err := mm.CreateExpectedSwitchOnFlow(context.Background(), &cwssaws.ExpectedSwitch{
			ExpectedSwitchId: &cwssaws.UUID{Value: uuid.NewString()}, BmcMacAddress: "00:11:22:33:44:55", SwitchSerialNumber: "SW001",
		})
		assert.NoError(t, err)
	})
}

func Test_expectedSwitchToFlowComponent(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	int32Ptr := func(i int32) *int32 { return &i }

	t.Run("maps all fields correctly", func(t *testing.T) {
		es := &cwssaws.ExpectedSwitch{
			ExpectedSwitchId:   &cwssaws.UUID{Value: "es-001"},
			BmcMacAddress:      "AA:BB:CC:DD:EE:FF",
			SwitchSerialNumber: "SW-001",
			RackId:             &cwssaws.RackId{Id: "rack-001"},
			Name:               strPtr("nvl-switch-1"),
			Manufacturer:       strPtr("NVIDIA"),
			Model:              strPtr("NVL-400"),
			Description:        strPtr("NVLink switch"),
			SlotId:             int32Ptr(4),
			TrayIdx:            int32Ptr(1),
			HostId:             int32Ptr(0),
		}
		component := expectedSwitchToFlowComponent(es)
		assert.Equal(t, flowv1.ComponentType_COMPONENT_TYPE_NVSWITCH, component.Type)
		assert.Equal(t, "es-001", component.Info.Id.Id)
		assert.Equal(t, "SW-001", component.Info.SerialNumber)
		assert.Equal(t, "nvl-switch-1", component.Info.Name)
		assert.Equal(t, "NVIDIA", component.Info.Manufacturer)
		assert.Equal(t, "NVL-400", *component.Info.Model)
		assert.Equal(t, "NVLink switch", *component.Info.Description)
		assert.Equal(t, "es-001", component.ComponentId)
		assert.NotNil(t, component.Position)
		assert.Equal(t, int32(4), component.Position.SlotId)
		assert.Equal(t, int32(1), component.Position.TrayIdx)
		if assert.Len(t, component.Bmcs, 1) {
			assert.Equal(t, "AA:BB:CC:DD:EE:FF", component.Bmcs[0].MacAddress)
		}
		assert.NotNil(t, component.RackId)
		assert.Equal(t, "rack-001", component.RackId.Id)
	})

	t.Run("handles minimal fields (nil optionals)", func(t *testing.T) {
		es := &cwssaws.ExpectedSwitch{
			ExpectedSwitchId: &cwssaws.UUID{Value: "es-002"}, BmcMacAddress: "11:22:33:44:55:66",
			SwitchSerialNumber: "SW-002",
		}
		component := expectedSwitchToFlowComponent(es)
		assert.Equal(t, flowv1.ComponentType_COMPONENT_TYPE_NVSWITCH, component.Type)
		assert.Empty(t, component.Info.Name)
		assert.Empty(t, component.Info.Manufacturer)
		assert.Nil(t, component.Info.Model)
		assert.Nil(t, component.Position)
		assert.Nil(t, component.RackId)
	})
}
