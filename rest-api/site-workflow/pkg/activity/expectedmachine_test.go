// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	tmocks "go.temporal.io/sdk/mocks"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestManageExpectedMachineInventory_DiscoverExpectedMachineInventory(t *testing.T) {
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
		findIDsError   error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "test collecting and publishing expected machine inventory, empty inventory",
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
			name: "test collecting and publishing expected machine inventory, normal inventory",
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
		{
			name: "test collecting and publishing expected machine inventory fallback, empty inventory",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems: 0,
				findIDsError:   status.Error(codes.Unimplemented, "not implemented"),
			},
		},
		{
			name: "test collecting and publishing expected machine inventory fallback, normal inventory",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems: 195,
				findIDsError:   status.Error(codes.Unimplemented, "not implemented"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &tmocks.Client{}
			tc.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
				mock.AnythingOfType("string"), mock.AnythingOfType("uuid.UUID"), mock.Anything).Return(wrun, nil)
			tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 0)

			manageInstance := NewManageExpectedMachineInventory(
				tt.fields.siteID,
				tt.fields.coreGrpcAtomicClient,
				tc,
				tt.fields.temporalPublishQueue,
				tt.fields.cloudPageSize,
			)

			ctx := context.Background()
			ctx = context.WithValue(ctx, "wantCount", tt.args.wantTotalItems)
			if tt.args.findIDsError != nil {
				ctx = context.WithValue(ctx, "wantError", tt.args.findIDsError)
			}

			totalPages := tt.args.wantTotalItems / tt.fields.cloudPageSize
			if tt.args.wantTotalItems%tt.fields.cloudPageSize > 0 {
				totalPages++
			}

			err := manageInstance.DiscoverExpectedMachineInventory(ctx)
			assert.NoError(t, err)

			if tt.args.wantTotalItems == 0 {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 1)
			} else {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", totalPages)
			}

			inventory, ok := tc.Calls[0].Arguments[4].(*cwssaws.ExpectedMachineInventory)
			assert.True(t, ok)

			if tt.args.wantTotalItems == 0 {
				assert.Equal(t, 0, len(inventory.ExpectedMachines))
			} else {
				assert.Equal(t, tt.fields.cloudPageSize, len(inventory.ExpectedMachines))
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

func TestManageExpectedMachine_CreateExpectedMachineOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedMachine
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test create expected machine success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  &cwssaws.UUID{Value: "test-machine-001"},
					BmcMacAddress:       "00:11:22:33:44:55",
					ChassisSerialNumber: "SN123456789",
				},
			},
			wantErr: false,
		},
		{
			name: "test create expected machine fail on missing MAC address",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  &cwssaws.UUID{Value: "test-machine-002"},
					BmcMacAddress:       "",
					ChassisSerialNumber: "SN123456789",
				},
			},
			wantErr: true, // This should fail since MAC address is missing (now required)
		},
		{
			name: "test create expected machine fail on missing serial number",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  &cwssaws.UUID{Value: "test-machine-003"},
					BmcMacAddress:       "00:11:22:33:44:55",
					ChassisSerialNumber: "",
				},
			},
			wantErr: true, // This should fail since serial number is missing (now required)
		},
		{
			name: "test create expected machine fail on missing id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  nil,
					BmcMacAddress:       "00:11:22:33:44:55",
					ChassisSerialNumber: "SN123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected machine fail on missing identifying information",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  &cwssaws.UUID{Value: "test-machine-004"},
					BmcMacAddress:       "",
					ChassisSerialNumber: "",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected machine fail on missing request",
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
			mm := NewManageExpectedMachine(tt.fields.coreGrpcAtomicClient, nil)
			err := mm.CreateExpectedMachineOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedMachine_UpdateExpectedMachineOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedMachine
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test update expected machine success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  &cwssaws.UUID{Value: "test-update-001"},
					BmcMacAddress:       "00:11:22:33:44:55",
					ChassisSerialNumber: "SN123456789",
				},
			},
			wantErr: false,
		},
		{
			name: "test update expected machine fail on missing id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  nil,
					BmcMacAddress:       "00:11:22:33:44:55",
					ChassisSerialNumber: "SN123456789",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected machine fail on missing MAC address",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  &cwssaws.UUID{Value: "test-update-002"},
					BmcMacAddress:       "",
					ChassisSerialNumber: "SN123456789",
				},
			},
			wantErr: true, // This should fail since MAC address is missing (now required)
		},
		{
			name: "test update expected machine fail on missing serial number",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  &cwssaws.UUID{Value: "test-update-003"},
					BmcMacAddress:       "00:11:22:33:44:55",
					ChassisSerialNumber: "",
				},
			},
			wantErr: true, // This should fail since serial number is missing (now required)
		},
		{
			name: "test update expected machine fail on missing both MAC and serial",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachine{
					Id:                  &cwssaws.UUID{Value: "test-update-004"},
					BmcMacAddress:       "",
					ChassisSerialNumber: "",
				},
			},
			wantErr: true, // This should fail since both MAC address and serial number are missing
		},
		{
			name: "test update expected machine fail on missing request",
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
			mm := NewManageExpectedMachine(tt.fields.coreGrpcAtomicClient, nil)
			err := mm.UpdateExpectedMachineOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedMachine_DeleteExpectedMachineOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedMachineRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test delete expected machine success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachineRequest{
					Id:            &cwssaws.UUID{Value: "test-delete-001"},
					BmcMacAddress: "00:11:22:33:44:55",
				},
			},
			wantErr: false,
		},
		{
			name: "test delete expected machine fail on missing id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachineRequest{
					Id:            nil,
					BmcMacAddress: "00:11:22:33:44:55",
				},
			},
			wantErr: true,
		},
		{
			name: "test delete expected machine success with missing BMC MAC address",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedMachineRequest{
					Id:            &cwssaws.UUID{Value: "test-delete-002"},
					BmcMacAddress: "",
				},
			},
			wantErr: false,
		},
		{
			name: "test delete expected machine fail on missing request",
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
			mm := NewManageExpectedMachine(tt.fields.coreGrpcAtomicClient, nil)
			err := mm.DeleteExpectedMachineOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedMachine_CreateExpectedMachinesOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.BatchExpectedMachineOperationRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test create expected machines success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.BatchExpectedMachineOperationRequest{
					ExpectedMachines: &cwssaws.ExpectedMachineList{
						ExpectedMachines: []*cwssaws.ExpectedMachine{
							{
								Id:                  &cwssaws.UUID{Value: "test-batch-001"},
								BmcMacAddress:       "00:11:22:33:44:55",
								ChassisSerialNumber: "SN123456789",
							},
							{
								Id:                  &cwssaws.UUID{Value: "test-batch-002"},
								BmcMacAddress:       "00:11:22:33:44:66",
								ChassisSerialNumber: "SN987654321",
							},
						},
					},
					AcceptPartialResults: true,
				},
			},
			wantErr: false,
		},
		{
			name: "test create expected machines fail on empty list",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.BatchExpectedMachineOperationRequest{
					ExpectedMachines: &cwssaws.ExpectedMachineList{
						ExpectedMachines: []*cwssaws.ExpectedMachine{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected machines fail on nil request",
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
			mm := NewManageExpectedMachine(tt.fields.coreGrpcAtomicClient, nil)
			response, err := mm.CreateExpectedMachinesOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.Equal(t, len(tt.args.request.ExpectedMachines.ExpectedMachines), len(response.Results), "Should have result for each machine")

				// Verify that each result includes ID and MAC address via ExpectedMachine payload
				for i, result := range response.Results {
					assert.NotNil(t, result.GetExpectedMachine())
					assert.NotNil(t, result.GetExpectedMachine().GetId())
					assert.Equal(t, tt.args.request.ExpectedMachines.ExpectedMachines[i].GetId().GetValue(), result.GetExpectedMachine().GetId().GetValue(), "ID should be included in result")
					assert.Equal(t, tt.args.request.ExpectedMachines.ExpectedMachines[i].BmcMacAddress, result.GetExpectedMachine().GetBmcMacAddress(), "MAC address should be included in result")
				}
			}
		})
	}
}

func TestManageExpectedMachine_UpdateExpectedMachinesOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.BatchExpectedMachineOperationRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test update expected machines success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.BatchExpectedMachineOperationRequest{
					ExpectedMachines: &cwssaws.ExpectedMachineList{
						ExpectedMachines: []*cwssaws.ExpectedMachine{
							{
								Id:                  &cwssaws.UUID{Value: "test-batch-update-001"},
								BmcMacAddress:       "00:11:22:33:44:55",
								ChassisSerialNumber: "SN123456789",
							},
							{
								Id:                  &cwssaws.UUID{Value: "test-batch-update-002"},
								BmcMacAddress:       "00:11:22:33:44:66",
								ChassisSerialNumber: "SN987654321",
							},
						},
					},
					AcceptPartialResults: true,
				},
			},
			wantErr: false,
		},
		{
			name: "test update expected machines fail on empty list",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.BatchExpectedMachineOperationRequest{
					ExpectedMachines: &cwssaws.ExpectedMachineList{
						ExpectedMachines: []*cwssaws.ExpectedMachine{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected machines fail on nil request",
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
			mm := NewManageExpectedMachine(tt.fields.coreGrpcAtomicClient, nil)
			response, err := mm.UpdateExpectedMachinesOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.Equal(t, len(tt.args.request.ExpectedMachines.ExpectedMachines), len(response.Results), "Should have result for each machine")

				// Verify that each result includes ID and MAC address via ExpectedMachine payload
				for i, result := range response.Results {
					assert.NotNil(t, result.GetExpectedMachine())
					assert.NotNil(t, result.GetExpectedMachine().GetId())
					assert.Equal(t, tt.args.request.ExpectedMachines.ExpectedMachines[i].GetId().GetValue(), result.GetExpectedMachine().GetId().GetValue(), "ID should be included in result")
					assert.Equal(t, tt.args.request.ExpectedMachines.ExpectedMachines[i].BmcMacAddress, result.GetExpectedMachine().GetBmcMacAddress(), "MAC address should be included in result")
				}
			}
		})
	}
}

func TestManageExpectedMachine_CreateExpectedMachineOnFlow(t *testing.T) {
	t.Run("nil Flow client skips gracefully", func(t *testing.T) {
		mm := ManageExpectedMachine{flowGrpcAtomicClient: nil}
		err := mm.CreateExpectedMachineOnFlow(context.Background(), &cwssaws.ExpectedMachine{
			Id: &cwssaws.UUID{Value: uuid.NewString()}, BmcMacAddress: "00:11:22:33:44:55", ChassisSerialNumber: "SN001",
		})
		assert.NoError(t, err)
	})

	t.Run("nil Flow client connection skips gracefully", func(t *testing.T) {
		mm := ManageExpectedMachine{flowGrpcAtomicClient: cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})}
		err := mm.CreateExpectedMachineOnFlow(context.Background(), &cwssaws.ExpectedMachine{
			Id: &cwssaws.UUID{Value: uuid.NewString()}, BmcMacAddress: "00:11:22:33:44:55", ChassisSerialNumber: "SN001",
		})
		assert.NoError(t, err)
	})
}

func TestManageExpectedMachine_CreateExpectedMachinesOnFlow(t *testing.T) {
	t.Run("nil Flow client skips gracefully", func(t *testing.T) {
		mm := ManageExpectedMachine{flowGrpcAtomicClient: nil}
		err := mm.CreateExpectedMachinesOnFlow(context.Background(), &cwssaws.BatchExpectedMachineOperationRequest{
			ExpectedMachines: &cwssaws.ExpectedMachineList{
				ExpectedMachines: []*cwssaws.ExpectedMachine{
					{Id: &cwssaws.UUID{Value: uuid.NewString()}, BmcMacAddress: "00:11:22:33:44:55", ChassisSerialNumber: "SN001"},
				},
			},
		})
		assert.NoError(t, err)
	})

	t.Run("nil Flow client connection skips gracefully", func(t *testing.T) {
		mm := ManageExpectedMachine{flowGrpcAtomicClient: cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})}
		err := mm.CreateExpectedMachinesOnFlow(context.Background(), &cwssaws.BatchExpectedMachineOperationRequest{
			ExpectedMachines: &cwssaws.ExpectedMachineList{
				ExpectedMachines: []*cwssaws.ExpectedMachine{
					{Id: &cwssaws.UUID{Value: uuid.NewString()}, BmcMacAddress: "00:11:22:33:44:55", ChassisSerialNumber: "SN001"},
				},
			},
		})
		assert.NoError(t, err)
	})
}

func Test_expectedMachineToFlowComponent(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	int32Ptr := func(i int32) *int32 { return &i }

	t.Run("maps all fields correctly", func(t *testing.T) {
		em := &cwssaws.ExpectedMachine{
			Id:                  &cwssaws.UUID{Value: "em-001"},
			BmcMacAddress:       "AA:BB:CC:DD:EE:FF",
			ChassisSerialNumber: "CHASSIS-001",
			RackId:              &cwssaws.RackId{Id: "rack-001"},
			Name:                strPtr("compute-node-1"),
			Manufacturer:        strPtr("NVIDIA"),
			Model:               strPtr("DGX-H100"),
			Description:         strPtr("GPU compute node"),
			FirmwareVersion:     strPtr("v2.1.0"),
			SlotId:              int32Ptr(1),
			TrayIdx:             int32Ptr(2),
			HostId:              int32Ptr(3),
		}
		component := expectedMachineToFlowComponent(em)
		assert.Equal(t, flowv1.ComponentType_COMPONENT_TYPE_COMPUTE, component.Type)
		assert.Equal(t, "em-001", component.Info.Id.Id)
		assert.Equal(t, "CHASSIS-001", component.Info.SerialNumber)
		assert.Equal(t, "compute-node-1", component.Info.Name)
		assert.Equal(t, "NVIDIA", component.Info.Manufacturer)
		assert.Equal(t, "DGX-H100", *component.Info.Model)
		assert.Equal(t, "GPU compute node", *component.Info.Description)
		assert.Equal(t, "em-001", component.ComponentId)
		assert.Equal(t, "v2.1.0", component.FirmwareVersion)
		assert.NotNil(t, component.Position)
		assert.Equal(t, int32(1), component.Position.SlotId)
		assert.Equal(t, int32(2), component.Position.TrayIdx)
		assert.Equal(t, int32(3), component.Position.HostId)
		if assert.Len(t, component.Bmcs, 1) {
			assert.Equal(t, flowv1.BMCType_BMC_TYPE_HOST, component.Bmcs[0].Type)
			assert.Equal(t, "AA:BB:CC:DD:EE:FF", component.Bmcs[0].MacAddress)
		}
		assert.NotNil(t, component.RackId)
		assert.Equal(t, "rack-001", component.RackId.Id)
	})

	t.Run("handles minimal fields (nil optionals)", func(t *testing.T) {
		em := &cwssaws.ExpectedMachine{
			Id: &cwssaws.UUID{Value: "em-002"}, BmcMacAddress: "11:22:33:44:55:66", ChassisSerialNumber: "CHASSIS-002",
		}
		component := expectedMachineToFlowComponent(em)
		assert.Equal(t, flowv1.ComponentType_COMPONENT_TYPE_COMPUTE, component.Type)
		assert.Equal(t, "em-002", component.ComponentId)
		assert.Empty(t, component.Info.Name)
		assert.Empty(t, component.Info.Manufacturer)
		assert.Nil(t, component.Info.Model)
		assert.Nil(t, component.Info.Description)
		assert.Empty(t, component.FirmwareVersion)
		assert.Nil(t, component.Position)
		assert.Nil(t, component.RackId)
	})

	t.Run("ignores empty rack_id wrapper", func(t *testing.T) {
		em := &cwssaws.ExpectedMachine{
			Id: &cwssaws.UUID{Value: "em-003"}, BmcMacAddress: "22:33:44:55:66:77",
			ChassisSerialNumber: "CHASSIS-003", RackId: &cwssaws.RackId{Id: ""},
		}
		component := expectedMachineToFlowComponent(em)
		assert.Nil(t, component.RackId)
	})

	t.Run("partial position fields", func(t *testing.T) {
		em := &cwssaws.ExpectedMachine{
			Id: &cwssaws.UUID{Value: "em-004"}, BmcMacAddress: "33:44:55:66:77:88",
			ChassisSerialNumber: "CHASSIS-004", SlotId: int32Ptr(5),
		}
		component := expectedMachineToFlowComponent(em)
		assert.NotNil(t, component.Position)
		assert.Equal(t, int32(5), component.Position.SlotId)
		assert.Equal(t, int32(0), component.Position.TrayIdx)
		assert.Equal(t, int32(0), component.Position.HostId)
	})
}
