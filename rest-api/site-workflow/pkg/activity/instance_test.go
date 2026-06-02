// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	tmocks "go.temporal.io/sdk/mocks"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

func TestManageInstance_UpdateInstanceConfigOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	ipxeScript := "#!ipxe"
	userData := "echo"

	labelKey := "key1"
	labelValue := "value1"

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.InstanceConfigUpdateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test Instance update success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.InstanceConfigUpdateRequest{
					InstanceId: &cwssaws.InstanceId{Value: uuid.NewString()},
					Metadata: &cwssaws.Metadata{
						Name:        "updated_name",
						Description: "updated_description",
						Labels: []*cwssaws.Label{
							{
								Key:   labelKey,
								Value: &labelValue,
							},
						},
					},
					Config: &cwssaws.InstanceConfig{
						Os: &cwssaws.OperatingSystem{
							RunProvisioningInstructionsOnEveryBoot: true,
							Variant: &cwssaws.OperatingSystem_Ipxe{
								Ipxe: &cwssaws.InlineIpxe{
									IpxeScript: ipxeScript,
								},
							},
							UserData: &userData,
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageInstance(tt.fields.coreGrpcAtomicClient)
			err := mm.UpdateInstanceOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageInstance_CreateInstanceOnSiteOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	ipxeScript := "#!ipxe"
	userData := "echo"

	labelKey := "key1"
	labelValue := "value1"

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.InstanceAllocationRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test create Instance success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.InstanceAllocationRequest{
					MachineId: &cwssaws.MachineId{Id: uuid.NewString()},
					Metadata: &cwssaws.Metadata{
						Name:        "new_name",
						Description: "new_description",
						Labels: []*cwssaws.Label{
							{
								Key:   labelKey,
								Value: &labelValue,
							},
						},
					},
					Config: &cwssaws.InstanceConfig{
						Os: &cwssaws.OperatingSystem{
							RunProvisioningInstructionsOnEveryBoot: true,
							Variant: &cwssaws.OperatingSystem_Ipxe{
								Ipxe: &cwssaws.InlineIpxe{
									IpxeScript: ipxeScript,
								},
							},
							UserData: &userData,
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageInstance(tt.fields.coreGrpcAtomicClient)
			err := mm.CreateInstanceOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestManageInstance_CreateInstancesOnSite tests the batch instance creation activity.
// Test cases:
//   - success: batch create 2 instances with valid requests
//   - nil request: returns NonRetryableApplicationError
//   - empty requests: returns NonRetryableApplicationError
//   - missing machine ID: returns NonRetryableApplicationError
func TestManageInstance_CreateInstancesOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	ipxeScript := "#!ipxe"
	userData := "echo"

	labelKey := "key1"
	labelValue := "value1"

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.BatchInstanceAllocationRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test batch create Instances success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.BatchInstanceAllocationRequest{
					InstanceRequests: []*cwssaws.InstanceAllocationRequest{
						{
							MachineId: &cwssaws.MachineId{Id: uuid.NewString()},
							Metadata: &cwssaws.Metadata{
								Name:        "instance_1",
								Description: "first instance",
								Labels: []*cwssaws.Label{
									{
										Key:   labelKey,
										Value: &labelValue,
									},
								},
							},
							Config: &cwssaws.InstanceConfig{
								Os: &cwssaws.OperatingSystem{
									RunProvisioningInstructionsOnEveryBoot: true,
									Variant: &cwssaws.OperatingSystem_Ipxe{
										Ipxe: &cwssaws.InlineIpxe{
											IpxeScript: ipxeScript,
										},
									},
									UserData: &userData,
								},
							},
						},
						{
							MachineId: &cwssaws.MachineId{Id: uuid.NewString()},
							Metadata: &cwssaws.Metadata{
								Name:        "instance_2",
								Description: "second instance",
								Labels: []*cwssaws.Label{
									{
										Key:   labelKey,
										Value: &labelValue,
									},
								},
							},
							Config: &cwssaws.InstanceConfig{
								Os: &cwssaws.OperatingSystem{
									RunProvisioningInstructionsOnEveryBoot: true,
									Variant: &cwssaws.OperatingSystem_Ipxe{
										Ipxe: &cwssaws.InlineIpxe{
											IpxeScript: ipxeScript,
										},
									},
									UserData: &userData,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test batch create Instances with nil request failure",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx:     context.Background(),
				request: nil,
			},
			wantErr: true,
		},
		{
			name: "test batch create Instances with empty requests failure",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.BatchInstanceAllocationRequest{
					InstanceRequests: []*cwssaws.InstanceAllocationRequest{},
				},
			},
			wantErr: true,
		},
		{
			name: "test batch create Instances with missing machine ID failure",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.BatchInstanceAllocationRequest{
					InstanceRequests: []*cwssaws.InstanceAllocationRequest{
						{
							MachineId: nil,
							Metadata: &cwssaws.Metadata{
								Name: "instance_1",
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageInstance(tt.fields.coreGrpcAtomicClient)
			err := mm.CreateInstancesOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageInstance_RebootInstanceOnSiteOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.InstancePowerRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test reboot Instance success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.InstancePowerRequest{
					MachineId: &cwssaws.MachineId{Id: uuid.NewString()},
					Operation: cwssaws.InstancePowerRequest_POWER_RESET,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageInstance(tt.fields.coreGrpcAtomicClient)
			err := mm.RebootInstanceOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageInstanceInventory_DiscoverInstanceInventory(t *testing.T) {
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
			name: "test collecting and publishing instance inventory, empty inventory",
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
			name: "test collecting and publishing instance inventory, normal inventory",
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

			manageInstance := NewManageInstanceInventory(ManageInventoryConfig{
				SiteID:                tt.fields.siteID,
				CoreGrpcAtomicClient:  tt.fields.coreGrpcAtomicClient,
				TemporalPublishClient: tc,
				TemporalPublishQueue:  tt.fields.temporalPublishQueue,
				SitePageSize:          tt.fields.sitePageSize,
				CloudPageSize:         tt.fields.cloudPageSize,
			})

			ctx := context.Background()
			ctx = context.WithValue(ctx, "wantCount", tt.args.wantTotalItems)

			totalPages := tt.args.wantTotalItems / tt.fields.cloudPageSize
			if tt.args.wantTotalItems%tt.fields.cloudPageSize > 0 {
				totalPages++
			}

			err := manageInstance.DiscoverInstanceInventory(ctx)
			assert.NoError(t, err)

			if tt.args.wantTotalItems == 0 {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 1)
			} else {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", totalPages)
			}

			inventory, ok := tc.Calls[0].Arguments[4].(*cwssaws.InstanceInventory)
			assert.True(t, ok)

			if tt.args.wantTotalItems == 0 {
				assert.Equal(t, 0, len(inventory.Instances))
			} else {
				assert.Equal(t, tt.fields.cloudPageSize, len(inventory.Instances))
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

func TestManageInstance_DeleteInstanceOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.InstanceReleaseRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test delete Instance success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.InstanceReleaseRequest{
					Id: &cwssaws.InstanceId{Value: uuid.NewString()},
				},
			},
			wantErr: false,
		},
		{
			name: "test delete Instance with nil ID failure",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.InstanceReleaseRequest{
					Id: nil,
				},
			},
			wantErr: true,
		},
		{
			name: "test delete Instance with empty non-nil ID failure",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.InstanceReleaseRequest{
					Id: &cwssaws.InstanceId{Value: ""},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageInstance(tt.fields.coreGrpcAtomicClient)
			err := mm.DeleteInstanceOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
