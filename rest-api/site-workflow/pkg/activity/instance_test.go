// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	tmocks "go.temporal.io/sdk/mocks"
	"go.temporal.io/sdk/temporal"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
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
		request *corev1.InstanceConfigUpdateRequest
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
				request: &corev1.InstanceConfigUpdateRequest{
					InstanceId: &corev1.InstanceId{Value: uuid.NewString()},
					Metadata: &corev1.Metadata{
						Name:        "updated_name",
						Description: "updated_description",
						Labels: []*corev1.Label{
							{
								Key:   labelKey,
								Value: &labelValue,
							},
						},
					},
					Config: &corev1.InstanceConfig{
						Os: &corev1.InstanceOperatingSystemConfig{
							RunProvisioningInstructionsOnEveryBoot: true,
							Variant: &corev1.InstanceOperatingSystemConfig_Ipxe{
								Ipxe: &corev1.InlineIpxe{
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
		request *corev1.InstanceAllocationRequest
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
				request: &corev1.InstanceAllocationRequest{
					MachineId: &corev1.MachineId{Id: uuid.NewString()},
					Metadata: &corev1.Metadata{
						Name:        "new_name",
						Description: "new_description",
						Labels: []*corev1.Label{
							{
								Key:   labelKey,
								Value: &labelValue,
							},
						},
					},
					Config: &corev1.InstanceConfig{
						Os: &corev1.InstanceOperatingSystemConfig{
							RunProvisioningInstructionsOnEveryBoot: true,
							Variant: &corev1.InstanceOperatingSystemConfig_Ipxe{
								Ipxe: &corev1.InlineIpxe{
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
		request *corev1.BatchInstanceAllocationRequest
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
				request: &corev1.BatchInstanceAllocationRequest{
					InstanceRequests: []*corev1.InstanceAllocationRequest{
						{
							MachineId: &corev1.MachineId{Id: uuid.NewString()},
							Metadata: &corev1.Metadata{
								Name:        "instance_1",
								Description: "first instance",
								Labels: []*corev1.Label{
									{
										Key:   labelKey,
										Value: &labelValue,
									},
								},
							},
							Config: &corev1.InstanceConfig{
								Os: &corev1.InstanceOperatingSystemConfig{
									RunProvisioningInstructionsOnEveryBoot: true,
									Variant: &corev1.InstanceOperatingSystemConfig_Ipxe{
										Ipxe: &corev1.InlineIpxe{
											IpxeScript: ipxeScript,
										},
									},
									UserData: &userData,
								},
							},
						},
						{
							MachineId: &corev1.MachineId{Id: uuid.NewString()},
							Metadata: &corev1.Metadata{
								Name:        "instance_2",
								Description: "second instance",
								Labels: []*corev1.Label{
									{
										Key:   labelKey,
										Value: &labelValue,
									},
								},
							},
							Config: &corev1.InstanceConfig{
								Os: &corev1.InstanceOperatingSystemConfig{
									RunProvisioningInstructionsOnEveryBoot: true,
									Variant: &corev1.InstanceOperatingSystemConfig_Ipxe{
										Ipxe: &corev1.InlineIpxe{
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
				request: &corev1.BatchInstanceAllocationRequest{
					InstanceRequests: []*corev1.InstanceAllocationRequest{},
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
				request: &corev1.BatchInstanceAllocationRequest{
					InstanceRequests: []*corev1.InstanceAllocationRequest{
						{
							MachineId: nil,
							Metadata: &corev1.Metadata{
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
		request *corev1.InstancePowerRequest
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		wantErr        bool
		wantErrMessage string
	}{
		{
			name: "test reboot Instance success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &corev1.InstancePowerRequest{
					InstanceId: &corev1.InstanceId{Value: uuid.NewString()},
					Operation:  corev1.InstancePowerRequest_POWER_RESET,
				},
			},
			wantErr: false,
		},
		{
			name: "test reboot Instance missing request",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr:        true,
			wantErrMessage: "received empty reboot Instance request",
		},
		{
			name: "test reboot Instance missing Instance ID",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx:     context.Background(),
				request: &corev1.InstancePowerRequest{},
			},
			wantErr:        true,
			wantErrMessage: "received reboot Instance request without Instance ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageInstance(tt.fields.coreGrpcAtomicClient)
			err := mm.RebootInstanceOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				require.Error(t, err)
				var appErr *temporal.ApplicationError
				require.ErrorAs(t, err, &appErr)
				assert.Equal(t, swe.ErrTypeInvalidRequest, appErr.Type())
				assert.True(t, appErr.NonRetryable())
				assert.Equal(t, tt.wantErrMessage, appErr.Message())
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
		// padBytesPerItem inflates every Instance Core returns, so a published page can outgrow
		// the Temporal blob budget and force the publish page size down.
		padBytesPerItem int
		// maxRequestIDs makes Core answer a FindInstancesByIds request carrying more IDs than
		// this with ResourceExhausted, forcing the site page size down.
		maxRequestIDs int
		// wantPageItems is the Instance count of each published page, in publish order.
		wantPageItems []int
		wantErr       bool
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
				wantPageItems:  []int{0},
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
				wantPageItems:  []int{25, 25, 25, 25, 25, 25, 25, 20},
			},
		},
		{
			// Core rejects 100, 90, ... down to 40, so the site page settles at 40 and the
			// publish page stays at 25, splitting each site page into 25 then 15.
			name: "test collecting and publishing instance inventory, site page steps down",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems: 100,
				maxRequestIDs:  45,
				wantPageItems:  []int{25, 15, 25, 15, 20},
			},
		},
		{
			// At 115 KB an Instance, 25 and 20 to a page both exceed the budget and 15 fits.
			name: "test collecting and publishing instance inventory, publish page steps down",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems:  60,
				padBytesPerItem: 115 * 1024,
				wantPageItems:   []int{15, 15, 15, 15},
			},
		},
		{
			// Both ladders at once: Core caps the fetch at 40 and the budget caps the page at 15.
			name: "test collecting and publishing instance inventory, both page sizes step down",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems:  60,
				padBytesPerItem: 115 * 1024,
				maxRequestIDs:   45,
				wantPageItems:   []int{15, 15, 10, 15, 5},
			},
		},
		{
			// A 3 MB Instance cannot be paged under the budget, so each one is published alone
			// rather than dropped.
			name: "test collecting and publishing instance inventory, single Instance over budget",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems:  2,
				padBytesPerItem: 3 * 1024 * 1024,
				wantPageItems:   []int{1, 1},
			},
		},
		{
			// Core still rejects the floor of 10, so nothing is published and the activity fails.
			name: "test collecting and publishing instance inventory, site page hits its floor",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems: 100,
				maxRequestIDs:  5,
				wantErr:        true,
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
			if tt.args.padBytesPerItem > 0 {
				ctx = context.WithValue(ctx, "instancePadBytes", tt.args.padBytesPerItem)
			}
			if tt.args.maxRequestIDs > 0 {
				ctx = context.WithValue(ctx, "maxRequestIDs", tt.args.maxRequestIDs)
			}

			err := manageInstance.DiscoverInstanceInventory(ctx)
			if tt.args.wantErr {
				assert.Error(t, err)
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 0)
				return
			}
			assert.NoError(t, err)
			tc.AssertNumberOfCalls(t, "ExecuteWorkflow", len(tt.args.wantPageItems))

			finalPages := []int{}
			for i, wantItems := range tt.args.wantPageItems {
				inventory, ok := tc.Calls[i].Arguments[4].(*corev1.InstanceInventory)
				require.True(t, ok)

				assert.Equal(t, corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS, inventory.InventoryStatus)
				assert.Equal(t, wantItems, len(inventory.Instances), "page %d Instance count", i+1)
				assert.Equal(t, i+1, int(inventory.InventoryPage.CurrentPage))
				assert.Equal(t, tt.args.wantTotalItems, int(inventory.InventoryPage.TotalItems))
				assert.Equal(t, tt.args.wantTotalItems, len(inventory.InventoryPage.ItemIds))

				if tt.args.wantTotalItems == 0 {
					// Nothing to page through, so Cloud receives the configured page size and no
					// page total, which is how it recognizes an unpaged inventory.
					assert.Equal(t, tt.fields.cloudPageSize, int(inventory.InventoryPage.PageSize))
					assert.Equal(t, 0, int(inventory.InventoryPage.TotalPages))
					continue
				}

				assert.Equal(t, wantItems, int(inventory.InventoryPage.PageSize), "page %d reported size", i+1)
				if inventory.InventoryPage.CurrentPage == inventory.InventoryPage.TotalPages {
					finalPages = append(finalPages, i+1)
				}
			}

			if tt.args.wantTotalItems > 0 {
				// Cloud runs its deletion sweep on the page where CurrentPage equals TotalPages,
				// so the last published page and only the last one has to satisfy it.
				assert.Equal(t, []int{len(tt.args.wantPageItems)}, finalPages)
			}
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
		request *corev1.InstanceReleaseRequest
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
				request: &corev1.InstanceReleaseRequest{
					Id: &corev1.InstanceId{Value: uuid.NewString()},
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
				request: &corev1.InstanceReleaseRequest{
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
				request: &corev1.InstanceReleaseRequest{
					Id: &corev1.InstanceId{Value: ""},
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
