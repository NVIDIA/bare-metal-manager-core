// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	tmocks "go.temporal.io/sdk/mocks"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/grpc"

	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"

	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/util"
)

func TestManageMachine_SetMachineMaintenanceOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.MaintenanceRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test enabling Machine maintenance mode success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.MaintenanceRequest{
					Operation: cwssaws.MaintenanceOperation_Enable,
					HostId:    &cwssaws.MachineId{Id: "test-machine-id"},
					Reference: util.GetStrPtr("test-reference"),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageMachine(tt.fields.coreGrpcAtomicClient)
			err := mm.SetMachineMaintenanceOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageMachine_UpdateMachineMetadataOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.MachineMetadataUpdateRequest
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test updating Machine metadata success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.MachineMetadataUpdateRequest{
					MachineId: &cwssaws.MachineId{Id: "test-machine-id"},
					Metadata: &cwssaws.Metadata{
						Labels: []*cwssaws.Label{
							{
								Key:   "test-key",
								Value: util.GetStrPtr("test-value"),
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewManageMachine(tt.fields.coreGrpcAtomicClient)
			err := mm.UpdateMachineMetadataOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageMachine_CreateMachineHealthReportOverrideOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	mm := NewManageMachine(coreGrpcAtomicClient)
	req := &cwssaws.InsertHealthReportOverrideRequest{
		MachineId: &cwssaws.MachineId{Id: "machine-1"},
		Override: &cwssaws.HealthReportOverride{
			Report: &cwssaws.HealthReport{
				Source: "request-online-repair",
				Alerts: []*cwssaws.HealthProbeAlert{
					{Id: "OnLineRepair", Message: `{"details":"d","issue_category":"OTHER","summary":"s"}`},
				},
			},
			Mode: cwssaws.OverrideMode_Merge,
		},
	}
	assert.NoError(t, mm.CreateMachineHealthReportOverrideOnSite(context.Background(), req))

	err := mm.CreateMachineHealthReportOverrideOnSite(context.Background(), nil)
	assert.Error(t, err)
}

func TestManageMachine_DeleteMachineHealthReportOverrideOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	mm := NewManageMachine(coreGrpcAtomicClient)
	req := &cwssaws.RemoveHealthReportOverrideRequest{
		MachineId: &cwssaws.MachineId{Id: "machine-1"},
		Source:    "request-online-repair",
	}
	assert.NoError(t, mm.DeleteMachineHealthReportOverrideOnSite(context.Background(), req))

	err := mm.DeleteMachineHealthReportOverrideOnSite(context.Background(), nil)
	assert.Error(t, err)
}

func Test_getPagedInventory(t *testing.T) {
	// Generate inventories
	pageSize := 25

	inventory1Machines := []*cwssaws.Machine{}
	inventory1MachineIDs := []*cwssaws.MachineId{}
	for i := 0; i < 95; i++ {
		inventory1Machines = append(inventory1Machines, &cwssaws.Machine{
			Id: &cwssaws.MachineId{
				Id: uuid.NewString(),
			},
			State: "Ready",
		})
		inventory1MachineIDs = append(inventory1MachineIDs, inventory1Machines[i].Id)
	}

	inventory2Machines := []*cwssaws.Machine{}
	inventory2MachineIDs := []*cwssaws.MachineId{}
	for i := 0; i < pageSize-5; i++ {
		inventory2Machines = append(inventory2Machines, &cwssaws.Machine{
			Id: &cwssaws.MachineId{
				Id: uuid.NewString(),
			},
			State: "Ready",
		})
		inventory2MachineIDs = append(inventory2MachineIDs, inventory2Machines[i].Id)
	}

	type args struct {
		pagedMachines   []*cwssaws.Machine
		pagedMachineIDs []*cwssaws.MachineId
		totalCount      int
		page            int
		pageSize        int
		status          cwssaws.InventoryStatus
		statusMessage   string
	}
	tests := []struct {
		name             string
		args             args
		wantMachineCount int
		wantTotalPages   int
		wantCurrentPage  int
		wantTotalItems   int
		wantItemIDCount  int
	}{
		{
			name: "test generating first page for empty inventory",
			args: args{
				pagedMachines:   nil,
				pagedMachineIDs: nil,
				totalCount:      0,
				page:            1,
				pageSize:        pageSize,
				status:          cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
				statusMessage:   "No Machines reported by SIte Controller",
			},
			wantMachineCount: 0,
			wantTotalPages:   0,
			wantCurrentPage:  1,
			wantTotalItems:   0,
			wantItemIDCount:  0,
		},
		{
			name: "test generating first page for normal inventory",
			args: args{
				pagedMachines:   inventory1Machines[:pageSize],
				pagedMachineIDs: inventory1MachineIDs[:pageSize],
				totalCount:      95,
				page:            1,
				pageSize:        pageSize,
				status:          cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
				statusMessage:   "Successfully retrieved Machines from Site Controller",
			},
			wantMachineCount: pageSize,
			wantTotalPages:   4,
			wantCurrentPage:  1,
			wantTotalItems:   95,
			wantItemIDCount:  pageSize,
		},
		{
			name: "test generating last page for inventory sized less than page size",
			args: args{
				pagedMachines:   inventory2Machines,
				pagedMachineIDs: inventory2MachineIDs,
				totalCount:      pageSize - 5,
				page:            1,
				pageSize:        pageSize,
				status:          cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
				statusMessage:   "Successfully retrieved Machines from Site Controller",
			},
			wantMachineCount: pageSize - 5,
			wantTotalPages:   1,
			wantCurrentPage:  1,
			wantTotalItems:   pageSize - 5,
			wantItemIDCount:  pageSize - 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPagedMachineInventory(tt.args.pagedMachines, tt.args.pagedMachineIDs, tt.args.totalCount, tt.args.page, tt.args.pageSize, tt.args.status, tt.args.statusMessage)
			assert.Equal(t, tt.wantMachineCount, len(got.Machines))
			assert.Equal(t, tt.wantCurrentPage, int(got.InventoryPage.CurrentPage))
			assert.Equal(t, tt.wantTotalPages, int(got.InventoryPage.TotalPages))
			assert.Equal(t, tt.wantTotalItems, int(got.InventoryPage.TotalItems))
			assert.Equal(t, tt.wantItemIDCount, len(got.InventoryPage.ItemIds))

			assert.Equal(t, tt.args.status, got.InventoryStatus)
			assert.Equal(t, tt.args.statusMessage, got.StatusMsg)
		})
	}
}

func Test_getPagedMachineIDs(t *testing.T) {
	type args struct {
		machineIDs []*cwssaws.MachineId
		page       int
		pageSize   int
	}
	tests := []struct {
		name               string
		args               args
		wantMachineIDCount int
	}{
		{
			name: "test getting first page for empty machine IDs",
			args: args{
				machineIDs: nil,
				page:       1,
				pageSize:   25,
			},
			wantMachineIDCount: 0,
		},
		{
			name: "test getting first page for normal machine IDs",
			args: args{
				machineIDs: []*cwssaws.MachineId{
					{Id: "machine-1"},
					{Id: "machine-2"},
					{Id: "machine-3"},
					{Id: "machine-4"},
					{Id: "machine-5"},
					{Id: "machine-6"},
					{Id: "machine-7"},
					{Id: "machine-8"},
					{Id: "machine-9"},
					{Id: "machine-10"},
				},
				page:     1,
				pageSize: 5,
			},
			wantMachineIDCount: 5,
		},
		{
			name: "test getting last page for machine IDs",
			args: args{
				machineIDs: []*cwssaws.MachineId{
					{Id: "machine-1"},
					{Id: "machine-2"},
					{Id: "machine-3"},
					{Id: "machine-4"},
					{Id: "machine-5"},
					{Id: "machine-6"},
					{Id: "machine-7"},
					{Id: "machine-8"},
					{Id: "machine-9"},
					{Id: "machine-10"},
				},
				page:     2,
				pageSize: 5,
			},
			wantMachineIDCount: 5,
		},
		{
			name: "test getting last page for machine IDs with less than page size",
			args: args{
				machineIDs: []*cwssaws.MachineId{
					{Id: "machine-1"},
					{Id: "machine-2"},
					{Id: "machine-3"},
					{Id: "machine-4"},
				},
				page:     1,
				pageSize: 5,
			},
			wantMachineIDCount: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPagedMachineIDs(tt.args.machineIDs, tt.args.page, tt.args.pageSize)
			assert.Equal(t, tt.wantMachineIDCount, len(got))
		})
	}
}

func TestManageMachineInventory_CollectAndPublishMachineInventory(t *testing.T) {
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
			name: "test collecting and publishing machine inventory, empty inventory",
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
			name: "test collecting and publishing machine inventory, normal inventory",
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

			mmi := &ManageMachineInventory{
				siteID:                tt.fields.siteID,
				coreGrpcAtomicClient:  tt.fields.coreGrpcAtomicClient,
				temporalPublishClient: tc,
				temporalPublishQueue:  tt.fields.temporalPublishQueue,
				sitePageSize:          tt.fields.sitePageSize,
				cloudPageSize:         tt.fields.cloudPageSize,
			}

			ctx := context.Background()
			ctx = context.WithValue(ctx, "wantCount", tt.args.wantTotalItems)

			totalPages := tt.args.wantTotalItems / tt.fields.cloudPageSize
			if tt.args.wantTotalItems%tt.fields.cloudPageSize > 0 {
				totalPages++
			}

			err := mmi.CollectAndPublishMachineInventory(ctx)
			assert.NoError(t, err)

			if tt.args.wantTotalItems == 0 {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 1)
			} else {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", totalPages)
			}

			inventory, ok := tc.Calls[0].Arguments[4].(*cwssaws.MachineInventory)
			assert.True(t, ok)

			if tt.args.wantTotalItems == 0 {
				assert.Equal(t, 0, len(inventory.Machines))
			} else {
				assert.Equal(t, tt.fields.cloudPageSize, len(inventory.Machines))
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

func TestManageMachine_GetDpuMachinesByIDs(t *testing.T) {
	// Custom mock implementation that returns DPU machines
	type mockDpuCoreGrpcClient struct {
		cClient.MockCoreGrpcServiceClient
	}

	mockFindMachinesByIds := func(ctx context.Context, in *cwssaws.MachinesByIdsRequest, opts ...grpc.CallOption) (*cwssaws.MachineList, error) {
		out := &cwssaws.MachineList{}
		if in != nil {
			for _, id := range in.MachineIds {
				out.Machines = append(out.Machines, &cwssaws.Machine{
					Id:          id,
					State:       "Ready",
					MachineType: cwssaws.MachineType_DPU,
				})
			}
		}
		return out, nil
	}

	mockGetNetworkConfig := func(ctx context.Context, in *cwssaws.ManagedHostNetworkConfigRequest, opts ...grpc.CallOption) (*cwssaws.ManagedHostNetworkConfigResponse, error) {
		return &cwssaws.ManagedHostNetworkConfigResponse{}, nil
	}

	type args struct {
		ctx           context.Context
		dpuMachineIDs []string
	}
	tests := []struct {
		name             string
		args             args
		wantDpuCount     int
		wantErr          bool
		wantNonRetryable bool
	}{
		{
			name: "test GetDpuMachinesByIDs returns correct DPU machines with matching IDs",
			args: args{
				ctx:           context.Background(),
				dpuMachineIDs: []string{"dpu-machine-1", "dpu-machine-2", "dpu-machine-3"},
			},
			wantDpuCount:     3,
			wantErr:          false,
			wantNonRetryable: false,
		},
		{
			name: "test GetDpuMachinesByIDs handles single machine ID",
			args: args{
				ctx:           context.Background(),
				dpuMachineIDs: []string{"dpu-machine-single"},
			},
			wantDpuCount:     1,
			wantErr:          false,
			wantNonRetryable: false,
		},
		{
			name: "test GetDpuMachinesByIDs with multiple machines verifies all IDs",
			args: args{
				ctx:           context.Background(),
				dpuMachineIDs: []string{"dpu-a", "dpu-b", "dpu-c", "dpu-d", "dpu-e"},
			},
			wantDpuCount:     5,
			wantErr:          false,
			wantNonRetryable: false,
		},
		{
			name: "test GetDpuMachinesByIDs rejects empty machine IDs with non-retryable error",
			args: args{
				ctx:           context.Background(),
				dpuMachineIDs: []string{},
			},
			wantDpuCount:     0,
			wantErr:          true,
			wantNonRetryable: true,
		},
		{
			name: "test GetDpuMachinesByIDs rejects nil machine IDs with non-retryable error",
			args: args{
				ctx:           context.Background(),
				dpuMachineIDs: nil,
			},
			wantDpuCount:     0,
			wantErr:          true,
			wantNonRetryable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock nico atomic client with our custom nico implementation
			baseAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
			baseClient := cClient.NewMockCoreGrpcClient()
			baseAtomicClient.SwapClient(baseClient)

			mm := &testManageMachineWithMock{
				ManageMachine: ManageMachine{
					coreGrpcAtomicClient: baseAtomicClient,
				},
				mockFindMachines: mockFindMachinesByIds,
				mockGetNetwork:   mockGetNetworkConfig,
			}

			got, err := mm.GetDpuMachinesByIDsWithMock(tt.args.ctx, tt.args.dpuMachineIDs)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantNonRetryable {
					var appErr *temporal.ApplicationError
					if errors.As(err, &appErr) {
						assert.True(t, appErr.NonRetryable(), "Expected error to be non-retryable")
					}
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, tt.wantDpuCount, len(got), "Expected %d DPU machines but got %d", tt.wantDpuCount, len(got))

				// Verify all returned DPU machines have correct structure and IDs
				returnedIDs := make(map[string]bool)
				for i, dpuMachine := range got {
					assert.NotNil(t, dpuMachine, "DPU machine at index %d should not be nil", i)
					assert.NotNil(t, dpuMachine.Machine, "DPU machine.Machine at index %d should not be nil", i)
					assert.Equal(t, cwssaws.MachineType_DPU, dpuMachine.Machine.MachineType,
						"DPU machine at index %d should have type DPU", i)
					assert.NotNil(t, dpuMachine.Machine.Id, "DPU machine ID at index %d should not be nil", i)
					assert.NotEmpty(t, dpuMachine.Machine.Id.Id, "DPU machine ID string at index %d should not be empty", i)
					assert.Equal(t, "Ready", dpuMachine.Machine.State, "DPU machine at index %d should be in Ready state", i)

					// Verify the machine ID matches one of the requested IDs
					machineID := dpuMachine.Machine.Id.Id
					found := false
					for _, requestedID := range tt.args.dpuMachineIDs {
						if machineID == requestedID {
							found = true
							break
						}
					}
					assert.True(t, found, "DPU machine ID '%s' at index %d should be in requested list %v",
						machineID, i, tt.args.dpuMachineIDs)

					// Track returned IDs to ensure no duplicates
					assert.False(t, returnedIDs[machineID], "DPU machine ID '%s' should not be returned twice", machineID)
					returnedIDs[machineID] = true

					// Network config should be present
					assert.NotNil(t, dpuMachine.DpuNetworkConfig,
						"DPU network config at index %d should not be nil", i)
				}

				// Verify all requested IDs were returned
				for _, requestedID := range tt.args.dpuMachineIDs {
					assert.True(t, returnedIDs[requestedID],
						"Requested DPU machine ID '%s' should be in the returned results", requestedID)
				}
			}
		})
	}
}

// testManageMachineWithMock wraps ManageMachine and overrides the gRPC calls for testing
type testManageMachineWithMock struct {
	ManageMachine
	mockFindMachines func(context.Context, *cwssaws.MachinesByIdsRequest, ...grpc.CallOption) (*cwssaws.MachineList, error)
	mockGetNetwork   func(context.Context, *cwssaws.ManagedHostNetworkConfigRequest, ...grpc.CallOption) (*cwssaws.ManagedHostNetworkConfigResponse, error)
}

// GetDpuMachinesByIDsWithMock is a test version that uses our mocked responses
func (mm *testManageMachineWithMock) GetDpuMachinesByIDsWithMock(ctx context.Context, dpuMachineIDs []string) ([]*cwssaws.DpuMachine, error) {
	logger := log.With().Str("Activity", "GetDpuMachinesByIDs").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if len(dpuMachineIDs) == 0 {
		err = errors.New("received GetDpuMachinesByIDs request without DPU Machine IDs")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), "INVALID_REQUEST", err)
	}

	// Convert string IDs to MachineId objects
	machineIDs := make([]*cwssaws.MachineId, 0, len(dpuMachineIDs))
	for _, id := range dpuMachineIDs {
		machineIDs = append(machineIDs, &cwssaws.MachineId{Id: id})
	}

	request := &cwssaws.MachinesByIdsRequest{
		MachineIds: machineIDs,
	}

	// Use mock instead of real client
	machineList, err := mm.mockFindMachines(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to retrieve DPU Machines by IDs")
		return nil, err
	}

	// For each DPU machine, fetch the network configuration
	dpuMachines := make([]*cwssaws.DpuMachine, 0, len(machineList.Machines))
	for _, machine := range machineList.Machines {
		if machine.MachineType == cwssaws.MachineType_DPU {
			networkConfigReq := &cwssaws.ManagedHostNetworkConfigRequest{
				DpuMachineId: machine.Id,
			}
			networkConfig, nerr := mm.mockGetNetwork(ctx, networkConfigReq)
			if nerr != nil {
				logger.Warn().Err(nerr).Str("DPU Machine ID", machine.Id.Id).Msg("Failed to retrieve network config for DPU machine, continuing without it")
			} else {
				logger.Debug().Str("DPU Machine ID", machine.Id.Id).Msg("Retrieved network config for DPU machine")
			}
			dpuMachines = append(dpuMachines, &cwssaws.DpuMachine{
				Machine:          machine,
				DpuNetworkConfig: networkConfig,
			})
		}
	}

	logger.Info().Int("dpu_machine_count", len(dpuMachines)).Msg("Completed activity")
	return dpuMachines, nil
}
