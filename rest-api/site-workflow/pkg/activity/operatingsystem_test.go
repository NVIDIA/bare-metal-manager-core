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
	tmocks "go.temporal.io/sdk/mocks"
)

func TestManageOsImage_CreateOsImageOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	orgID := "m4jjok8wsg"

	type fields struct {
		CoreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.OsImageAttributes
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test create Operating System success",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.OsImageAttributes{
					TenantOrganizationId: orgID,
					SourceUrl:            "http://imagenet.com",
					Digest:               "1231d1dffq213123",
				},
			},
			wantErr: false,
		},
		{
			name: "test create Operating System fails on missing org ID",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.OsImageAttributes{
					SourceUrl: "http://imagenet.com",
					Digest:    "1231d1dffq213123",
				},
			},
			wantErr: true,
		},
		{
			name: "test create Operating System fails on missing source url",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.OsImageAttributes{
					TenantOrganizationId: orgID,
					Digest:               "1231d1dffq213123",
				},
			},
			wantErr: true,
		},
		{
			name: "test create Operating System fails on missing digest",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.OsImageAttributes{
					SourceUrl:            "http://imagenet.com",
					TenantOrganizationId: orgID,
				},
			},
			wantErr: true,
		},
		{
			name: "test create Operating System fails on missing request",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
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
			mt := NewManageOperatingSystem(tt.fields.CoreGrpcAtomicClient)
			err := mt.CreateOsImageOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageOsImage_UpdateOsImageOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	orgID := "m4jjok8wsg"

	type fields struct {
		CoreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.OsImageAttributes
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test update Operating System success",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.OsImageAttributes{
					TenantOrganizationId: orgID,
					SourceUrl:            "http://updateimagenet.com",
					Digest:               "1231231dqweffqwq342",
				},
			},
			wantErr: false,
		},
		{
			name: "test update Operating System fails on missing org ID",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.OsImageAttributes{
					SourceUrl: "http://updateimagenet.com",
					Digest:    "1231231dqweffqwq342",
				},
			},
			wantErr: true,
		},
		{
			name: "test update Operating System fails on missing source url",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.OsImageAttributes{
					TenantOrganizationId: orgID,
					Digest:               "1231231dqweffqwq342",
				},
			},
			wantErr: true,
		},
		{
			name: "test update Operating System fails on missing digest",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.OsImageAttributes{
					SourceUrl:            "http://updateimagenet.com",
					TenantOrganizationId: orgID,
				},
			},
			wantErr: true,
		},
		{
			name: "test update Operating System fails on missing request",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
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
			mt := NewManageOperatingSystem(tt.fields.CoreGrpcAtomicClient)
			err := mt.UpdateOsImageOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageOsImage_DeleteOsImageOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	orgID := "m4jjok8wsg"

	type fields struct {
		CoreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.DeleteOsImageRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test delete Operating System success",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.DeleteOsImageRequest{
					Id:                   &cwssaws.UUID{Value: uuid.NewString()},
					TenantOrganizationId: orgID,
				},
			},
			wantErr: false,
		},
		{
			name: "test delete Operating System fails on missing org ID",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx:     context.Background(),
				request: &cwssaws.DeleteOsImageRequest{},
			},
			wantErr: true,
		},
		{
			name: "test delete Operating System fails on missing request",
			fields: fields{
				CoreGrpcAtomicClient: coreGrpcAtomicClient,
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
			mt := NewManageOperatingSystem(tt.fields.CoreGrpcAtomicClient)
			err := mt.DeleteOsImageOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageOperatingSystem_CreateOperatingSystemOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()
	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	validID := &cwssaws.OperatingSystemId{Value: uuid.NewString()}

	type fields struct {
		CoreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.CreateOperatingSystemRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "success - creates OS in nico-core",
			fields: fields{CoreGrpcAtomicClient: coreGrpcAtomicClient},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.CreateOperatingSystemRequest{
					Id:                   validID,
					Name:                 "test-os",
					TenantOrganizationId: "TestOrg",
				},
			},
			wantErr: false,
		},
		{
			name:   "fails - nil request",
			fields: fields{CoreGrpcAtomicClient: coreGrpcAtomicClient},
			args: args{
				ctx:     context.Background(),
				request: nil,
			},
			wantErr: true,
		},
		{
			name:   "fails - missing Name",
			fields: fields{CoreGrpcAtomicClient: coreGrpcAtomicClient},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.CreateOperatingSystemRequest{
					Id:                   validID,
					TenantOrganizationId: "TestOrg",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mos := NewManageOperatingSystem(tt.fields.CoreGrpcAtomicClient)
			_, err := mos.CreateOperatingSystemOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageOperatingSystem_UpdateOperatingSystemOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()
	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	validID := &cwssaws.OperatingSystemId{Value: uuid.NewString()}

	type fields struct {
		CoreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.UpdateOperatingSystemRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "success - updates OS in nico-core",
			fields: fields{CoreGrpcAtomicClient: coreGrpcAtomicClient},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.UpdateOperatingSystemRequest{
					Id: validID,
				},
			},
			wantErr: false,
		},
		{
			name:   "fails - nil request",
			fields: fields{CoreGrpcAtomicClient: coreGrpcAtomicClient},
			args: args{
				ctx:     context.Background(),
				request: nil,
			},
			wantErr: true,
		},
		{
			name:   "fails - missing ID",
			fields: fields{CoreGrpcAtomicClient: coreGrpcAtomicClient},
			args: args{
				ctx:     context.Background(),
				request: &cwssaws.UpdateOperatingSystemRequest{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mos := NewManageOperatingSystem(tt.fields.CoreGrpcAtomicClient)
			err := mos.UpdateOperatingSystemOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageOperatingSystem_DeleteOperatingSystemOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()
	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	validID := &cwssaws.OperatingSystemId{Value: uuid.NewString()}

	type fields struct {
		CoreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.DeleteOperatingSystemRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "success - deletes OS from nico-core",
			fields: fields{CoreGrpcAtomicClient: coreGrpcAtomicClient},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.DeleteOperatingSystemRequest{
					Id: validID,
				},
			},
			wantErr: false,
		},
		{
			name:   "fails - nil request",
			fields: fields{CoreGrpcAtomicClient: coreGrpcAtomicClient},
			args: args{
				ctx:     context.Background(),
				request: nil,
			},
			wantErr: true,
		},
		{
			name:   "fails - missing ID",
			fields: fields{CoreGrpcAtomicClient: coreGrpcAtomicClient},
			args: args{
				ctx:     context.Background(),
				request: &cwssaws.DeleteOperatingSystemRequest{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mos := NewManageOperatingSystem(tt.fields.CoreGrpcAtomicClient)
			err := mos.DeleteOperatingSystemOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageOperatingSystemInventory_DiscoverOperatingSystemInventory(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()
	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	wid := "test-os-workflow-id"
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return(wid)

	type fields struct {
		siteID              uuid.UUID
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
		publishQueue        string
	}
	type args struct {
		wantOSCount int
		wantError   error
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "success - empty inventory published",
			fields: fields{
				siteID:              uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				publishQueue:        "test-queue",
			},
			args:    args{wantOSCount: 0},
			wantErr: false,
		},
		{
			name: "success - non-empty inventory published",
			fields: fields{
				siteID:              uuid.New(),
				coreGrpcAtomicClient: coreGrpcAtomicClient,
				publishQueue:        "test-queue",
			},
			args:    args{wantOSCount: 5},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &tmocks.Client{}
			tc.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
				mock.AnythingOfType("string"), mock.AnythingOfType("uuid.UUID"), mock.Anything).Return(wrun, nil)

			inv := NewManageOperatingSystemInventory(ManageInventoryConfig{
				SiteID:                tt.fields.siteID,
				CoreGrpcAtomicClient:   tt.fields.coreGrpcAtomicClient,
				TemporalPublishClient: tc,
				TemporalPublishQueue:  tt.fields.publishQueue,
			})

			ctx := context.Background()
			ctx = context.WithValue(ctx, "wantCount", tt.args.wantOSCount)

			err := inv.DiscoverOperatingSystemInventory(ctx)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				tc.AssertCalled(t, "ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)

				inventory, ok := tc.Calls[0].Arguments[4].(*cwssaws.OperatingSystemInventory)
				assert.True(t, ok, "expected OperatingSystemInventory argument")
				assert.Equal(t, cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS, inventory.GetInventoryStatus())
				assert.Len(t, inventory.GetOperatingSystems(), tt.args.wantOSCount)
			}
		})
	}
}

func TestManageOperatingSystemInventory_DiscoverOperatingSystemInventory_NilClient(t *testing.T) {
	// Simulate the case where the gRPC client is not yet connected (nil).
	// Before the fix this caused a nil pointer dereference panic.
	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	// deliberately do NOT swap in a real client — value stays nil

	tc := &tmocks.Client{}

	inv := NewManageOperatingSystemInventory(ManageInventoryConfig{
		SiteID:                uuid.New(),
		CoreGrpcAtomicClient:   coreGrpcAtomicClient,
		TemporalPublishClient: tc,
		TemporalPublishQueue:  "test-queue",
	})

	err := inv.DiscoverOperatingSystemInventory(context.Background())
	assert.ErrorIs(t, err, cClient.ErrCoreGrpcClientNotConnected)
	tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 0)
}

func TestManageOsImageInventory_DiscoverOsImageInventory(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	wid := "test-workflow-id"
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return(wid)

	type fields struct {
		siteID               uuid.UUID
		coreGrpcAtomicClient  *cClient.CoreGrpcAtomicClient
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
			name: "test collecting and publishing os image inventory fallback, empty inventory",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient:  coreGrpcAtomicClient,
				temporalPublishQueue: "test-queue",
				sitePageSize:         100,
				cloudPageSize:        25,
			},
			args: args{
				wantTotalItems: 0,
			},
		},
		{
			name: "test collecting and publishing os image inventory fallback, normal inventory",
			fields: fields{
				siteID:               uuid.New(),
				coreGrpcAtomicClient:  coreGrpcAtomicClient,
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

			manageOsImage := NewManageOsImageInventory(ManageInventoryConfig{
				SiteID:                tt.fields.siteID,
				CoreGrpcAtomicClient:   tt.fields.coreGrpcAtomicClient,
				TemporalPublishClient: tc,
				TemporalPublishQueue:  tt.fields.temporalPublishQueue,
				SitePageSize:          tt.fields.sitePageSize,
				CloudPageSize:         tt.fields.cloudPageSize,
			})

			ctx := context.Background()
			ctx = context.WithValue(ctx, "wantCount", tt.args.wantTotalItems)
			if tt.args.findIDsError != nil {
				ctx = context.WithValue(ctx, "wantError", tt.args.findIDsError)
			}

			totalPages := tt.args.wantTotalItems / tt.fields.cloudPageSize
			if tt.args.wantTotalItems%tt.fields.cloudPageSize > 0 {
				totalPages++
			}

			err := manageOsImage.DiscoverOsImageInventory(ctx)
			assert.NoError(t, err)

			if tt.args.wantTotalItems == 0 {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", 1)
			} else {
				tc.AssertNumberOfCalls(t, "ExecuteWorkflow", totalPages)
			}

			inventory, ok := tc.Calls[0].Arguments[4].(*cwssaws.OsImageInventory)
			assert.True(t, ok)

			if tt.args.wantTotalItems == 0 {
				assert.Equal(t, 0, len(inventory.OsImages))
			} else {
				assert.Equal(t, tt.fields.cloudPageSize, len(inventory.OsImages))
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
