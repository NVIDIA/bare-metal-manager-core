// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/common/pkg/util/labels"
	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestManageExpectedRack_CreateExpectedRackOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedRack
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test create expected rack success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedRack{
					RackId:   &cwssaws.RackId{Id: "test-rack-001"},
					RackType: "test-rack-profile-001",
				},
			},
			wantErr: false,
		},
		{
			name: "test create expected rack fail on missing rack_id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedRack{
					RackId:   nil,
					RackType: "test-rack-profile-001",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected rack fail on missing rack_profile_id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedRack{
					RackId:   &cwssaws.RackId{Id: "test-rack-002"},
					RackType: "",
				},
			},
			wantErr: true,
		},
		{
			name: "test create expected rack fail on missing request",
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
			mer := NewManageExpectedRack(tt.fields.coreGrpcAtomicClient, nil)
			err := mer.CreateExpectedRackOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedRack_UpdateExpectedRackOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedRack
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test update expected rack success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedRack{
					RackId:   &cwssaws.RackId{Id: "test-update-rack-001"},
					RackType: "test-update-rack-profile-001",
				},
			},
			wantErr: false,
		},
		{
			name: "test update expected rack fail on missing rack_id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedRack{
					RackId:   nil,
					RackType: "test-update-rack-profile-001",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected rack fail on missing rack_profile_id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedRack{
					RackId:   &cwssaws.RackId{Id: "test-update-rack-002"},
					RackType: "",
				},
			},
			wantErr: true,
		},
		{
			name: "test update expected rack fail on missing request",
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
			mer := NewManageExpectedRack(tt.fields.coreGrpcAtomicClient, nil)
			err := mer.UpdateExpectedRackOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedRack_DeleteExpectedRackOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedRackRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test delete expected rack success",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedRackRequest{
					RackId: "test-delete-rack-001",
				},
			},
			wantErr: false,
		},
		{
			name: "test delete expected rack fail on empty rack_id",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedRackRequest{
					RackId: "",
				},
			},
			wantErr: true,
		},
		{
			name: "test delete expected rack fail on missing request",
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
			mer := NewManageExpectedRack(tt.fields.coreGrpcAtomicClient, nil)
			err := mer.DeleteExpectedRackOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedRack_ReplaceAllExpectedRacksOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	type fields struct {
		coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
	}
	type args struct {
		ctx     context.Context
		request *cwssaws.ExpectedRackList
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test replace all expected racks success with empty list",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx:     context.Background(),
				request: &cwssaws.ExpectedRackList{},
			},
			wantErr: false,
		},
		{
			name: "test replace all expected racks success with valid list",
			fields: fields{
				coreGrpcAtomicClient: coreGrpcAtomicClient,
			},
			args: args{
				ctx: context.Background(),
				request: &cwssaws.ExpectedRackList{
					ExpectedRacks: []*cwssaws.ExpectedRack{
						{
							RackId:   &cwssaws.RackId{Id: "test-replace-rack-001"},
							RackType: "test-replace-rack-profile-001",
						},
						{
							RackId:   &cwssaws.RackId{Id: "test-replace-rack-002"},
							RackType: "test-replace-rack-profile-002",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test replace all expected racks fail on missing request",
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
			mer := NewManageExpectedRack(tt.fields.coreGrpcAtomicClient, nil)
			err := mer.ReplaceAllExpectedRacksOnSite(tt.args.ctx, tt.args.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageExpectedRack_DeleteAllExpectedRacksOnSite(t *testing.T) {
	mockCoreGrpcClient := cClient.NewMockCoreGrpcClient()

	coreGrpcAtomicClient := cClient.NewCoreGrpcAtomicClient(&cClient.CoreGrpcClientConfig{})
	coreGrpcAtomicClient.SwapClient(mockCoreGrpcClient)

	mer := NewManageExpectedRack(coreGrpcAtomicClient, nil)
	err := mer.DeleteAllExpectedRacksOnSite(context.Background())
	assert.NoError(t, err)
}

func TestManageExpectedRack_CreateExpectedRackOnFlow(t *testing.T) {
	t.Run("nil Flow client skips gracefully", func(t *testing.T) {
		mer := ManageExpectedRack{flowGrpcAtomicClient: nil}
		err := mer.CreateExpectedRackOnFlow(context.Background(), &cwssaws.ExpectedRack{
			RackId:   &cwssaws.RackId{Id: uuid.NewString()},
			RackType: uuid.NewString(),
		})
		assert.NoError(t, err)
	})

	t.Run("nil Flow client connection skips gracefully", func(t *testing.T) {
		mer := ManageExpectedRack{flowGrpcAtomicClient: cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})}
		err := mer.CreateExpectedRackOnFlow(context.Background(), &cwssaws.ExpectedRack{
			RackId:   &cwssaws.RackId{Id: uuid.NewString()},
			RackType: uuid.NewString(),
		})
		assert.NoError(t, err)
	})
}

func Test_expectedRackToFlowRack(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	t.Run("maps all fields with full labels", func(t *testing.T) {
		rack := &cwssaws.ExpectedRack{
			RackId:   &cwssaws.RackId{Id: "rack-001"},
			RackType: "rack-profile-001",
			Metadata: &cwssaws.Metadata{
				Name:        "rack-alpha",
				Description: "Primary compute rack",
				Labels: []*cwssaws.Label{
					{Key: labels.RackLabelChassisManufacturer, Value: strPtr("NVIDIA")},
					{Key: labels.RackLabelChassisSerialNumber, Value: strPtr("SN-RACK-001")},
					{Key: labels.RackLabelChassisModel, Value: strPtr("MGX-1000")},
					{Key: labels.RackLabelLocationRegion, Value: strPtr("us-east-1")},
					{Key: labels.RackLabelLocationDatacenter, Value: strPtr("dc1")},
					{Key: labels.RackLabelLocationRoom, Value: strPtr("room-A")},
					{Key: labels.RackLabelLocationPosition, Value: strPtr("row-3-col-7")},
				},
			},
		}
		var flowRack *flowv1.Rack = expectedRackToFlowRack(rack)

		if assert.NotNil(t, flowRack.Info) {
			assert.NotNil(t, flowRack.Info.Id)
			assert.Equal(t, "rack-001", flowRack.Info.Id.Id)
			assert.Equal(t, "rack-alpha", flowRack.Info.Name)
			assert.Equal(t, "NVIDIA", flowRack.Info.Manufacturer)
			assert.Equal(t, "SN-RACK-001", flowRack.Info.SerialNumber)
			if assert.NotNil(t, flowRack.Info.Model) {
				assert.Equal(t, "MGX-1000", *flowRack.Info.Model)
			}
			if assert.NotNil(t, flowRack.Info.Description) {
				assert.Equal(t, "Primary compute rack", *flowRack.Info.Description)
			}
		}

		if assert.NotNil(t, flowRack.Location) {
			assert.Equal(t, "us-east-1", flowRack.Location.Region)
			assert.Equal(t, "dc1", flowRack.Location.Datacenter)
			assert.Equal(t, "room-A", flowRack.Location.Room)
			assert.Equal(t, "row-3-col-7", flowRack.Location.Position)
		}
	})

	t.Run("handles minimal fields (no metadata)", func(t *testing.T) {
		rack := &cwssaws.ExpectedRack{
			RackId:   &cwssaws.RackId{Id: "rack-002"},
			RackType: "rack-profile-002",
		}
		flowRack := expectedRackToFlowRack(rack)

		if assert.NotNil(t, flowRack.Info) {
			if assert.NotNil(t, flowRack.Info.Id) {
				assert.Equal(t, "rack-002", flowRack.Info.Id.Id)
			}
			assert.Empty(t, flowRack.Info.Name)
			assert.Empty(t, flowRack.Info.Manufacturer)
			assert.Empty(t, flowRack.Info.SerialNumber)
			assert.Nil(t, flowRack.Info.Model)
			assert.Nil(t, flowRack.Info.Description)
		}

		if assert.NotNil(t, flowRack.Location) {
			assert.Empty(t, flowRack.Location.Region)
			assert.Empty(t, flowRack.Location.Datacenter)
			assert.Empty(t, flowRack.Location.Room)
			assert.Empty(t, flowRack.Location.Position)
		}
	})

	t.Run("handles partial labels", func(t *testing.T) {
		rack := &cwssaws.ExpectedRack{
			RackId:   &cwssaws.RackId{Id: "rack-003"},
			RackType: "rack-profile-003",
			Metadata: &cwssaws.Metadata{
				Name: "rack-bravo",
				Labels: []*cwssaws.Label{
					{Key: labels.RackLabelChassisManufacturer, Value: strPtr("NVIDIA")},
					{Key: labels.RackLabelLocationRegion, Value: strPtr("us-west-2")},
				},
			},
		}
		flowRack := expectedRackToFlowRack(rack)

		if assert.NotNil(t, flowRack.Info) {
			assert.Equal(t, "rack-bravo", flowRack.Info.Name)
			assert.Equal(t, "NVIDIA", flowRack.Info.Manufacturer)
			assert.Empty(t, flowRack.Info.SerialNumber)
			assert.Nil(t, flowRack.Info.Model)
			assert.Nil(t, flowRack.Info.Description)
		}

		if assert.NotNil(t, flowRack.Location) {
			assert.Equal(t, "us-west-2", flowRack.Location.Region)
			assert.Empty(t, flowRack.Location.Datacenter)
			assert.Empty(t, flowRack.Location.Room)
			assert.Empty(t, flowRack.Location.Position)
		}
	})

}
