// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	"github.com/stretchr/testify/assert"
)

func TestNewAPIRack(t *testing.T) {
	description := "Test rack description"
	model := "NVL72"

	tests := []struct {
		name           string
		rack           *flowv1.Rack
		withComponents bool
		want           *APIRack
	}{
		{
			name:           "nil rack returns nil",
			rack:           nil,
			withComponents: false,
			want:           nil,
		},
		{
			name: "basic rack without components",
			rack: &flowv1.Rack{
				Info: &flowv1.DeviceInfo{
					Id:           &flowv1.UUID{Id: "test-rack-id"},
					Name:         "test-rack",
					Manufacturer: "NVIDIA",
					Model:        &model,
					SerialNumber: "SN12345",
					Description:  &description,
				},
				Location: &flowv1.Location{
					Region:     "us-west-2",
					Datacenter: "DC1",
					Room:       "Room-A",
					Position:   "Row-1-Pos-5",
				},
			},
			withComponents: false,
			want: &APIRack{
				ID:           "test-rack-id",
				Name:         "test-rack",
				Manufacturer: "NVIDIA",
				Model:        "NVL72",
				SerialNumber: "SN12345",
				Description:  "Test rack description",
				Location: &APIRackLocation{
					Region:     "us-west-2",
					Datacenter: "DC1",
					Room:       "Room-A",
					Position:   "Row-1-Pos-5",
				},
				Components: nil,
			},
		},
		{
			name: "rack with components",
			rack: &flowv1.Rack{
				Info: &flowv1.DeviceInfo{
					Id:   &flowv1.UUID{Id: "rack-with-components"},
					Name: "rack-1",
				},
				Components: []*flowv1.Component{
					{
						Type: flowv1.ComponentType_COMPONENT_TYPE_COMPUTE,
						Info: &flowv1.DeviceInfo{
							Id:           &flowv1.UUID{Id: "comp-1"},
							Name:         "compute-node-1",
							SerialNumber: "CSN001",
							Manufacturer: "NVIDIA",
						},
						FirmwareVersion: "1.0.0",
						Position: &flowv1.RackPosition{
							SlotId: 1,
						},
						ComponentId: "nico-machine-123",
					},
					{
						Type: flowv1.ComponentType_COMPONENT_TYPE_TORSWITCH,
						Info: &flowv1.DeviceInfo{
							Id:   &flowv1.UUID{Id: "comp-2"},
							Name: "switch-1",
						},
						Position: &flowv1.RackPosition{
							SlotId: 48,
						},
					},
				},
			},
			withComponents: true,
			want: &APIRack{
				ID:   "rack-with-components",
				Name: "rack-1",
				Components: []*APIRackComponent{
					{
						ID:              "comp-1",
						ComponentID:     "nico-machine-123",
						Type:            "Compute",
						Name:            "compute-node-1",
						SerialNumber:    "CSN001",
						Manufacturer:    "NVIDIA",
						FirmwareVersion: "1.0.0",
						SlotID:          1,
					},
					{
						ID:     "comp-2",
						Type:   "TORSwitch",
						Name:   "switch-1",
						SlotID: 48,
					},
				},
			},
		},
		{
			name: "rack with components but withComponents=false",
			rack: &flowv1.Rack{
				Info: &flowv1.DeviceInfo{
					Id:   &flowv1.UUID{Id: "rack-id"},
					Name: "rack-name",
				},
				Components: []*flowv1.Component{
					{
						Type: flowv1.ComponentType_COMPONENT_TYPE_COMPUTE,
						Info: &flowv1.DeviceInfo{
							Id:   &flowv1.UUID{Id: "comp-1"},
							Name: "compute-node-1",
						},
					},
				},
			},
			withComponents: false,
			want: &APIRack{
				ID:         "rack-id",
				Name:       "rack-name",
				Components: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAPIRack(tt.rack, tt.withComponents)

			if tt.want == nil {
				assert.Nil(t, got)
				return
			}

			assert.NotNil(t, got)
			assert.Equal(t, tt.want.ID, got.ID)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Manufacturer, got.Manufacturer)
			assert.Equal(t, tt.want.Model, got.Model)
			assert.Equal(t, tt.want.SerialNumber, got.SerialNumber)
			assert.Equal(t, tt.want.Description, got.Description)

			if tt.want.Location != nil {
				assert.NotNil(t, got.Location)
				assert.Equal(t, tt.want.Location.Region, got.Location.Region)
				assert.Equal(t, tt.want.Location.Datacenter, got.Location.Datacenter)
				assert.Equal(t, tt.want.Location.Room, got.Location.Room)
				assert.Equal(t, tt.want.Location.Position, got.Location.Position)
			}

			if tt.want.Components != nil {
				assert.NotNil(t, got.Components)
				assert.Equal(t, len(tt.want.Components), len(got.Components))
				for i, wantComp := range tt.want.Components {
					gotComp := got.Components[i]
					assert.Equal(t, wantComp.ID, gotComp.ID)
					assert.Equal(t, wantComp.ComponentID, gotComp.ComponentID)
					assert.Equal(t, wantComp.Type, gotComp.Type)
					assert.Equal(t, wantComp.Name, gotComp.Name)
					assert.Equal(t, wantComp.SerialNumber, gotComp.SerialNumber)
					assert.Equal(t, wantComp.Manufacturer, gotComp.Manufacturer)
					assert.Equal(t, wantComp.FirmwareVersion, gotComp.FirmwareVersion)
					assert.Equal(t, wantComp.SlotID, gotComp.SlotID)
				}
			} else {
				assert.Nil(t, got.Components)
			}
		})
	}
}

func TestAPIBringUpRackRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		request APIBringUpRackRequest
		wantErr bool
	}{
		{
			name:    "valid - with siteId",
			request: APIBringUpRackRequest{SiteID: "site-1"},
			wantErr: false,
		},
		{
			name:    "valid - with siteId and description",
			request: APIBringUpRackRequest{SiteID: "site-1", Description: "bring up rack"},
			wantErr: false,
		},
		{
			name:    "invalid - missing siteId",
			request: APIBringUpRackRequest{},
			wantErr: true,
		},
		{
			name:    "invalid - empty siteId",
			request: APIBringUpRackRequest{SiteID: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewAPIBringUpRackResponse(t *testing.T) {
	tests := []struct {
		name     string
		resp     *flowv1.SubmitTaskResponse
		expected *APIBringUpRackResponse
	}{
		{
			name:     "nil response returns empty task IDs",
			resp:     nil,
			expected: &APIBringUpRackResponse{TaskIDs: []string{}},
		},
		{
			name: "single task ID",
			resp: &flowv1.SubmitTaskResponse{
				TaskIds: []*flowv1.UUID{{Id: "task-1"}},
			},
			expected: &APIBringUpRackResponse{TaskIDs: []string{"task-1"}},
		},
		{
			name: "multiple task IDs",
			resp: &flowv1.SubmitTaskResponse{
				TaskIds: []*flowv1.UUID{{Id: "task-1"}, {Id: "task-2"}},
			},
			expected: &APIBringUpRackResponse{TaskIDs: []string{"task-1", "task-2"}},
		},
		{
			name:     "empty task IDs",
			resp:     &flowv1.SubmitTaskResponse{},
			expected: &APIBringUpRackResponse{TaskIDs: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewAPIBringUpRackResponse(tt.resp)
			assert.NotNil(t, result)
			assert.Equal(t, tt.expected.TaskIDs, result.TaskIDs)
		})
	}
}

func TestAPIBatchBringUpRackRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		request APIBatchBringUpRackRequest
		wantErr bool
	}{
		{
			name:    "valid - with siteId only",
			request: APIBatchBringUpRackRequest{SiteID: "site-1"},
			wantErr: false,
		},
		{
			name: "valid - with filter",
			request: APIBatchBringUpRackRequest{
				SiteID: "site-1",
				Filter: &RackFilter{Names: []string{"Rack-001"}},
			},
			wantErr: false,
		},
		{
			name: "valid - with description",
			request: APIBatchBringUpRackRequest{
				SiteID:      "site-1",
				Description: "batch bring up",
			},
			wantErr: false,
		},
		{
			name:    "invalid - missing siteId",
			request: APIBatchBringUpRackRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
