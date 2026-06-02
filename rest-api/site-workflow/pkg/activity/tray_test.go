// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"
	"testing"

	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	"github.com/stretchr/testify/assert"
)

func TestManageTray_GetTray(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.GetComponentInfoByIDRequest
		mockResp    *flowv1.GetComponentInfoResponse
		mockErr     error
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			mockResp:    nil,
			mockErr:     nil,
			wantErr:     true,
			errContains: "empty get tray request",
		},
		{
			name: "request with nil ID returns error",
			request: &flowv1.GetComponentInfoByIDRequest{
				Id: nil,
			},
			mockResp:    nil,
			mockErr:     nil,
			wantErr:     true,
			errContains: "missing tray ID",
		},
		{
			name: "request with empty ID returns error",
			request: &flowv1.GetComponentInfoByIDRequest{
				Id: &flowv1.UUID{Id: ""},
			},
			mockResp:    nil,
			mockErr:     nil,
			wantErr:     true,
			errContains: "missing tray ID",
		},
		{
			name: "successful request - compute tray",
			request: &flowv1.GetComponentInfoByIDRequest{
				Id: &flowv1.UUID{Id: "test-tray-id"},
			},
			mockResp: &flowv1.GetComponentInfoResponse{
				Component: &flowv1.Component{
					Type: flowv1.ComponentType_COMPONENT_TYPE_COMPUTE,
					Info: &flowv1.DeviceInfo{
						Id:           &flowv1.UUID{Id: "test-tray-id"},
						Name:         "Test Compute Tray",
						Manufacturer: "NVIDIA",
						SerialNumber: "TSN001",
					},
					FirmwareVersion: "2.0.0",
					ComponentId:     "nico-machine-123",
					Position: &flowv1.RackPosition{
						SlotId:  1,
						TrayIdx: 0,
						HostId:  1,
					},
				},
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name: "successful request - switch tray",
			request: &flowv1.GetComponentInfoByIDRequest{
				Id: &flowv1.UUID{Id: "switch-tray-id"},
			},
			mockResp: &flowv1.GetComponentInfoResponse{
				Component: &flowv1.Component{
					Type: flowv1.ComponentType_COMPONENT_TYPE_NVSWITCH,
					Info: &flowv1.DeviceInfo{
						Id:   &flowv1.UUID{Id: "switch-tray-id"},
						Name: "NVSwitch Tray",
					},
				},
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name: "Flow client error",
			request: &flowv1.GetComponentInfoByIDRequest{
				Id: &flowv1.UUID{Id: "test-tray-id"},
			},
			mockResp:    nil,
			mockErr:     errors.New("connection refused"),
			wantErr:     true,
			errContains: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock Flow client
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()

			// Create atomic client and swap with mock
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)

			// Create ManageTray instance
			manageTray := NewManageTray(flowGrpcAtomicClient)

			// Execute activity with context injection
			ctx := context.Background()
			if tt.mockErr != nil {
				ctx = context.WithValue(ctx, "wantError", tt.mockErr)
			}
			if tt.mockResp != nil {
				ctx = context.WithValue(ctx, "wantResponse", tt.mockResp)
			}
			result, err := manageTray.GetTray(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tt.mockResp.GetComponent().GetInfo().GetId().GetId(), result.GetComponent().GetInfo().GetId().GetId())
		})
	}
}

func TestManageTray_GetTrays(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.GetComponentsRequest
		mockResp    *flowv1.GetComponentsResponse
		mockErr     error
		wantErr     bool
		errContains string
	}{
		{
			name:    "successful request - nil request (gets all trays)",
			request: nil,
			mockResp: &flowv1.GetComponentsResponse{
				Components: []*flowv1.Component{},
				Total:      0,
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name:    "successful request - empty request",
			request: &flowv1.GetComponentsRequest{},
			mockResp: &flowv1.GetComponentsResponse{
				Components: []*flowv1.Component{},
				Total:      0,
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name:    "successful request - multiple trays",
			request: &flowv1.GetComponentsRequest{},
			mockResp: &flowv1.GetComponentsResponse{
				Components: []*flowv1.Component{
					{
						Type: flowv1.ComponentType_COMPONENT_TYPE_COMPUTE,
						Info: &flowv1.DeviceInfo{
							Id:   &flowv1.UUID{Id: "tray-1"},
							Name: "Compute Tray 1",
						},
						FirmwareVersion: "1.0.0",
						Position: &flowv1.RackPosition{
							SlotId: 1,
						},
					},
					{
						Type: flowv1.ComponentType_COMPONENT_TYPE_NVSWITCH,
						Info: &flowv1.DeviceInfo{
							Id:   &flowv1.UUID{Id: "tray-2"},
							Name: "Switch Tray 1",
						},
						Position: &flowv1.RackPosition{
							SlotId: 24,
						},
					},
					{
						Type: flowv1.ComponentType_COMPONENT_TYPE_POWERSHELF,
						Info: &flowv1.DeviceInfo{
							Id:   &flowv1.UUID{Id: "tray-3"},
							Name: "Power Shelf 1",
						},
						Position: &flowv1.RackPosition{
							SlotId: 48,
						},
					},
				},
				Total: 3,
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name: "successful request - with target spec filter",
			request: &flowv1.GetComponentsRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "rack-123"},
									},
									ComponentTypes: []flowv1.ComponentType{
										flowv1.ComponentType_COMPONENT_TYPE_COMPUTE,
									},
								},
							},
						},
					},
				},
			},
			mockResp: &flowv1.GetComponentsResponse{
				Components: []*flowv1.Component{
					{
						Type: flowv1.ComponentType_COMPONENT_TYPE_COMPUTE,
						Info: &flowv1.DeviceInfo{
							Id:   &flowv1.UUID{Id: "compute-tray-1"},
							Name: "Compute Tray",
						},
						RackId: &flowv1.UUID{Id: "rack-123"},
					},
				},
				Total: 1,
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name:        "Flow client error",
			request:     &flowv1.GetComponentsRequest{},
			mockResp:    nil,
			mockErr:     errors.New("internal server error"),
			wantErr:     true,
			errContains: "internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock Flow client
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()

			// Create atomic client and swap with mock
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)

			// Create ManageTray instance
			manageTray := NewManageTray(flowGrpcAtomicClient)

			// Execute activity with context injection
			ctx := context.Background()
			if tt.mockErr != nil {
				ctx = context.WithValue(ctx, "wantError", tt.mockErr)
			}
			if tt.mockResp != nil {
				ctx = context.WithValue(ctx, "wantResponse", tt.mockResp)
			}
			result, err := manageTray.GetTrays(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tt.mockResp.GetTotal(), result.GetTotal())
			assert.Equal(t, len(tt.mockResp.GetComponents()), len(result.GetComponents()))
		})
	}
}

func TestNewManageTray(t *testing.T) {
	// Create a mock Flow client
	flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})

	// Test constructor
	manageTray := NewManageTray(flowGrpcAtomicClient)

	assert.NotNil(t, manageTray.flowGrpcAtomicClient)
	assert.Equal(t, flowGrpcAtomicClient, manageTray.flowGrpcAtomicClient)
}
