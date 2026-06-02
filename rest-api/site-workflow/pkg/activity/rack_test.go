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

func TestManageRack_GetRack(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.GetRackInfoByIDRequest
		mockResp    *flowv1.GetRackInfoResponse
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
			errContains: "empty get rack request",
		},
		{
			name: "request with nil ID returns error",
			request: &flowv1.GetRackInfoByIDRequest{
				Id: nil,
			},
			mockResp:    nil,
			mockErr:     nil,
			wantErr:     true,
			errContains: "without rack ID",
		},
		{
			name: "request with empty ID returns error",
			request: &flowv1.GetRackInfoByIDRequest{
				Id: &flowv1.UUID{Id: ""},
			},
			mockResp:    nil,
			mockErr:     nil,
			wantErr:     true,
			errContains: "without rack ID",
		},
		{
			name: "successful request",
			request: &flowv1.GetRackInfoByIDRequest{
				Id:             &flowv1.UUID{Id: "test-rack-id"},
				WithComponents: true,
			},
			mockResp: &flowv1.GetRackInfoResponse{
				Rack: &flowv1.Rack{
					Info: &flowv1.DeviceInfo{
						Id:   &flowv1.UUID{Id: "test-rack-id"},
						Name: "Test Rack",
					},
				},
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name: "Flow client error",
			request: &flowv1.GetRackInfoByIDRequest{
				Id: &flowv1.UUID{Id: "test-rack-id"},
			},
			mockResp:    nil,
			mockErr:     errors.New("connection refused"),
			wantErr:     true,
			errContains: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock Flow gRPC client
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()

			// Create atomic client and swap with mock
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)

			// Create ManageRack instance
			manageRack := NewManageRack(flowGrpcAtomicClient)

			// Execute activity with context injection
			ctx := context.Background()
			if tt.mockErr != nil {
				ctx = context.WithValue(ctx, "wantError", tt.mockErr)
			}
			if tt.mockResp != nil {
				ctx = context.WithValue(ctx, "wantResponse", tt.mockResp)
			}
			result, err := manageRack.GetRack(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			if tt.request != nil && tt.request.GetId() != nil {
				assert.Equal(t, tt.request.GetId().GetId(), result.GetRack().GetInfo().GetId().GetId())
			}
		})
	}
}

func TestManageRack_GetRacks(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.GetListOfRacksRequest
		mockResp    *flowv1.GetListOfRacksResponse
		mockErr     error
		wantErr     bool
		errContains string
	}{
		{
			name:    "successful request - empty list",
			request: &flowv1.GetListOfRacksRequest{},
			mockResp: &flowv1.GetListOfRacksResponse{
				Racks: []*flowv1.Rack{},
				Total: 0,
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name: "successful request - multiple racks",
			request: &flowv1.GetListOfRacksRequest{
				WithComponents: true,
			},
			mockResp: &flowv1.GetListOfRacksResponse{
				Racks: []*flowv1.Rack{
					{
						Info: &flowv1.DeviceInfo{
							Id:   &flowv1.UUID{Id: "rack-1"},
							Name: "Rack 1",
						},
					},
					{
						Info: &flowv1.DeviceInfo{
							Id:   &flowv1.UUID{Id: "rack-2"},
							Name: "Rack 2",
						},
					},
				},
				Total: 2,
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name:        "Flow client error",
			request:     &flowv1.GetListOfRacksRequest{},
			mockResp:    nil,
			mockErr:     errors.New("internal server error"),
			wantErr:     true,
			errContains: "internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock Flow gRPC client
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()

			// Create atomic client and swap with mock
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)

			// Create ManageRack instance
			manageRack := NewManageRack(flowGrpcAtomicClient)

			// Execute activity with context injection
			ctx := context.Background()
			if tt.mockErr != nil {
				ctx = context.WithValue(ctx, "wantError", tt.mockErr)
			}
			if tt.mockResp != nil {
				ctx = context.WithValue(ctx, "wantResponse", tt.mockResp)
			}
			result, err := manageRack.GetRacks(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			if tt.mockResp != nil {
				assert.Equal(t, tt.mockResp.GetTotal(), result.GetTotal())
				assert.Equal(t, len(tt.mockResp.GetRacks()), len(result.GetRacks()))
			} else {
				// Mock returns empty list by default
				assert.Equal(t, int32(0), result.GetTotal())
				assert.Equal(t, 0, len(result.GetRacks()))
			}
		})
	}
}

func TestManageRack_ValidateRackComponents(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.ValidateComponentsRequest
		mockResp    *flowv1.ValidateComponentsResponse
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
			errContains: "empty validate rack components request",
		},
		{
			name: "successful request - no diffs",
			request: &flowv1.ValidateComponentsRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
			},
			mockResp: &flowv1.ValidateComponentsResponse{
				Diffs:           []*flowv1.ComponentDiff{},
				TotalDiffs:      0,
				MissingCount:    0,
				UnexpectedCount: 0,
				MismatchCount:   0,
				MatchCount:      5,
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name: "successful request - with diffs",
			request: &flowv1.ValidateComponentsRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
			},
			mockResp: &flowv1.ValidateComponentsResponse{
				Diffs: []*flowv1.ComponentDiff{
					{
						Type:        flowv1.DiffType_DIFF_TYPE_MISSING,
						ComponentId: "comp-1",
					},
				},
				TotalDiffs:      1,
				MissingCount:    1,
				UnexpectedCount: 0,
				MismatchCount:   0,
				MatchCount:      4,
			},
			mockErr: nil,
			wantErr: false,
		},
		{
			name: "Flow client error",
			request: &flowv1.ValidateComponentsRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
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

			// Create ManageRack instance
			manageRack := NewManageRack(flowGrpcAtomicClient)

			// Execute activity with context injection
			ctx := context.Background()
			if tt.mockErr != nil {
				ctx = context.WithValue(ctx, "wantError", tt.mockErr)
			}
			if tt.mockResp != nil {
				ctx = context.WithValue(ctx, "wantResponse", tt.mockResp)
			}
			result, err := manageRack.ValidateRackComponents(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			if tt.mockResp != nil {
				assert.Equal(t, tt.mockResp.GetTotalDiffs(), result.GetTotalDiffs())
				assert.Equal(t, tt.mockResp.GetMatchCount(), result.GetMatchCount())
				assert.Equal(t, len(tt.mockResp.GetDiffs()), len(result.GetDiffs()))
			}
		})
	}
}

func TestManageRack_PowerOnRack(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.PowerOnRackRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty power on rack request",
		},
		{
			name: "successful request",
			request: &flowv1.PowerOnRackRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
				Description: "API power on Rack",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
			manageRack := NewManageRack(flowGrpcAtomicClient)

			ctx := context.Background()
			result, err := manageRack.PowerOnRack(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.GetTaskIds())
		})
	}
}

func TestManageRack_PowerOffRack(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.PowerOffRackRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty power off rack request",
		},
		{
			name: "successful request",
			request: &flowv1.PowerOffRackRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
				Description: "API power off Rack",
			},
			wantErr: false,
		},
		{
			name: "successful forced request",
			request: &flowv1.PowerOffRackRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
				Forced:      true,
				Description: "API force power off Rack",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
			manageRack := NewManageRack(flowGrpcAtomicClient)

			ctx := context.Background()
			result, err := manageRack.PowerOffRack(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.GetTaskIds())
		})
	}
}

func TestManageRack_PowerResetRack(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.PowerResetRackRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty power reset rack request",
		},
		{
			name: "successful request",
			request: &flowv1.PowerResetRackRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
				Description: "API power cycle Rack",
			},
			wantErr: false,
		},
		{
			name: "successful forced request",
			request: &flowv1.PowerResetRackRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
				Forced:      true,
				Description: "API force power cycle Rack",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
			manageRack := NewManageRack(flowGrpcAtomicClient)

			ctx := context.Background()
			result, err := manageRack.PowerResetRack(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.GetTaskIds())
		})
	}
}

func TestManageRack_BringUpRack(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.BringUpRackRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty bring up rack request",
		},
		{
			name: "successful request",
			request: &flowv1.BringUpRackRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
				Description: "API bring up Rack",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
			manageRack := NewManageRack(flowGrpcAtomicClient)

			ctx := context.Background()
			result, err := manageRack.BringUpRack(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.GetTaskIds())
		})
	}
}

func TestManageRack_UpgradeFirmware(t *testing.T) {
	tests := []struct {
		name        string
		request     *flowv1.UpgradeFirmwareRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request returns error",
			request:     nil,
			wantErr:     true,
			errContains: "empty upgrade firmware request",
		},
		{
			name: "successful request without version",
			request: &flowv1.UpgradeFirmwareRequest{
				TargetSpec: &flowv1.OperationTargetSpec{
					Targets: &flowv1.OperationTargetSpec_Racks{
						Racks: &flowv1.RackTargets{
							Targets: []*flowv1.RackTarget{
								{
									Identifier: &flowv1.RackTarget_Id{
										Id: &flowv1.UUID{Id: "test-rack-id"},
									},
								},
							},
						},
					},
				},
				Description: "API firmware upgrade Rack",
			},
			wantErr: false,
		},
		{
			name: "successful request with version",
			request: func() *flowv1.UpgradeFirmwareRequest {
				version := "24.11.0"
				return &flowv1.UpgradeFirmwareRequest{
					TargetSpec: &flowv1.OperationTargetSpec{
						Targets: &flowv1.OperationTargetSpec_Racks{
							Racks: &flowv1.RackTargets{
								Targets: []*flowv1.RackTarget{
									{
										Identifier: &flowv1.RackTarget_Id{
											Id: &flowv1.UUID{Id: "test-rack-id"},
										},
									},
								},
							},
						},
					},
					TargetVersion: &version,
					Description:   "API firmware upgrade Rack",
				}
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlowGrpcClient := cClient.NewMockFlowGrpcClient()
			flowGrpcAtomicClient := cClient.NewFlowGrpcAtomicClient(&cClient.FlowGrpcClientConfig{})
			flowGrpcAtomicClient.SwapClient(mockFlowGrpcClient)
			manageRack := NewManageRack(flowGrpcAtomicClient)

			ctx := context.Background()
			result, err := manageRack.UpgradeFirmware(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.GetTaskIds())
		})
	}
}
