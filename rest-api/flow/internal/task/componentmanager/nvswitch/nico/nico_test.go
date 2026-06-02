// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nico

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
	nicoprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/nico"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

func TestInjectExpectation(t *testing.T) {
	testCases := map[string]struct {
		client      nicoapi.Client
		info        operations.InjectExpectationTaskInfo
		expectError bool
		errContains string
	}{
		"success": {
			client: nicoapi.NewMockClient(),
			info: operations.InjectExpectationTaskInfo{
				Info: mustMarshal(t, nicoapi.AddExpectedSwitchRequest{
					BMCMACAddress:      "aa:bb:cc:dd:ee:ff",
					BMCUsername:        "admin",
					BMCPassword:        "password",
					SwitchSerialNumber: "SW-SN-001",
				}),
			},
			expectError: false,
		},
		"invalid json returns error": {
			client: nicoapi.NewMockClient(),
			info: operations.InjectExpectationTaskInfo{
				Info: json.RawMessage(`{bad-json`),
			},
			expectError: true,
			errContains: "failed to unmarshal",
		},
		"nil client returns error": {
			client: nil,
			info: operations.InjectExpectationTaskInfo{
				Info: mustMarshal(t, nicoapi.AddExpectedSwitchRequest{
					BMCMACAddress: "aa:bb:cc:dd:ee:ff",
				}),
			},
			expectError: true,
			errContains: "nico client is not configured",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			m := New(tc.client)

			target := common.Target{
				Type:         devicetypes.ComponentTypeNVSwitch,
				ComponentIDs: []string{"switch-1"},
			}

			err := m.InjectExpectation(context.Background(), target, tc.info)
			if tc.expectError {
				assert.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPowerControl(t *testing.T) {
	m := New(nicoapi.NewMockClient())

	target := common.Target{
		Type:         devicetypes.ComponentTypeNVSwitch,
		ComponentIDs: []string{"switch-1", "switch-2"},
	}

	err := m.PowerControl(context.Background(), target, operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationPowerOn,
	})
	assert.NoError(t, err)
}

func TestFirmwareControl(t *testing.T) {
	m := New(nicoapi.NewMockClient())

	target := common.Target{
		Type:         devicetypes.ComponentTypeNVSwitch,
		ComponentIDs: []string{"switch-1"},
	}

	err := m.FirmwareControl(context.Background(), target, operations.FirmwareControlTaskInfo{
		TargetVersion: "2.0.0",
	})
	assert.NoError(t, err)
}

func TestGetFirmwareStatus(t *testing.T) {
	m := New(nicoapi.NewMockClient())

	target := common.Target{
		Type:         devicetypes.ComponentTypeNVSwitch,
		ComponentIDs: []string{"switch-1"},
	}

	statuses, err := m.GetFirmwareStatus(context.Background(), target)
	assert.NoError(t, err)
	assert.NotNil(t, statuses)
}

func TestAggregateNICoStatuses(t *testing.T) {
	mkStatus := func(compID string, state pb.FirmwareUpdateState, errMsg string) *pb.FirmwareUpdateStatus {
		return &pb.FirmwareUpdateStatus{
			Result: &pb.ComponentResult{
				ComponentId: compID,
				Error:       errMsg,
			},
			State: state,
		}
	}

	tests := map[string]struct {
		statuses      []*pb.FirmwareUpdateStatus
		expectedState operations.FirmwareUpdateState
		expectedError string
	}{
		"empty returns unknown": {
			statuses:      nil,
			expectedState: operations.FirmwareUpdateStateUnknown,
		},
		"all completed": {
			statuses: []*pb.FirmwareUpdateStatus{
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
			},
			expectedState: operations.FirmwareUpdateStateCompleted,
		},
		"any failure marks overall failed": {
			statuses: []*pb.FirmwareUpdateStatus{
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_FAILED, "BMC update failed"),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
			},
			expectedState: operations.FirmwareUpdateStateFailed,
			expectedError: "BMC update failed",
		},
		"last completed but earlier failed still reports failed": {
			statuses: []*pb.FirmwareUpdateStatus{
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_FAILED, "CPLD flash error"),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
			},
			expectedState: operations.FirmwareUpdateStateFailed,
			expectedError: "CPLD flash error",
		},
		"cancelled treated as failed": {
			statuses: []*pb.FirmwareUpdateStatus{
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_CANCELLED, ""),
			},
			expectedState: operations.FirmwareUpdateStateFailed,
		},
		"still in progress": {
			statuses: []*pb.FirmwareUpdateStatus{
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_IN_PROGRESS, ""),
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_QUEUED, ""),
			},
			expectedState: operations.FirmwareUpdateStateQueued,
		},
		"single completed": {
			statuses: []*pb.FirmwareUpdateStatus{
				mkStatus("sw-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
			},
			expectedState: operations.FirmwareUpdateStateCompleted,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := aggregateNICoStatuses("sw-1", tc.statuses)
			require.Equal(t, "sw-1", result.ComponentID)
			require.Equal(t, tc.expectedState, result.State, "expected state %v, got %v", tc.expectedState, result.State)
			if tc.expectedError != "" {
				assert.Contains(t, result.Error, tc.expectedError)
			}
		})
	}
}

// newManagerForSafetyTest swaps the long default 30-minute assignment
// timeout for a tight one so the wait loop actually times out within the
// test budget. Tests in this file use the same package, so they can reach
// the unexported assignment field directly.
func newManagerForSafetyTest(t *testing.T, client nicoapi.Client) *Manager {
	t.Helper()
	m := New(client)
	m.assignment = nicoprovider.NewAssignmentChecker(client, 50*time.Millisecond, 10*time.Millisecond)
	return m
}

func TestPowerControl_RefusesWhenRackHostAssigned(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.SetSwitchRackID("sw-1", "rack-A")
	client.SetRackHostMachineIDs("rack-A", []string{"host-1"})
	client.AddMachine(nicoapi.MachineDetail{MachineID: "host-1", State: "Assigned/Provisioning"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeNVSwitch,
		ComponentIDs: []string{"sw-1"},
	}

	err := m.PowerControl(context.Background(), target, operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationPowerOff,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused")
	assert.Contains(t, err.Error(), "Assigned state")
	assert.Contains(t, err.Error(), "host-1")
}

func TestPowerControl_AllowsWhenRackHostsReady(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.SetSwitchRackID("sw-1", "rack-A")
	client.SetRackHostMachineIDs("rack-A", []string{"host-1"})
	client.AddMachine(nicoapi.MachineDetail{MachineID: "host-1", State: "Ready"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeNVSwitch,
		ComponentIDs: []string{"sw-1"},
	}

	err := m.PowerControl(context.Background(), target, operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationPowerOn,
	})
	require.NoError(t, err)
}

func TestFirmwareControl_RefusesWhenRackHostAssigned(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.SetSwitchRackID("sw-1", "rack-A")
	client.SetRackHostMachineIDs("rack-A", []string{"host-1"})
	client.AddMachine(nicoapi.MachineDetail{MachineID: "host-1", State: "Assigned/Provisioning"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeNVSwitch,
		ComponentIDs: []string{"sw-1"},
	}

	err := m.FirmwareControl(context.Background(), target, operations.FirmwareControlTaskInfo{
		Operation:     operations.FirmwareOperationUpgrade,
		TargetVersion: "1.0.0",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused")
	assert.Contains(t, err.Error(), "Assigned state")
}

// TestPowerControl_OverrideBypassesRackAssignmentCheck verifies that
// OverrideAssignmentCheck short-circuits the rack-scoped gate on
// NVSwitch PowerControl. The host on the resolved rack is in
// Assigned/* — which would otherwise block the call — yet the
// operation is expected to proceed past the gate. The switch is left
// without an explicit rack mapping to confirm the override path skips
// the rack lookup entirely.
func TestPowerControl_OverrideBypassesRackAssignmentCheck(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.SetSwitchRackID("sw-1", "rack-A")
	client.SetRackHostMachineIDs("rack-A", []string{"host-1"})
	client.AddMachine(nicoapi.MachineDetail{MachineID: "host-1", State: "Assigned/Provisioning"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeNVSwitch,
		ComponentIDs: []string{"sw-1"},
	}

	err := m.PowerControl(context.Background(), target, operations.PowerControlTaskInfo{
		Operation:               operations.PowerOperationPowerOn,
		OverrideAssignmentCheck: true,
	})
	require.NoError(t, err)
}

func mustMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	return data
}
