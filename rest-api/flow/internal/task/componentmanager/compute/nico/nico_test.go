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
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/capability"
	nicoprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/nico"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

func TestDescriptor(t *testing.T) {
	d := Descriptor()

	assert.Equal(t, devicetypes.ComponentTypeCompute, d.Type)
	assert.Equal(t, ImplementationName, d.Implementation)
	assert.ElementsMatch(t, []string{nicoprovider.ProviderName}, d.RequiredProviders)
	assert.ElementsMatch(t,
		capability.CapabilitySet{
			capability.CapabilityBringUpControl,
			capability.CapabilityBringUpStatus,
			capability.CapabilityFirmwareControl,
			capability.CapabilityFirmwareStatus,
			capability.CapabilityInjectExpectation,
			capability.CapabilityPowerControl,
			capability.CapabilityPowerStatus,
		},
		d.Capabilities,
	)
}

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
				Info: mustMarshal(t, nicoapi.AddExpectedMachineRequest{
					BMCMACAddress:       "aa:bb:cc:dd:ee:ff",
					BMCUsername:         "admin",
					BMCPassword:         "password",
					ChassisSerialNumber: "SN12345",
				}),
			},
			expectError: false,
		},
		"invalid json returns error": {
			client: nicoapi.NewMockClient(),
			info: operations.InjectExpectationTaskInfo{
				Info: json.RawMessage(`{invalid`),
			},
			expectError: true,
			errContains: "failed to unmarshal",
		},
		"nil client returns error": {
			client: nil,
			info: operations.InjectExpectationTaskInfo{
				Info: mustMarshal(t, nicoapi.AddExpectedMachineRequest{
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
				Type:         devicetypes.ComponentTypeCompute,
				ComponentIDs: []string{"machine-1"},
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

func TestPowerControl_HappyPath(t *testing.T) {
	m := New(nicoapi.NewMockClient())

	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1", "machine-2"},
	}

	err := m.PowerControl(context.Background(), target, operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationPowerOn,
	})
	require.NoError(t, err)
}

func TestPowerControl_RejectsUnsupportedOperation(t *testing.T) {
	m := New(nicoapi.NewMockClient())
	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	err := m.PowerControl(context.Background(), target, operations.PowerControlTaskInfo{
		Operation: operations.PowerOperation(0xff),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported power operation")
}

func TestFirmwareControl_HappyPath(t *testing.T) {
	m := New(nicoapi.NewMockClient())

	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	err := m.FirmwareControl(context.Background(), target, operations.FirmwareControlTaskInfo{
		Operation:     operations.FirmwareOperationUpgrade,
		TargetVersion: "fw-bundle-id-v1",
		SubTargets:    []string{"bmc", "bios"},
	})
	require.NoError(t, err)
}

func TestFirmwareControl_RejectsUnknownSubTarget(t *testing.T) {
	m := New(nicoapi.NewMockClient())
	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	err := m.FirmwareControl(context.Background(), target, operations.FirmwareControlTaskInfo{
		Operation:  operations.FirmwareOperationUpgrade,
		SubTargets: []string{"made-up"},
	})
	require.Error(t, err)
}

func TestGetFirmwareStatus_HappyPath(t *testing.T) {
	m := New(nicoapi.NewMockClient())

	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	statuses, err := m.GetFirmwareStatus(context.Background(), target)
	require.NoError(t, err)
	require.NotNil(t, statuses)
	// Mock returns no statuses, so the requested machine still appears with
	// Unknown state.
	require.Contains(t, statuses, "machine-1")
	assert.Equal(t, operations.FirmwareUpdateStateUnknown, statuses["machine-1"].State)
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
				mkStatus("machine-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("machine-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
			},
			expectedState: operations.FirmwareUpdateStateCompleted,
		},
		"any failure marks overall failed": {
			statuses: []*pb.FirmwareUpdateStatus{
				mkStatus("machine-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("machine-1", pb.FirmwareUpdateState_FW_STATE_FAILED, "BIOS update failed"),
			},
			expectedState: operations.FirmwareUpdateStateFailed,
			expectedError: "BIOS update failed",
		},
		"still in progress": {
			statuses: []*pb.FirmwareUpdateStatus{
				mkStatus("machine-1", pb.FirmwareUpdateState_FW_STATE_COMPLETED, ""),
				mkStatus("machine-1", pb.FirmwareUpdateState_FW_STATE_IN_PROGRESS, ""),
			},
			expectedState: operations.FirmwareUpdateStateQueued,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := aggregateNICoStatuses("machine-1", tc.statuses)
			require.Equal(t, "machine-1", result.ComponentID)
			require.Equal(t, tc.expectedState, result.State)
			if tc.expectedError != "" {
				assert.Contains(t, result.Error, tc.expectedError)
			}
		})
	}
}

// newManagerForSafetyTest swaps the long default 30-minute assignment
// timeout for a tight one so the wait loop actually times out within the
// test budget.
func newManagerForSafetyTest(t *testing.T, client nicoapi.Client) *Manager {
	t.Helper()
	m := New(client)
	m.assignment = nicoprovider.NewAssignmentChecker(client, 50*time.Millisecond, 10*time.Millisecond)
	return m
}

func TestPowerControl_RefusesAssignedMachine(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "machine-1", State: "Assigned/Provisioning"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	err := m.PowerControl(context.Background(), target, operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationPowerOff,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused")
	assert.Contains(t, err.Error(), "Assigned state")
}

func TestPowerControl_AllowsUnassignedMachine(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "machine-1", State: "Ready"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	err := m.PowerControl(context.Background(), target, operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationPowerOn,
	})
	require.NoError(t, err)
}

func TestFirmwareControl_RefusesAssignedMachine(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "machine-1", State: "Assigned/Provisioning"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	err := m.FirmwareControl(context.Background(), target, operations.FirmwareControlTaskInfo{
		Operation:     operations.FirmwareOperationUpgrade,
		TargetVersion: "fw-v1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused")
	assert.Contains(t, err.Error(), "Assigned state")
}

// TestPowerControl_OverrideBypassesAssignmentCheck verifies that
// OverrideAssignmentCheck short-circuits the assignment-state gate on
// PowerControl. The host is in Assigned/* — which would otherwise block
// the call — yet the operation is expected to proceed past the gate.
func TestPowerControl_OverrideBypassesAssignmentCheck(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "machine-1", State: "Assigned/Provisioning"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	err := m.PowerControl(context.Background(), target, operations.PowerControlTaskInfo{
		Operation:               operations.PowerOperationPowerOn,
		OverrideAssignmentCheck: true,
	})
	require.NoError(t, err)
}

func TestBringUpControl_RefusesAssignedMachine(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "machine-1", State: "Assigned/Provisioning"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	err := m.BringUpControl(context.Background(), target, operations.BringUpTaskInfo{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused")
	assert.Contains(t, err.Error(), "Assigned state")
}

func TestBringUpControl_OverrideBypassesAssignmentCheck(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "machine-1", State: "Assigned/Provisioning"})

	m := newManagerForSafetyTest(t, client)
	target := common.Target{
		Type:         devicetypes.ComponentTypeCompute,
		ComponentIDs: []string{"machine-1"},
	}

	err := m.BringUpControl(context.Background(), target, operations.BringUpTaskInfo{
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
