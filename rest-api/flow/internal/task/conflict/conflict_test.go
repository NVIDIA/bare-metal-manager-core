// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package conflict

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/operation"
	taskcommon "github.com/NVIDIA/infra-controller-rest/flow/internal/task/common"
	taskdef "github.com/NVIDIA/infra-controller-rest/flow/internal/task/task"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

// makeTask builds a minimal Task for conflict tests.
// Component UUIDs, when provided, are stored under ComponentTypeCompute.
// Pass no UUIDs to get a task with nil ComponentsByType (old-task fallback).
func makeTask(
	rackID uuid.UUID,
	opType taskcommon.TaskType,
	opCode string,
	componentUUIDs ...uuid.UUID,
) *taskdef.Task {
	t := &taskdef.Task{
		ID:     uuid.New(),
		RackID: rackID,
		Operation: operation.Wrapper{
			Type: opType,
			Code: opCode,
		},
		Status: taskcommon.TaskStatusRunning,
	}
	if len(componentUUIDs) > 0 {
		t.Attributes = taskcommon.TaskAttributes{
			ComponentsByType: map[devicetypes.ComponentType][]uuid.UUID{
				devicetypes.ComponentTypeCompute: componentUUIDs,
			},
		}
	}
	return t
}

// makeTaskWithType builds a Task whose components are stored under the
// specified ComponentType. Use this for component-type-specific tests.
func makeTaskWithType(
	rackID uuid.UUID,
	opType taskcommon.TaskType,
	opCode string,
	ct devicetypes.ComponentType,
	componentUUIDs ...uuid.UUID,
) *taskdef.Task {
	return &taskdef.Task{
		ID:     uuid.New(),
		RackID: rackID,
		Operation: operation.Wrapper{
			Type: opType,
			Code: opCode,
		},
		Status: taskcommon.TaskStatusRunning,
		Attributes: taskcommon.TaskAttributes{
			ComponentsByType: map[devicetypes.ComponentType][]uuid.UUID{
				ct: componentUUIDs,
			},
		},
	}
}

func TestOperationSpec_Matches(t *testing.T) {
	tests := []struct {
		name     string
		spec     OperationSpec
		target   OperationSpec
		expected bool
	}{
		{
			name:     "exact match",
			spec:     OperationSpec{OperationType: "power_control", OperationCode: "power_on"},
			target:   OperationSpec{OperationType: "power_control", OperationCode: "power_on"},
			expected: true,
		},
		{
			name:     "wildcard type matches any type",
			spec:     OperationSpec{OperationType: "*", OperationCode: "power_on"},
			target:   OperationSpec{OperationType: "anything", OperationCode: "power_on"},
			expected: true,
		},
		{
			name:     "wildcard code matches any code",
			spec:     OperationSpec{OperationType: "power_control", OperationCode: "*"},
			target:   OperationSpec{OperationType: "power_control", OperationCode: "power_off"},
			expected: true,
		},
		{
			name:     "both wildcards match anything",
			spec:     OperationSpec{OperationType: "*", OperationCode: "*"},
			target:   OperationSpec{OperationType: "anything", OperationCode: "anything"},
			expected: true,
		},
		{
			name:     "type mismatch",
			spec:     OperationSpec{OperationType: "power_control", OperationCode: "power_on"},
			target:   OperationSpec{OperationType: "firmware_control", OperationCode: "power_on"},
			expected: false,
		},
		{
			name:     "code mismatch",
			spec:     OperationSpec{OperationType: "power_control", OperationCode: "power_on"},
			target:   OperationSpec{OperationType: "power_control", OperationCode: "power_off"},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.spec.Matches(tc.target))
		})
	}
}

func TestComponentUUIDsOverlap(t *testing.T) {
	rackID := uuid.New()
	shared := uuid.New()

	tests := []struct {
		name     string
		a        *taskdef.Task
		b        *taskdef.Task
		expected bool
	}{
		{
			name: "shared component UUID overlaps",
			a: makeTask(rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				shared, uuid.New()),
			b: makeTask(rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				uuid.New(), shared),
			expected: true,
		},
		{
			name: "no shared component UUIDs do not overlap",
			a: makeTask(rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				uuid.New()),
			b: makeTask(rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				uuid.New()),
			expected: false,
		},
		{
			name:     "empty component UUIDs do not overlap",
			a:        makeTask(rackID, taskcommon.TaskTypePowerControl, "power_on"),
			b:        makeTask(rackID, taskcommon.TaskTypePowerControl, "power_on"),
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(
				t, tc.expected,
				componentUUIDsOverlap(tc.a, tc.b),
			)
		})
	}
}

func TestRule_Conflicts_ExclusiveMode(t *testing.T) {
	// Exclusive mode: any active task is a conflict regardless of type.
	// Rack pre-filtering is done by the store, not by the rule.
	rule := &Rule{}
	rackID := uuid.New()
	incoming := makeTask(rackID, taskcommon.TaskTypePowerControl, "power_on")

	tests := []struct {
		name        string
		activeTasks []*taskdef.Task
		expected    bool
	}{
		{
			name:        "nil active tasks — no conflict",
			activeTasks: nil,
			expected:    false,
		},
		{
			name:        "empty active tasks — no conflict",
			activeTasks: []*taskdef.Task{},
			expected:    false,
		},
		{
			name: "one active task — conflict",
			activeTasks: []*taskdef.Task{
				makeTask(rackID, taskcommon.TaskTypeFirmwareControl, "upgrade"),
			},
			expected: true,
		},
		{
			name: "multiple active tasks — conflict",
			activeTasks: []*taskdef.Task{
				makeTask(rackID, taskcommon.TaskTypePowerControl, "power_off"),
				makeTask(rackID, taskcommon.TaskTypeFirmwareControl, "upgrade"),
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, rule.Conflicts(incoming, tc.activeTasks))
		})
	}
}

func TestRule_Conflicts_PairMode(t *testing.T) {
	rackID := uuid.New()
	rule := &Rule{
		ConflictingPairs: []Entry{
			{
				A: OperationSpec{OperationType: "power_control", OperationCode: "*"},
				B: OperationSpec{OperationType: "firmware_control", OperationCode: "*"},
			},
			{
				A: OperationSpec{OperationType: "bring_up", OperationCode: "*"},
				B: OperationSpec{OperationType: "bring_up", OperationCode: "*"},
			},
		},
	}

	tests := []struct {
		name        string
		incoming    *taskdef.Task
		activeTasks []*taskdef.Task
		expected    bool
	}{
		{
			name: "no active tasks",
			incoming: makeTask(
				rackID, taskcommon.TaskTypePowerControl, "power_on",
			),
			activeTasks: []*taskdef.Task{},
			expected:    false,
		},
		{
			name: "active task matches a pair",
			incoming: makeTask(
				rackID, taskcommon.TaskTypePowerControl, "power_on",
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID, taskcommon.TaskTypeFirmwareControl, "upgrade"),
			},
			expected: true,
		},
		{
			name: "active task does not match any pair",
			incoming: makeTask(
				rackID, taskcommon.TaskTypePowerControl, "power_on",
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID, taskcommon.TaskTypePowerControl, "power_off"),
			},
			expected: false,
		},
		{
			name: "active task matches second pair",
			incoming: makeTask(
				rackID, taskcommon.TaskTypeBringUp, "full",
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID, taskcommon.TaskTypeBringUp, "full"),
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, rule.Conflicts(tc.incoming, tc.activeTasks))
		})
	}
}

func TestBuiltinRule(t *testing.T) {
	rackID := uuid.New()
	sharedComp := uuid.New()

	tests := []struct {
		name        string
		incoming    *taskdef.Task
		activeTasks []*taskdef.Task
		expected    bool
	}{
		{
			name: "no active tasks — no conflict",
			incoming: makeTask(
				rackID, taskcommon.TaskTypePowerControl, "power_on",
			),
			activeTasks: nil,
			expected:    false,
		},
		{
			// PowerShelf power blocks all power ops at rack scope.
			name: "power blocks power",
			incoming: makeTaskWithType(
				rackID, taskcommon.TaskTypePowerControl, "power_on",
				devicetypes.ComponentTypePowerShelf, uuid.New(),
			),
			activeTasks: []*taskdef.Task{
				makeTaskWithType(rackID,
					taskcommon.TaskTypePowerControl, "power_off",
					devicetypes.ComponentTypePowerShelf, uuid.New()),
			},
			expected: true,
		},
		{
			// PowerShelf power blocks all firmware ops at rack scope.
			name: "power blocks firmware",
			incoming: makeTaskWithType(
				rackID, taskcommon.TaskTypePowerControl, "power_on",
				devicetypes.ComponentTypePowerShelf, uuid.New(),
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID,
					taskcommon.TaskTypeFirmwareControl, "upgrade"),
			},
			expected: true,
		},
		{
			// Symmetric: active PowerShelf power blocks incoming firmware.
			name: "firmware blocks power (symmetric)",
			incoming: makeTask(
				rackID, taskcommon.TaskTypeFirmwareControl, "upgrade",
			),
			activeTasks: []*taskdef.Task{
				makeTaskWithType(rackID,
					taskcommon.TaskTypePowerControl, "power_on",
					devicetypes.ComponentTypePowerShelf, uuid.New()),
			},
			expected: true,
		},
		{
			name: "firmware blocks firmware (overlapping components)",
			incoming: makeTask(
				rackID, taskcommon.TaskTypeFirmwareControl, "upgrade",
				sharedComp,
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID,
					taskcommon.TaskTypeFirmwareControl, "upgrade",
					sharedComp),
			},
			expected: true,
		},
		{
			// Firmware upgrades on disjoint component sets are safe to
			// run in parallel: no component UUID overlap.
			name: "firmware does not block firmware (different components)",
			incoming: makeTask(
				rackID, taskcommon.TaskTypeFirmwareControl, "upgrade",
				uuid.New(),
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID,
					taskcommon.TaskTypeFirmwareControl, "upgrade",
					uuid.New()),
			},
			expected: false,
		},
		{
			name: "bring_up blocks power",
			incoming: makeTask(
				rackID, taskcommon.TaskTypeBringUp, "full",
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID,
					taskcommon.TaskTypePowerControl, "power_on"),
			},
			expected: true,
		},
		{
			name: "power blocks bring_up (symmetric)",
			incoming: makeTask(
				rackID, taskcommon.TaskTypePowerControl, "power_on",
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID,
					taskcommon.TaskTypeBringUp, "full"),
			},
			expected: true,
		},
		{
			name: "inject_expectation does not conflict with power",
			incoming: makeTask(
				rackID, taskcommon.TaskTypeInjectExpectation, "inject",
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID,
					taskcommon.TaskTypePowerControl, "power_on"),
			},
			expected: false,
		},
		{
			name: "inject_expectation does not conflict with firmware",
			incoming: makeTask(
				rackID, taskcommon.TaskTypeInjectExpectation, "inject",
			),
			activeTasks: []*taskdef.Task{
				makeTask(rackID,
					taskcommon.TaskTypeFirmwareControl, "upgrade"),
			},
			expected: false,
		},
		// --- Component-type-specific entries ---
		{
			// PowerShelf power cuts rack power → blocks any power op
			// at rack scope regardless of component type.
			name: "powershelf power blocks compute power (rack scope)",
			incoming: makeTaskWithType(
				rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				devicetypes.ComponentTypeCompute, uuid.New(),
			),
			activeTasks: []*taskdef.Task{
				makeTaskWithType(rackID,
					taskcommon.TaskTypePowerControl, "power_off",
					devicetypes.ComponentTypePowerShelf, uuid.New()),
			},
			expected: true,
		},
		{
			// PowerShelf power blocks firmware at rack scope:
			// unsafe to flash any component while shelf power is in flux.
			name: "powershelf power blocks compute firmware (rack scope)",
			incoming: makeTaskWithType(
				rackID,
				taskcommon.TaskTypeFirmwareControl, "upgrade",
				devicetypes.ComponentTypeCompute, uuid.New(),
			),
			activeTasks: []*taskdef.Task{
				makeTaskWithType(rackID,
					taskcommon.TaskTypePowerControl, "power_off",
					devicetypes.ComponentTypePowerShelf, uuid.New()),
			},
			expected: true,
		},
		{
			// Compute power ops block each other only when they target
			// overlapping component UUIDs.
			name: "compute power blocks compute power (shared component)",
			incoming: makeTaskWithType(
				rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				devicetypes.ComponentTypeCompute, sharedComp,
			),
			activeTasks: []*taskdef.Task{
				makeTaskWithType(rackID,
					taskcommon.TaskTypePowerControl, "power_off",
					devicetypes.ComponentTypeCompute, sharedComp),
			},
			expected: true,
		},
		{
			// Compute power on disjoint components is safe in parallel.
			name: "compute power safe with compute power (no overlap)",
			incoming: makeTaskWithType(
				rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				devicetypes.ComponentTypeCompute, uuid.New(),
			),
			activeTasks: []*taskdef.Task{
				makeTaskWithType(rackID,
					taskcommon.TaskTypePowerControl, "power_on",
					devicetypes.ComponentTypeCompute, uuid.New()),
			},
			expected: false,
		},
		{
			// Compute and NVSwitch power ops are isolated — no entry
			// covers cross-type conflicts at component scope.
			name: "compute power safe with nvswitch power",
			incoming: makeTaskWithType(
				rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				devicetypes.ComponentTypeCompute, uuid.New(),
			),
			activeTasks: []*taskdef.Task{
				makeTaskWithType(rackID,
					taskcommon.TaskTypePowerControl, "power_on",
					devicetypes.ComponentTypeNVSwitch, uuid.New()),
			},
			expected: false,
		},
		{
			// Compute power blocks firmware on overlapping compute
			// components.
			name: "compute power blocks compute firmware (shared comp)",
			incoming: makeTaskWithType(
				rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				devicetypes.ComponentTypeCompute, sharedComp,
			),
			activeTasks: []*taskdef.Task{
				makeTaskWithType(rackID,
					taskcommon.TaskTypeFirmwareControl, "upgrade",
					devicetypes.ComponentTypeCompute, sharedComp),
			},
			expected: true,
		},
		{
			// Compute power on disjoint component set does not block
			// firmware on non-overlapping compute components.
			name: "compute power safe with compute firmware (no overlap)",
			incoming: makeTaskWithType(
				rackID,
				taskcommon.TaskTypePowerControl, "power_on",
				devicetypes.ComponentTypeCompute, uuid.New(),
			),
			activeTasks: []*taskdef.Task{
				makeTaskWithType(rackID,
					taskcommon.TaskTypeFirmwareControl, "upgrade",
					devicetypes.ComponentTypeCompute, uuid.New()),
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(
				t, tc.expected,
				builtinRule.Conflicts(
					tc.incoming, tc.activeTasks,
				),
			)
		})
	}
}

func TestResolver_HasConflict(t *testing.T) {
	rackA := uuid.New()
	rackB := uuid.New()

	tests := []struct {
		name          string
		setupStore    func(*mockStore)
		incoming      *taskdef.Task
		expectedValue bool
		expectedErr   bool
	}{
		{
			name:       "no active tasks on rack",
			setupStore: func(_ *mockStore) {},
			incoming: makeTask(
				rackA, taskcommon.TaskTypePowerControl, "power_on",
			),
			expectedValue: false,
		},
		{
			name: "conflicting active task on rack",
			setupStore: func(s *mockStore) {
				s.activeTasks[rackA] = []*taskdef.Task{
					makeTaskWithType(rackA,
						taskcommon.TaskTypePowerControl,
						"power_off",
						devicetypes.ComponentTypePowerShelf,
						uuid.New()),
				}
			},
			incoming: makeTaskWithType(
				rackA, taskcommon.TaskTypePowerControl, "power_on",
				devicetypes.ComponentTypePowerShelf, uuid.New(),
			),
			expectedValue: true,
		},
		{
			name: "non-conflicting active task on rack",
			setupStore: func(s *mockStore) {
				s.activeTasks[rackA] = []*taskdef.Task{
					makeTask(rackA,
						taskcommon.TaskTypeInjectExpectation,
						"inject"),
				}
			},
			incoming: makeTask(
				rackA, taskcommon.TaskTypeInjectExpectation, "inject",
			),
			expectedValue: false,
		},
		{
			name: "active task on different rack — no conflict",
			setupStore: func(s *mockStore) {
				s.activeTasks[rackA] = []*taskdef.Task{
					makeTask(rackA,
						taskcommon.TaskTypePowerControl,
						"power_on"),
				}
			},
			incoming: makeTask(
				rackB, taskcommon.TaskTypePowerControl, "power_on",
			),
			expectedValue: false,
		},
		{
			name: "store error is propagated",
			setupStore: func(s *mockStore) {
				s.listActiveErr = errors.New("db connection lost")
			},
			incoming: makeTask(
				rackA, taskcommon.TaskTypePowerControl, "power_on",
			),
			expectedErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newMockStore()
			tc.setupStore(store)
			resolver := NewResolver(store)

			hasConflict, err := resolver.HasConflict(
				context.Background(),
				tc.incoming,
			)

			if tc.expectedErr {
				require.Error(t, err)
				assert.False(t, hasConflict)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedValue, hasConflict)
			}
		})
	}
}
