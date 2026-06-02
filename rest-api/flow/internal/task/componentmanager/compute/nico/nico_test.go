// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nico

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
	cmconfig "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/config"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

func TestConfigDecoderDecodeYAML(t *testing.T) {
	decoder := ConfigDecoder{}

	decoded, err := decoder.DecodeYAML(yaml.Node{})
	require.NoError(t, err)
	config := decoded.(*Config)
	assert.Equal(t, DefaultComputePowerDelay, config.ComputePowerDelay)

	decoded, err = decoder.DecodeYAML(managerYAMLNode(t, `compute_power_delay: 0s`))
	require.NoError(t, err)
	config = decoded.(*Config)
	assert.Equal(t, 0*time.Second, config.ComputePowerDelay)

	_, err = decoder.DecodeYAML(managerYAMLNode(t, `compute_power_delay: nope`))
	require.Error(t, err)
	assert.True(t, errors.Is(err, cmconfig.ErrInvalidManagerConfigField))
	assertInvalidManagerConfigField(t, err, "compute_power_delay")

	_, err = decoder.DecodeYAML(managerYAMLNode(t, `compute_power_dely: 15s`))
	require.Error(t, err)
	assert.True(t, errors.Is(err, cmconfig.ErrInvalidManagerConfig))
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
			m := New(tc.client, 0)

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

func mustMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	return data
}

func assertInvalidManagerConfigField(t *testing.T, err error, field string) {
	t.Helper()

	var fieldErr cmconfig.InvalidManagerConfigFieldError
	require.True(t, errors.As(err, &fieldErr))
	assert.Equal(t, ConfigDecoder{}.Identity(), fieldErr.Identity)
	assert.Equal(t, field, fieldErr.Field)
}

func managerYAMLNode(t *testing.T, data string) yaml.Node {
	t.Helper()

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(data), &node))
	require.NotEmpty(t, node.Content)
	return *node.Content[0]
}

// TestFirmwareControl_SubTargetsAccepted verifies that the compute/nico
// FirmwareControl path tolerates info.SubTargets without erroring. This
// path goes through SetMachineAutoUpdate + SetFirmwareUpdateTimeWindow,
// which has no per-sub-target selection in NICo, so the manager only logs
// a warning and proceeds; we exercise that branch here. The actual
// per-sub-target dispatch will be added when compute moves to NICo's
// UpdateComponentFirmware (see comment in nico.go).
func TestFirmwareControl_SubTargetsAccepted(t *testing.T) {
	tests := map[string]struct {
		subTargets []string
	}{
		"nil sub_targets (legacy path)":     {subTargets: nil},
		"empty sub_targets (legacy path)":   {subTargets: []string{}},
		"non-empty sub_targets (warn path)": {subTargets: []string{"bmc", "bios"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m := New(nicoapi.NewMockClient(), 0)
			target := common.Target{
				Type:         devicetypes.ComponentTypeCompute,
				ComponentIDs: []string{"machine-1"},
			}

			err := m.FirmwareControl(context.Background(), target, operations.FirmwareControlTaskInfo{
				Operation:  operations.FirmwareOperationUpgrade,
				SubTargets: tc.subTargets,
			})
			require.NoError(t, err)
		})
	}
}

// --- Tests for firmware version helper functions ---

func desiredEntry(versions map[string]string) *pb.DesiredFirmwareVersionEntry {
	return &pb.DesiredFirmwareVersionEntry{
		ComponentVersions: versions,
	}
}

func TestVersionsEqual(t *testing.T) {
	tests := map[string]struct {
		a, b   map[string]string
		expect bool
	}{
		"equal single key": {
			a:      map[string]string{"bmc": "1.0"},
			b:      map[string]string{"bmc": "1.0"},
			expect: true,
		},
		"equal multiple keys": {
			a:      map[string]string{"bmc": "1.0", "uefi": "2.0"},
			b:      map[string]string{"bmc": "1.0", "uefi": "2.0"},
			expect: true,
		},
		"different values": {
			a:      map[string]string{"bmc": "1.0"},
			b:      map[string]string{"bmc": "2.0"},
			expect: false,
		},
		"different lengths": {
			a:      map[string]string{"bmc": "1.0"},
			b:      map[string]string{"bmc": "1.0", "uefi": "2.0"},
			expect: false,
		},
		"both empty": {
			a:      map[string]string{},
			b:      map[string]string{},
			expect: true,
		},
		"a nil b empty": {
			a:      nil,
			b:      map[string]string{},
			expect: true,
		},
		"both nil": {
			a:      nil,
			b:      nil,
			expect: true,
		},
		"missing key in b": {
			a:      map[string]string{"bmc": "1.0", "uefi": "2.0"},
			b:      map[string]string{"bmc": "1.0", "cpld": "3.0"},
			expect: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expect, versionsEqual(tc.a, tc.b))
		})
	}
}

func TestFirmwareVersionsMatch(t *testing.T) {
	tests := map[string]struct {
		desired, actual map[string]string
		expect          bool
	}{
		"exact match": {
			desired: map[string]string{"bmc": "1.0", "uefi": "2.0"},
			actual:  map[string]string{"bmc": "1.0", "uefi": "2.0"},
			expect:  true,
		},
		"desired is subset of actual": {
			desired: map[string]string{"bmc": "1.0"},
			actual:  map[string]string{"bmc": "1.0", "uefi": "2.0", "cpld": "3.0"},
			expect:  true,
		},
		"version mismatch": {
			desired: map[string]string{"bmc": "1.0"},
			actual:  map[string]string{"bmc": "2.0"},
			expect:  false,
		},
		"desired key missing from actual": {
			desired: map[string]string{"bmc": "1.0", "uefi": "2.0"},
			actual:  map[string]string{"bmc": "1.0"},
			expect:  false,
		},
		"empty desired returns false": {
			desired: map[string]string{},
			actual:  map[string]string{"bmc": "1.0"},
			expect:  false,
		},
		"nil desired returns false": {
			desired: nil,
			actual:  map[string]string{"bmc": "1.0"},
			expect:  false,
		},
		"empty actual with non-empty desired returns false": {
			desired: map[string]string{"bmc": "1.0"},
			actual:  map[string]string{},
			expect:  false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expect, firmwareVersionsMatch(tc.desired, tc.actual))
		})
	}
}

func TestMatchesAnyDesired(t *testing.T) {
	tests := map[string]struct {
		actual  map[string]string
		entries []*pb.DesiredFirmwareVersionEntry
		expect  bool
	}{
		"matches first entry": {
			actual: map[string]string{"bmc": "1.0", "uefi": "2.0"},
			entries: []*pb.DesiredFirmwareVersionEntry{
				desiredEntry(map[string]string{"bmc": "1.0"}),
				desiredEntry(map[string]string{"bmc": "9.0"}),
			},
			expect: true,
		},
		"matches second entry": {
			actual: map[string]string{"bmc": "9.0"},
			entries: []*pb.DesiredFirmwareVersionEntry{
				desiredEntry(map[string]string{"bmc": "1.0"}),
				desiredEntry(map[string]string{"bmc": "9.0"}),
			},
			expect: true,
		},
		"matches none": {
			actual: map[string]string{"bmc": "5.0"},
			entries: []*pb.DesiredFirmwareVersionEntry{
				desiredEntry(map[string]string{"bmc": "1.0"}),
				desiredEntry(map[string]string{"bmc": "9.0"}),
			},
			expect: false,
		},
		"empty entries": {
			actual:  map[string]string{"bmc": "1.0"},
			entries: nil,
			expect:  false,
		},
		"entry with empty component_versions never matches": {
			actual: map[string]string{"bmc": "1.0"},
			entries: []*pb.DesiredFirmwareVersionEntry{
				desiredEntry(map[string]string{}),
			},
			expect: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expect, matchesAnyDesired(tc.actual, tc.entries))
		})
	}
}

func TestParseTargetVersion(t *testing.T) {
	tests := map[string]struct {
		input       string
		expected    map[string]string
		expectError bool
		errContains string
	}{
		"valid json object": {
			input:    `{"bmc":"7.10.30.00","uefi":"2.22.1"}`,
			expected: map[string]string{"bmc": "7.10.30.00", "uefi": "2.22.1"},
		},
		"single key": {
			input:    `{"bmc":"1.0"}`,
			expected: map[string]string{"bmc": "1.0"},
		},
		"empty object": {
			input:    `{}`,
			expected: map[string]string{},
		},
		"invalid json": {
			input:       `{not valid`,
			expectError: true,
			errContains: "target_version must be a JSON object",
		},
		"json array instead of object": {
			input:       `["bmc","1.0"]`,
			expectError: true,
			errContains: "target_version must be a JSON object",
		},
		"json string instead of object": {
			input:       `"bmc:1.0"`,
			expectError: true,
			errContains: "target_version must be a JSON object",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := parseTargetVersion(tc.input)
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestIsTargetVersionInDesired(t *testing.T) {
	entries := []*pb.DesiredFirmwareVersionEntry{
		desiredEntry(map[string]string{"bmc": "7.10.30.00", "uefi": "2.22.1"}),
		desiredEntry(map[string]string{"bmc": "8.0.0.00", "uefi": "3.0.0"}),
	}

	tests := map[string]struct {
		target  map[string]string
		entries []*pb.DesiredFirmwareVersionEntry
		expect  bool
	}{
		"matches first entry exactly": {
			target:  map[string]string{"bmc": "7.10.30.00", "uefi": "2.22.1"},
			entries: entries,
			expect:  true,
		},
		"matches second entry exactly": {
			target:  map[string]string{"bmc": "8.0.0.00", "uefi": "3.0.0"},
			entries: entries,
			expect:  true,
		},
		"partial match is not equal": {
			target:  map[string]string{"bmc": "7.10.30.00"},
			entries: entries,
			expect:  false,
		},
		"no match": {
			target:  map[string]string{"bmc": "99.0.0", "uefi": "99.0"},
			entries: entries,
			expect:  false,
		},
		"empty entries": {
			target:  map[string]string{"bmc": "1.0"},
			entries: nil,
			expect:  false,
		},
		"empty target with empty entry": {
			target:  map[string]string{},
			entries: []*pb.DesiredFirmwareVersionEntry{desiredEntry(map[string]string{})},
			expect:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expect, isTargetVersionInDesired(tc.target, tc.entries))
		})
	}
}

func TestAllFirmwareUpToDate(t *testing.T) {
	desiredEntries := []*pb.DesiredFirmwareVersionEntry{
		desiredEntry(map[string]string{"bmc": "1.0", "uefi": "2.0"}),
		desiredEntry(map[string]string{"bmc": "3.0", "uefi": "4.0"}),
	}

	tests := map[string]struct {
		componentIDs   []string
		actualFirmware map[string]map[string]string
		targetFirmware map[string]string
		desiredEntries []*pb.DesiredFirmwareVersionEntry
		expect         bool
	}{
		"all match target firmware": {
			componentIDs: []string{"m1", "m2"},
			actualFirmware: map[string]map[string]string{
				"m1": {"bmc": "1.0", "uefi": "2.0"},
				"m2": {"bmc": "1.0", "uefi": "2.0"},
			},
			targetFirmware: map[string]string{"bmc": "1.0"},
			desiredEntries: desiredEntries,
			expect:         true,
		},
		"one machine does not match target": {
			componentIDs: []string{"m1", "m2"},
			actualFirmware: map[string]map[string]string{
				"m1": {"bmc": "1.0", "uefi": "2.0"},
				"m2": {"bmc": "OLD", "uefi": "2.0"},
			},
			targetFirmware: map[string]string{"bmc": "1.0"},
			desiredEntries: desiredEntries,
			expect:         false,
		},
		"all match desired (no target)": {
			componentIDs: []string{"m1", "m2"},
			actualFirmware: map[string]map[string]string{
				"m1": {"bmc": "1.0", "uefi": "2.0"},
				"m2": {"bmc": "3.0", "uefi": "4.0"},
			},
			targetFirmware: nil,
			desiredEntries: desiredEntries,
			expect:         true,
		},
		"one machine does not match any desired": {
			componentIDs: []string{"m1", "m2"},
			actualFirmware: map[string]map[string]string{
				"m1": {"bmc": "1.0", "uefi": "2.0"},
				"m2": {"bmc": "OLD", "uefi": "OLD"},
			},
			targetFirmware: nil,
			desiredEntries: desiredEntries,
			expect:         false,
		},
		"empty actualFirmware": {
			componentIDs:   []string{"m1"},
			actualFirmware: map[string]map[string]string{},
			targetFirmware: nil,
			desiredEntries: desiredEntries,
			expect:         false,
		},
		"nil actualFirmware": {
			componentIDs:   []string{"m1"},
			actualFirmware: nil,
			targetFirmware: nil,
			desiredEntries: desiredEntries,
			expect:         false,
		},
		"component missing from actualFirmware": {
			componentIDs: []string{"m1", "m2"},
			actualFirmware: map[string]map[string]string{
				"m1": {"bmc": "1.0", "uefi": "2.0"},
			},
			targetFirmware: nil,
			desiredEntries: desiredEntries,
			expect:         false,
		},
		"component has empty firmware map": {
			componentIDs: []string{"m1"},
			actualFirmware: map[string]map[string]string{
				"m1": {},
			},
			targetFirmware: nil,
			desiredEntries: desiredEntries,
			expect:         false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expect, allFirmwareUpToDate(
				tc.componentIDs, tc.actualFirmware, tc.targetFirmware, tc.desiredEntries,
			))
		})
	}
}
