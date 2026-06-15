// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package firmwarecomponents

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nicopb "github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi/gen"
)

func TestParseNICoNVSwitch(t *testing.T) {
	t.Run("nil input returns nil (caller decides)", func(t *testing.T) {
		got, err := ParseNICoNVSwitch(nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("known names map to proto enums", func(t *testing.T) {
		got, err := ParseNICoNVSwitch([]string{"bmc", "cpld", "bios", "nvos"})
		require.NoError(t, err)
		assert.Equal(t, []nicopb.NvSwitchComponent{
			nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_BMC,
			nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_CPLD,
			nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_BIOS,
			nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_NVOS,
		}, got)
	})

	t.Run("uppercase and surrounding whitespace are tolerated", func(t *testing.T) {
		got, err := ParseNICoNVSwitch([]string{" BMC ", "NVOS"})
		require.NoError(t, err)
		assert.Equal(t, []nicopb.NvSwitchComponent{
			nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_BMC,
			nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_NVOS,
		}, got)
	})

	t.Run("unknown name is rejected with sorted suggestions", func(t *testing.T) {
		_, err := ParseNICoNVSwitch([]string{"pmc"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"pmc"`)
		assert.Contains(t, err.Error(), "bios, bmc, cpld, nvos")
	})
}

func TestParseNICoPowerShelf(t *testing.T) {
	got, err := ParseNICoPowerShelf([]string{"pmc", "psu"})
	require.NoError(t, err)
	assert.Equal(t, []nicopb.PowerShelfComponent{
		nicopb.PowerShelfComponent_POWER_SHELF_COMPONENT_PMC,
		nicopb.PowerShelfComponent_POWER_SHELF_COMPONENT_PSU,
	}, got)

	_, err = ParseNICoPowerShelf([]string{"bmc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pmc, psu")
}

func TestParseNICoComputeTray(t *testing.T) {
	got, err := ParseNICoComputeTray([]string{"bmc", "bios"})
	require.NoError(t, err)
	assert.Equal(t, []nicopb.ComputeTrayComponent{
		nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_BMC,
		nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_BIOS,
	}, got)

	_, err = ParseNICoComputeTray([]string{"nvos"})
	require.Error(t, err)
}

// TestParseNICoComputeTrayRejectsDpu pins the contract that ParseNICoComputeTray
// does NOT silently accept "dpu". Callers must route that target through
// SplitNICoComputeTraySubTargets first; otherwise a misrouted "dpu" must
// surface as an explicit error rather than as an empty / wrong enum value.
func TestParseNICoComputeTrayRejectsDpu(t *testing.T) {
	_, err := ParseNICoComputeTray([]string{"dpu"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"dpu"`)
}

func TestSplitNICoComputeTraySubTargets(t *testing.T) {
	tests := []struct {
		name              string
		in                []string
		wantComputeSubs   []string
		wantHasDpu        bool
		describesBehavior string
	}{
		{
			name:              "nil/empty input does not opt-in to DPU",
			in:                nil,
			wantComputeSubs:   nil,
			wantHasDpu:        false,
			describesBehavior: "empty targets means no DPU reprov; matches REST handler default",
		},
		{
			name:            "compute-tray-only sub-targets pass through verbatim",
			in:              []string{"bmc", "bios"},
			wantComputeSubs: []string{"bmc", "bios"},
			wantHasDpu:      false,
		},
		{
			name:            "lone dpu opts in and produces empty compute-tray sub list",
			in:              []string{"dpu"},
			wantComputeSubs: nil,
			wantHasDpu:      true,
		},
		{
			name:            "mixed input is split into compute sub-targets and dpu opt-in",
			in:              []string{"bmc", "dpu", "bios"},
			wantComputeSubs: []string{"bmc", "bios"},
			wantHasDpu:      true,
		},
		{
			name:            "dpu casing and surrounding whitespace are tolerated",
			in:              []string{" DPU ", "Dpu"},
			wantComputeSubs: nil,
			wantHasDpu:      true,
		},
		{
			name:            "non-dpu names are passed through with their casing intact",
			in:              []string{" BMC ", "Bios"},
			wantComputeSubs: []string{" BMC ", "Bios"},
			wantHasDpu:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSubs, gotHasDpu := SplitNICoComputeTraySubTargets(tc.in)
			assert.Equal(t, tc.wantComputeSubs, gotSubs)
			assert.Equal(t, tc.wantHasDpu, gotHasDpu)
		})
	}
}

func TestSupportedNamesAreSortedAndImmutable(t *testing.T) {
	names := SupportedNICoNVSwitchNames()
	require.Equal(t, []string{"bios", "bmc", "cpld", "nvos"}, names)

	names[0] = "mutated"
	again := SupportedNICoNVSwitchNames()
	require.Equal(t, []string{"bios", "bmc", "cpld", "nvos"}, again)
}

// === Completeness guards =================================================
//
// These tests fail when Core's proto adds a new value to one of the NICo
// per-tray-type enums and the developer has not added a matching lowercase
// entry to firmwarecomponents.go. The intent is to force the choice of a
// public REST name to happen in PR review, on purpose, rather than being
// silently derived (or silently dropped) by a generic helper.

// completenessFor checks that every non-UNKNOWN value in the protoc-
// generated _name reverse map is represented in our hand-written mapping.
// enumLabel is used purely for the error message.
func completenessFor[E ~int32](
	t *testing.T,
	enumLabel string,
	protoNames map[int32]string,
	mapping map[string]E,
) {
	t.Helper()

	present := make(map[int32]struct{}, len(mapping))
	for _, v := range mapping {
		present[int32(v)] = struct{}{}
	}

	for v, name := range protoNames {
		// Skip the proto-conventional sentinel; we deliberately never
		// expose it on the REST surface.
		if v == 0 || strings.HasSuffix(name, "_UNKNOWN") || strings.HasSuffix(name, "_UNSPECIFIED") {
			continue
		}
		if _, ok := present[v]; !ok {
			t.Fatalf(
				"firmwarecomponents: %s proto value %s (=%d) has no lowercase REST name. "+
					"Add an entry to the corresponding map in firmwarecomponents.go.",
				enumLabel, name, v,
			)
		}
	}
}

func TestNICoNVSwitchMapIsComplete(t *testing.T) {
	completenessFor(t, "NvSwitchComponent", nicopb.NvSwitchComponent_name, nicoNVSwitchByName)
}

func TestNICoPowerShelfMapIsComplete(t *testing.T) {
	completenessFor(t, "PowerShelfComponent", nicopb.PowerShelfComponent_name, nicoPowerShelfByName)
}

func TestNICoComputeTrayMapIsComplete(t *testing.T) {
	completenessFor(t, "ComputeTrayComponent", nicopb.ComputeTrayComponent_name, nicoComputeTrayByName)
}
