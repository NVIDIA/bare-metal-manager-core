// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package firmwarecomponents converts the lowercase component-name strings
// accepted by the REST/Flow firmware-update API into the per-tray-type
// enum values used by each downstream component manager.
//
// The mappings are written explicitly so that:
//
//   - Renaming or removing a proto enum constant in Core fails the build
//     here at compile time, instead of silently turning into an empty
//     accepted set.
//   - The lowercase REST name for each enum value is reviewable in a PR
//     rather than derived from a prefix-stripping heuristic.
//   - Editors can jump from "bmc" straight to the proto enum const.
//
// Completeness against Core's proto is enforced by the unit tests in this
// package: for each NICo enum, the tests iterate the protoc-generated
// `*_name` reverse map and require every non-UNKNOWN value to appear in
// our mapping. When Core adds a new value, regen + test failure tells the
// developer to pick a lowercase name and add an entry here, on purpose.
package firmwarecomponents

import (
	"fmt"
	"sort"
	"strings"

	nicopb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/nsmapi"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/psmapi"
)

// === NICo (Core) per-tray enums. ==========================================

var (
	nicoNVSwitchByName = map[string]nicopb.NvSwitchComponent{
		"bmc":  nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_BMC,
		"cpld": nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_CPLD,
		"bios": nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_BIOS,
		"nvos": nicopb.NvSwitchComponent_NV_SWITCH_COMPONENT_NVOS,
	}
	nicoNVSwitchNames = sortedKeys(nicoNVSwitchByName)

	nicoPowerShelfByName = map[string]nicopb.PowerShelfComponent{
		"pmc": nicopb.PowerShelfComponent_POWER_SHELF_COMPONENT_PMC,
		"psu": nicopb.PowerShelfComponent_POWER_SHELF_COMPONENT_PSU,
	}
	nicoPowerShelfNames = sortedKeys(nicoPowerShelfByName)

	nicoComputeTrayByName = map[string]nicopb.ComputeTrayComponent{
		"bmc":               nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_BMC,
		"bios":              nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_BIOS,
		"cec":               nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_CEC,
		"nic":               nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_NIC,
		"cpld_mb":           nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_CPLD_MB,
		"cpld_pdb":          nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_CPLD_PDB,
		"hgx_bmc":           nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_HGX_BMC,
		"combined_bmc_uefi": nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_COMBINED_BMC_UEFI,
		"gpu":               nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_GPU,
		"cx7":               nicopb.ComputeTrayComponent_COMPUTE_TRAY_COMPONENT_CX7,
	}
	nicoComputeTrayNames = sortedKeys(nicoComputeTrayByName)
)

// ParseNICoNVSwitch maps lowercase names to NICo NvSwitchComponent values.
// Returns nil for an empty input (callers may interpret as "all components").
func ParseNICoNVSwitch(names []string) ([]nicopb.NvSwitchComponent, error) {
	return lookup(names, nicoNVSwitchByName, nicoNVSwitchNames, "nvswitch")
}

// ParseNICoPowerShelf maps lowercase names to NICo PowerShelfComponent values.
func ParseNICoPowerShelf(names []string) ([]nicopb.PowerShelfComponent, error) {
	return lookup(names, nicoPowerShelfByName, nicoPowerShelfNames, "powershelf")
}

// ParseNICoComputeTray maps lowercase names to NICo ComputeTrayComponent values.
func ParseNICoComputeTray(names []string) ([]nicopb.ComputeTrayComponent, error) {
	return lookup(names, nicoComputeTrayByName, nicoComputeTrayNames, "compute")
}

// SupportedNICoNVSwitchNames returns the lowercase names accepted by
// ParseNICoNVSwitch in deterministic order. Useful for surfacing the set
// in API documentation or operator tooling.
func SupportedNICoNVSwitchNames() []string { return append([]string(nil), nicoNVSwitchNames...) }

// SupportedNICoPowerShelfNames returns the lowercase names accepted by
// ParseNICoPowerShelf in deterministic order.
func SupportedNICoPowerShelfNames() []string {
	return append([]string(nil), nicoPowerShelfNames...)
}

// SupportedNICoComputeTrayNames returns the lowercase names accepted by
// ParseNICoComputeTray in deterministic order.
func SupportedNICoComputeTrayNames() []string {
	return append([]string(nil), nicoComputeTrayNames...)
}

// === Legacy NSM-direct path. nsmapi.NVSwitchComponent is a hand-rolled Go
//     enum (not a proto enum), so we keep an explicit map here. ===

var (
	nsmNVSwitchByName = map[string]nsmapi.NVSwitchComponent{
		"bmc":  nsmapi.NVSwitchComponentBMC,
		"cpld": nsmapi.NVSwitchComponentCPLD,
		"bios": nsmapi.NVSwitchComponentBIOS,
		"nvos": nsmapi.NVSwitchComponentNVOS,
	}
	nsmNVSwitchNames = sortedKeys(nsmNVSwitchByName)
)

// ParseNSMNVSwitch maps lowercase names to nsmapi.NVSwitchComponent values.
func ParseNSMNVSwitch(names []string) ([]nsmapi.NVSwitchComponent, error) {
	return lookup(names, nsmNVSwitchByName, nsmNVSwitchNames, "nvswitch")
}

// === Legacy PSM-direct path. Same story as NSM. ===

var (
	psmPowerShelfByName = map[string]psmapi.PowershelfComponent{
		"pmc": psmapi.PowershelfComponentPMC,
		"psu": psmapi.PowershelfComponentPSU,
	}
	psmPowerShelfNames = sortedKeys(psmPowerShelfByName)
)

// ParsePSMPowerShelf maps lowercase names to psmapi.PowershelfComponent values.
func ParsePSMPowerShelf(names []string) ([]psmapi.PowershelfComponent, error) {
	return lookup(names, psmPowerShelfByName, psmPowerShelfNames, "powershelf")
}

// === internal helpers ====================================================

// sortedKeys returns the keys of m in lexicographic order. Used to produce
// deterministic "expected one of: ..." error messages.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lookup is the shared per-name resolution loop. An empty/nil input yields
// (nil, nil); callers decide whether nil means "all components" or "default
// to one specific component". Surrounding whitespace is tolerated; case
// is normalized to lowercase before lookup.
func lookup[E any](names []string, table map[string]E, sortedNames []string, kind string) ([]E, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make([]E, 0, len(names))
	for _, n := range names {
		v, ok := table[strings.ToLower(strings.TrimSpace(n))]
		if !ok {
			return nil, fmt.Errorf(
				"unknown %s component %q (expected one of: %s)",
				kind, n, strings.Join(sortedNames, ", "),
			)
		}
		out = append(out, v)
	}
	return out, nil
}
