// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoapi

import (
	"encoding/json"
	"strings"

	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
)

// MapComponentOperationStatus translates a raw Core controller_state string into a
// types.ComponentOperationStatus for the given component type. The raw form differs
// per type — that is why this lives in nicoapi (which owns "what raw
// string Core returns") rather than in the dependency-light pkg/types:
//   - Compute: ManagedHostState Display (e.g. "Ready", "Assigned/Provisioning").
//   - Switch / PowerShelf: JSON object with a "state" tag (e.g. {"state":"ready"}).
//
// Unrecognized inputs map to PhaseUnknown so callers fail closed.
func MapComponentOperationStatus(componentType types.ComponentType, rawState string) types.ComponentOperationStatus {
	switch componentType {
	case types.ComponentTypeCompute:
		return mapComputeStatus(rawState)
	case types.ComponentTypeNVSwitch:
		return mapSwitchStatus(rawState)
	case types.ComponentTypePowerShelf:
		return mapPowerShelfStatus(rawState)
	default:
		return types.ComponentOperationStatus{
			Phase:  types.PhaseUnknown,
			Reason: "unsupported component type: " + string(componentType),
		}
	}
}

func mapComputeStatus(raw string) types.ComponentOperationStatus {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return types.ComponentOperationStatus{Phase: types.PhaseUnknown, Reason: "no controller_state from core"}
	}

	head := raw
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		head = raw[:i]
	}

	switch head {
	case "Ready", "StartAssignmentCycle":
		return blockNoneIfReady(types.PhaseReady, "", types.ComponentTypeCompute)
	case "Created",
		"DPUDiscovering",
		"DPUInitializing",
		"HostInitializing",
		"Measuring",
		"PreAssignedMeasuring",
		"PostAssignedMeasuring",
		"BomValidating":
		return blockAll(types.PhaseInitializing, raw, types.ComponentTypeCompute)
	case "Assigned",
		"WaitingForCleanup",
		"Reprovisioning",
		"HostReprovisioning":
		return blockAll(types.PhaseInUse, raw, types.ComponentTypeCompute)
	case "Failed":
		return blockAll(types.PhaseError, raw, types.ComponentTypeCompute)
	case "ForceDeletion":
		return blockAll(types.PhaseDeleting, raw, types.ComponentTypeCompute)
	}

	// ManagedHostState::Validation Display delegates straight to its
	// inner ValidationState, so there is no "Validation/" prefix to key
	// on. Treat any unmatched value conservatively as Initializing —
	// safer than Unknown for compute since core is doing work.
	return blockAll(types.PhaseInitializing, raw, types.ComponentTypeCompute)
}

// switchStateEnvelope decodes the serde-tagged JSON emitted by core for
// SwitchControllerState / PowerShelfControllerState. Only the "state"
// discriminator is needed for the Phase decision; the full payload is
// kept in Reason for diagnostics.
type switchStateEnvelope struct {
	State string `json:"state"`
}

func mapSwitchStatus(raw string) types.ComponentOperationStatus {
	tag, ok := decodeTaggedState(raw)
	if !ok {
		return types.ComponentOperationStatus{Phase: types.PhaseUnknown, Reason: "undecodable switch state: " + raw}
	}
	switch tag {
	case "ready":
		return blockNoneIfReady(types.PhaseReady, "", types.ComponentTypeNVSwitch)
	case "created", "initializing", "configuring", "validating", "bomvalidating":
		return blockAll(types.PhaseInitializing, raw, types.ComponentTypeNVSwitch)
	case "reprovisioning":
		return blockAll(types.PhaseInUse, raw, types.ComponentTypeNVSwitch)
	case "error":
		return blockAll(types.PhaseError, raw, types.ComponentTypeNVSwitch)
	case "deleting":
		return blockAll(types.PhaseDeleting, raw, types.ComponentTypeNVSwitch)
	}
	return types.ComponentOperationStatus{Phase: types.PhaseUnknown, Reason: "unknown switch state tag: " + tag}
}

func mapPowerShelfStatus(raw string) types.ComponentOperationStatus {
	tag, ok := decodeTaggedState(raw)
	if !ok {
		return types.ComponentOperationStatus{Phase: types.PhaseUnknown, Reason: "undecodable power shelf state: " + raw}
	}
	switch tag {
	case "ready":
		return blockNoneIfReady(types.PhaseReady, "", types.ComponentTypePowerShelf)
	case "initializing", "fetchingdata", "configuring":
		return blockAll(types.PhaseInitializing, raw, types.ComponentTypePowerShelf)
	case "maintenance":
		return blockAll(types.PhaseInUse, raw, types.ComponentTypePowerShelf)
	case "error":
		return blockAll(types.PhaseError, raw, types.ComponentTypePowerShelf)
	case "deleting":
		return blockAll(types.PhaseDeleting, raw, types.ComponentTypePowerShelf)
	}
	return types.ComponentOperationStatus{Phase: types.PhaseUnknown, Reason: "unknown power shelf state tag: " + tag}
}

func decodeTaggedState(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	var env switchStateEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil || env.State == "" {
		return "", false
	}
	return env.State, true
}

// blockedOpsByType lists the operations Flow currently knows how to gate
// per component type. When Phase != Ready, all of these are blocked;
// Ready blocks none. Per-operation refinement (e.g. allowing power while
// a compute is in Assigned/Provisioning) is deferred.
var blockedOpsByType = map[types.ComponentType][]types.OperationType{
	types.ComponentTypeCompute:    {types.OperationTypePowerControl, types.OperationTypeFirmwareControl},
	types.ComponentTypeNVSwitch:   {types.OperationTypePowerControl, types.OperationTypeFirmwareControl},
	types.ComponentTypePowerShelf: {types.OperationTypePowerControl, types.OperationTypeFirmwareControl},
}

func blockAll(phase types.Phase, reason string, ct types.ComponentType) types.ComponentOperationStatus {
	return types.ComponentOperationStatus{
		Phase:             phase,
		Reason:            reason,
		BlockedOperations: append([]types.OperationType(nil), blockedOpsByType[ct]...),
	}
}

func blockNoneIfReady(phase types.Phase, reason string, _ types.ComponentType) types.ComponentOperationStatus {
	return types.ComponentOperationStatus{Phase: phase, Reason: reason}
}
