// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nico

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/capability"
	cmcatalog "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/catalog"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providerapi"
	nicoprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/nico"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/firmwarecomponents"
)

const (
	// ImplementationName is the name used to identify this implementation.
	ImplementationName = "nico"
)

// Manager manages NVLink switch components via the NICo API.
type Manager struct {
	nicoClient nicoapi.Client
	// assignment guards power/firmware operations on a switch from running
	// while any host on the switch's rack is still attached to an instance.
	// A switch reset typically disrupts NVLink traffic for the whole rack,
	// so this safety check is rack-scoped rather than component-scoped.
	assignment *nicoprovider.AssignmentChecker
}

// New creates a new NICo-based NVSwitch Manager instance.
func New(nicoClient nicoapi.Client) *Manager {
	return &Manager{
		nicoClient: nicoClient,
		assignment: nicoprovider.NewAssignmentChecker(nicoClient, 0, 0),
	}
}

// Factory creates a new Manager from the provided providers.
// It retrieves the NICoProvider from the registry and uses its client.
func Factory(providerRegistry *providerapi.ProviderRegistry) (componentmanager.ComponentManager, error) {
	provider, err := providerapi.GetTyped[*nicoprovider.Provider](
		providerRegistry,
		nicoprovider.ProviderName,
	)
	if err != nil {
		return nil, fmt.Errorf("nvswitch/nico requires nico provider: %w", err)
	}

	return New(provider.Client()), nil
}

// Descriptor returns the NICo NVSwitch manager descriptor.
func Descriptor() cmcatalog.Descriptor {
	return cmcatalog.Descriptor{
		DescriptorIdentity: cmcatalog.DescriptorIdentity{
			Type:           devicetypes.ComponentTypeNVSwitch,
			Implementation: ImplementationName,
		},
		RequiredProviders: []string{nicoprovider.ProviderName},
		Capabilities: capability.CapabilitySet{
			capability.CapabilityFirmwareConsistencyCheck,
			capability.CapabilityFirmwareControl,
			capability.CapabilityFirmwareStatus,
			capability.CapabilityInjectExpectation,
			capability.CapabilityPowerControl,
			capability.CapabilityPowerStatus,
		},
	}
}

// FactorySpec returns the NICo NVSwitch manager runtime factory spec.
func FactorySpec() componentmanager.FactorySpec {
	return componentmanager.FactorySpec{
		Descriptor: Descriptor(),
		Factory:    Factory,
	}
}

// Descriptor returns the NICo NVSwitch manager descriptor.
func (m *Manager) Descriptor() cmcatalog.Descriptor {
	return Descriptor()
}

// InjectExpectation registers an expected switch with NICo via AddExpectedSwitch.
// The Info field should contain a JSON-encoded nicoapi.AddExpectedSwitchRequest.
func (m *Manager) InjectExpectation(
	ctx context.Context,
	target common.Target,
	info operations.InjectExpectationTaskInfo,
) error {
	var req nicoapi.AddExpectedSwitchRequest
	if err := json.Unmarshal(info.Info, &req); err != nil {
		return fmt.Errorf("failed to unmarshal AddExpectedSwitchRequest: %w", err)
	}

	if m.nicoClient == nil {
		return fmt.Errorf("nico client is not configured")
	}

	if err := m.nicoClient.AddExpectedSwitch(ctx, req); err != nil {
		return fmt.Errorf("failed to add expected switch: %w", err)
	}

	log.Info().
		Str("bmc_mac", req.BMCMACAddress).
		Str("switch_serial", req.SwitchSerialNumber).
		Msg("Successfully registered expected switch with NICo")

	return nil
}

func switchIDsProto(ids []string) *pb.SwitchIdList {
	pbIDs := make([]*pb.SwitchId, len(ids))
	for i, id := range ids {
		pbIDs[i] = &pb.SwitchId{Id: id}
	}
	return &pb.SwitchIdList{Ids: pbIDs}
}

// ensureRackOperable is the per-Manager policy gate for disruptive
// operations on the racks that own the given switches. The default policy
// refuses to proceed while any host on the resolved rack(s) is still in
// Core's Assigned/* lifecycle state, because a switch reset disrupts
// NVLink traffic for the entire rack.
//
// When overrideAssignmentCheck is true the gate is short-circuited
// without performing the rack lookup: the operator has acknowledged the
// tenant impact upstream and the rack-resolution gRPC call is no longer
// necessary. A warning is emitted with the switch IDs so the bypass is
// auditable from the worker log alone.
//
// A switch that Core does not associate with a rack is logged and
// skipped: failing closed would block bring-up flows for switches that
// have not yet been ingested into the rack topology.
func (m *Manager) ensureRackOperable(
	ctx context.Context,
	switchIDs []string,
	overrideAssignmentCheck bool,
) error {
	if len(switchIDs) == 0 {
		return nil
	}

	if overrideAssignmentCheck {
		log.Warn().
			Strs("switch_ids", switchIDs).
			Msg("Assignment safety check bypassed by override_assignment_check on NVSwitch operation")
		return nil
	}

	rackBySwitch, err := m.nicoClient.FindSwitchRackIDs(ctx, switchIDs)
	if err != nil {
		return fmt.Errorf("look up rack for switches: %w", err)
	}

	rackIDs := make([]string, 0, len(rackBySwitch))
	for _, rid := range rackBySwitch {
		rackIDs = append(rackIDs, rid)
	}

	var orphan []string
	for _, sid := range switchIDs {
		if _, ok := rackBySwitch[sid]; !ok {
			orphan = append(orphan, sid)
		}
	}
	if len(orphan) > 0 {
		log.Warn().
			Strs("switch_ids", orphan).
			Msg("NVSwitch has no rack assignment; assignment safety check cannot be applied")
	}

	return m.assignment.WaitForRacksUnassigned(ctx, rackIDs)
}

// PowerControl performs power operations on NVLink switches via NICo's
// ComponentPowerControl RPC.
func (m *Manager) PowerControl(
	ctx context.Context,
	target common.Target,
	info operations.PowerControlTaskInfo,
) error {
	log.Debug().Msgf(
		"NVSwitch power control %s op %s via NICo",
		target.String(),
		info.Operation.String(),
	)

	if err := target.Validate(); err != nil {
		return fmt.Errorf("target is invalid: %w", err)
	}

	if err := m.ensureRackOperable(ctx, target.ComponentIDs, info.OverrideAssignmentCheck); err != nil {
		return fmt.Errorf("refused: %w", err)
	}

	var action pb.SystemPowerControl
	switch info.Operation {
	case operations.PowerOperationPowerOn, operations.PowerOperationForcePowerOn:
		action = pb.SystemPowerControl_SYSTEM_POWER_CONTROL_ON
	case operations.PowerOperationPowerOff:
		action = pb.SystemPowerControl_SYSTEM_POWER_CONTROL_GRACEFUL_SHUTDOWN
	case operations.PowerOperationForcePowerOff:
		action = pb.SystemPowerControl_SYSTEM_POWER_CONTROL_FORCE_OFF
	case operations.PowerOperationRestart, operations.PowerOperationWarmReset:
		action = pb.SystemPowerControl_SYSTEM_POWER_CONTROL_GRACEFUL_RESTART
	case operations.PowerOperationForceRestart:
		action = pb.SystemPowerControl_SYSTEM_POWER_CONTROL_FORCE_RESTART
	default:
		return fmt.Errorf("unsupported power operation for NVSwitch: %v", info.Operation)
	}

	req := &pb.ComponentPowerControlRequest{
		Target: &pb.ComponentPowerControlRequest_SwitchIds{
			SwitchIds: switchIDsProto(target.ComponentIDs),
		},
		Action: action,
	}

	resp, err := m.nicoClient.ComponentPowerControl(ctx, req)
	if err != nil {
		return fmt.Errorf("ComponentPowerControl failed: %w", err)
	}

	for _, r := range resp.GetResults() {
		if r.GetStatus() != pb.ComponentManagerStatusCode_COMPONENT_MANAGER_STATUS_CODE_SUCCESS {
			return fmt.Errorf("power control failed for %s: %s", r.GetComponentId(), r.GetError())
		}
	}

	log.Info().Msgf("NVSwitch power control %s on %s completed via NICo",
		info.Operation.String(), target.String())
	return nil
}

func (m *Manager) GetPowerStatus(
	ctx context.Context,
	target common.Target,
) (map[string]operations.PowerStatus, error) {
	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("target is invalid: %w", err)
	}

	req := &pb.GetComponentInventoryRequest{
		Target: &pb.GetComponentInventoryRequest_SwitchIds{
			SwitchIds: switchIDsProto(target.ComponentIDs),
		},
	}

	resp, err := m.nicoClient.GetComponentInventory(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetComponentInventory failed: %w", err)
	}

	result := make(map[string]operations.PowerStatus, len(target.ComponentIDs))
	for _, id := range target.ComponentIDs {
		result[id] = operations.PowerStatusUnknown
	}

	for _, entry := range resp.GetEntries() {
		compID := entry.GetResult().GetComponentId()
		if ps := nicoprovider.ExtractPowerState(entry.GetReport()); ps != operations.PowerStatusUnknown {
			result[compID] = ps
		}
	}

	return result, nil
}

// nicoPowerStateToOperationsPowerStatus converts nico PowerState to operations PowerStatus.
func nicoPowerStateToOperationsPowerStatus(state nicoapi.PowerState) operations.PowerStatus {
	switch state {
	case nicoapi.PowerStateOn:
		return operations.PowerStatusOn
	case nicoapi.PowerStateOff, nicoapi.PowerStateDisabled:
		return operations.PowerStatusOff
	default:
		return operations.PowerStatusUnknown
	}
}

// FirmwareControl schedules a firmware update via NICo's UpdateComponentFirmware API.
//
// When TargetVersion is provided it is forwarded directly to Core.
// When TargetVersion is empty (e.g. BringUp context), the method queries
// Core's desired firmware entries and the actual firmware from explored
// endpoints to perform an idempotency check. If all switches already run the
// desired firmware the call returns early without triggering an update.
//
// Before issuing the update the method also verifies that all target switches
// report the same firmware version set. A heterogeneous fleet is rejected
// because a single UpdateComponentFirmware call cannot target mixed versions.
func (m *Manager) FirmwareControl(ctx context.Context, target common.Target, info operations.FirmwareControlTaskInfo) error {
	log.Debug().
		Str("components", target.String()).
		Str("target_version", info.TargetVersion).
		Strs("sub_targets", info.SubTargets).
		Msg("Starting firmware update for NVSwitch via NICo")

	if err := target.Validate(); err != nil {
		return fmt.Errorf("target is invalid: %w", err)
	}

	if err := m.ensureRackOperable(ctx, target.ComponentIDs, info.OverrideAssignmentCheck); err != nil {
		return fmt.Errorf("refused: %w", err)
	}

	subComponents, err := firmwarecomponents.ParseNICoNVSwitch(info.SubTargets)
	if err != nil {
		return err
	}

	if info.TargetVersion == "" {
		upToDate, err := m.checkFirmwareUpToDate(ctx, target)
		if err != nil {
			log.Warn().Err(err).Msg("NVSwitch idempotency check failed, proceeding with update")
		} else if upToDate {
			log.Info().
				Str("components", target.String()).
				Msg("All NVSwitch firmware already at desired version, skipping update")
			return nil
		}
	}

	req := &pb.UpdateComponentFirmwareRequest{
		Target: &pb.UpdateComponentFirmwareRequest_Switches{
			Switches: &pb.UpdateSwitchFirmwareTarget{
				SwitchIds:  switchIDsProto(target.ComponentIDs),
				Components: subComponents,
			},
		},
		TargetVersion: info.TargetVersion,
	}

	resp, err := m.nicoClient.UpdateComponentFirmware(ctx, req)
	if err != nil {
		return fmt.Errorf("UpdateComponentFirmware failed: %w", err)
	}

	for _, r := range resp.GetResults() {
		if r.GetStatus() != pb.ComponentManagerStatusCode_COMPONENT_MANAGER_STATUS_CODE_SUCCESS {
			return fmt.Errorf("firmware update failed for %s: %s", r.GetComponentId(), r.GetError())
		}
	}

	log.Info().
		Str("components", target.String()).
		Str("target_version", info.TargetVersion).
		Msg("Firmware update started for NVSwitch via NICo")
	return nil
}

// checkFirmwareUpToDate queries actual firmware from GetComponentInventory and
// desired firmware from Core, returning true when all target switches are
// already running a desired version.
func (m *Manager) checkFirmwareUpToDate(ctx context.Context, target common.Target) (bool, error) {
	desiredEntries, err := m.nicoClient.GetDesiredFirmwareVersions(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to query desired firmware versions: %w", err)
	}

	actualFirmware, err := m.getActualFirmwareVersions(ctx, target)
	if err != nil {
		return false, err
	}

	if len(actualFirmware) == 0 {
		return false, nil
	}

	for _, id := range target.ComponentIDs {
		actual, ok := actualFirmware[id]
		if !ok || len(actual) == 0 {
			return false, nil
		}
		if !matchesAnyDesired(actual, desiredEntries) {
			return false, nil
		}
	}
	return true, nil
}

// getActualFirmwareVersions queries GetComponentInventory for the target
// switches and extracts firmware versions from the exploration reports.
// report.FirmwareVersions is empty for NVSwitches (Core's FirmwareConfig
// only covers host/DPU), so fall back to the raw Redfish FirmwareInventory
// entries in report.Service[].Inventories[], keyed by Inventory.Id.
func (m *Manager) getActualFirmwareVersions(ctx context.Context, target common.Target) (map[string]map[string]string, error) {
	req := &pb.GetComponentInventoryRequest{
		Target: &pb.GetComponentInventoryRequest_SwitchIds{
			SwitchIds: switchIDsProto(target.ComponentIDs),
		},
	}

	resp, err := m.nicoClient.GetComponentInventory(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetComponentInventory failed: %w", err)
	}

	result := make(map[string]map[string]string, len(target.ComponentIDs))
	for _, entry := range resp.GetEntries() {
		compID := entry.GetResult().GetComponentId()
		report := entry.GetReport()
		fwVersions := report.GetFirmwareVersions()
		if len(fwVersions) == 0 {
			fwVersions = extractInventoryVersions(report)
		}
		if len(fwVersions) > 0 {
			result[compID] = fwVersions
		}
	}
	return result, nil
}

// extractInventoryVersions builds a firmware version map from the raw Redfish
// FirmwareInventory entries in the exploration report, keyed by Inventory.Id.
// Entries without a version are skipped.
func extractInventoryVersions(report *pb.EndpointExplorationReport) map[string]string {
	out := make(map[string]string)
	for _, svc := range report.GetService() {
		for _, inv := range svc.GetInventories() {
			if v := inv.GetVersion(); v != "" {
				out[inv.GetId()] = v
			}
		}
	}
	return out
}

// VerifyFirmwareConsistency checks that all target switches report the same
// firmware version set. Returns an error when versions are heterogeneous.
func (m *Manager) VerifyFirmwareConsistency(ctx context.Context, target common.Target) error {
	actualFirmware, err := m.getActualFirmwareVersions(ctx, target)
	if err != nil {
		return err
	}

	var referenceJSON string
	for _, id := range target.ComponentIDs {
		actual, ok := actualFirmware[id]
		if !ok {
			return fmt.Errorf("switch %s has no firmware version data", id)
		}
		encoded, _ := json.Marshal(actual)
		currentJSON := string(encoded)
		if referenceJSON == "" {
			referenceJSON = currentJSON
		} else if currentJSON != referenceJSON {
			return fmt.Errorf(
				"NVSwitch firmware versions are inconsistent: switch %s has %s, expected %s",
				id, currentJSON, referenceJSON,
			)
		}
	}

	log.Info().
		Int("switch_count", len(target.ComponentIDs)).
		Str("firmware_versions", referenceJSON).
		Msg("All NVSwitch firmware versions are consistent")
	return nil
}

func matchesAnyDesired(actual map[string]string, entries []*pb.DesiredFirmwareVersionEntry) bool {
	for _, entry := range entries {
		if firmwareVersionsMatch(entry.GetComponentVersions(), actual) {
			return true
		}
	}
	return false
}

func firmwareVersionsMatch(desired, actual map[string]string) bool {
	for k, v := range desired {
		if actual[k] != v {
			return false
		}
	}
	return true
}

// GetFirmwareStatus returns the current status of firmware updates for the target components.
// Core may return multiple sub-component statuses (BMC/CPLD/BIOS/NVOS) per switch, so we
// aggregate them into a single status per switch UUID.
func (m *Manager) GetFirmwareStatus(ctx context.Context, target common.Target) (map[string]operations.FirmwareUpdateStatus, error) {
	log.Debug().
		Str("components", target.String()).
		Msg("GetFirmwareStatus called for NVSwitch")

	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("target is invalid: %w", err)
	}

	req := &pb.GetComponentFirmwareStatusRequest{
		Target: &pb.GetComponentFirmwareStatusRequest_SwitchIds{
			SwitchIds: switchIDsProto(target.ComponentIDs),
		},
	}

	resp, err := m.nicoClient.GetComponentFirmwareStatus(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetComponentFirmwareStatus failed: %w", err)
	}

	// Group statuses by component ID since Core may return multiple
	// sub-component updates (BMC, CPLD, BIOS, NVOS) for the same switch.
	grouped := make(map[string][]*pb.FirmwareUpdateStatus)
	for _, s := range resp.GetStatuses() {
		compID := s.GetResult().GetComponentId()
		grouped[compID] = append(grouped[compID], s)
	}

	// Ensure every requested component ID is present in the result,
	// even if Core returned no statuses for it. This mirrors the
	// nvswitchmanager path which queries each switch individually.
	result := make(map[string]operations.FirmwareUpdateStatus, len(target.ComponentIDs))
	for _, compID := range target.ComponentIDs {
		result[compID] = aggregateNICoStatuses(compID, grouped[compID])
	}

	return result, nil
}

// aggregateNICoStatuses examines all sub-component firmware statuses for a switch
// and produces a single FirmwareUpdateStatus. Any failure → Failed; all completed →
// Completed; otherwise still in progress.
//
// TODO: Validate that Core returns all expected sub-component statuses (BMC, CPLD,
// BIOS, NVOS) per switch. Currently we cannot verify completeness because the proto
// FirmwareUpdateStatus message does not carry a sub-component type field. Once Core
// exposes that information, we should check that all 4 sub-components are present and
// treat a missing sub-component as incomplete (not Completed).
func aggregateNICoStatuses(compID string, statuses []*pb.FirmwareUpdateStatus) operations.FirmwareUpdateStatus {
	if len(statuses) == 0 {
		return operations.FirmwareUpdateStatus{
			ComponentID: compID,
			State:       operations.FirmwareUpdateStateUnknown,
		}
	}

	allCompleted := true
	var failures []string

	for _, s := range statuses {
		mapped := nicoprovider.MapFirmwareState(s.GetState())
		switch mapped {
		case operations.FirmwareUpdateStateFailed:
			errMsg := s.GetResult().GetError()
			if errMsg == "" {
				errMsg = s.GetState().String()
			}
			failures = append(failures, errMsg)
		case operations.FirmwareUpdateStateCompleted:
			// ok
		default:
			allCompleted = false
		}
	}

	if len(failures) > 0 {
		return operations.FirmwareUpdateStatus{
			ComponentID: compID,
			State:       operations.FirmwareUpdateStateFailed,
			Error:       fmt.Sprintf("firmware update failed for components: %s", strings.Join(failures, "; ")),
		}
	}

	if allCompleted {
		return operations.FirmwareUpdateStatus{
			ComponentID: compID,
			State:       operations.FirmwareUpdateStateCompleted,
		}
	}

	return operations.FirmwareUpdateStatus{
		ComponentID: compID,
		State:       operations.FirmwareUpdateStateQueued,
	}
}
