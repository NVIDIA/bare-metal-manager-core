// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/common/utils"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

func isMachineComponentType(t string) bool {
	return t == devicetypes.ComponentTypeToString(devicetypes.ComponentTypeCompute)
}

// ---------------------------------------------------------------------------
// syncMachines: sync machine components against NICo
// ---------------------------------------------------------------------------
//
// NICo API calls (3 round-trips):
//   - GetMachines (FindMachineIds + FindMachinesByIds): BMC-MAC linking,
//     firmware_version and controller_state direct-write, plus
//     missing_in_expected detection
//   - GetPowerStates: power_state direct-write
//   - GetMachinePositionInfo: position validation fields for drift comparison
//
// Flow:
//  1. DB: get all compute components (with BMCs)
//  2. NICo GetMachines: fetch all machine details (linking, firmware, state, missing_in_expected)
//  3. Link by BMC MAC (from step 2 data) → direct-write external_id
//  4. NICo GetPowerStates: direct-write power_state
//  5. Direct-write firmware_version (from step 2 data)
//  6. NICo GetMachinePositionInfo: compare validation fields, return drifts
//
// Correlation/identity key: BMC MAC address (serial number is not used).
// Validation fields (compared for drift): slot_id, tray_index, host_id
// Direct-write fields (written to DB, not compared): external_id, power_state, firmware_version
func syncMachines(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) (received int, drifts []model.ComponentDrift, rpcOK bool) {
	log.Debug().Msg("Syncing machines...")

	// Step 1: Get all compute components (with BMCs) from DB
	components, err := model.GetComponentsByType(ctx, pool.DB, devicetypes.ComponentTypeCompute)
	if err != nil {
		log.Error().Msgf("Unable to retrieve compute components from db: %v", err)
		return 0, nil, false
	}

	if len(components) == 0 {
		return 0, nil, true
	}

	// Step 2: Fetch all machine details from NICo. This is the single source
	// for BMC-MAC linking, firmware_version, controller_state, and
	// missing_in_expected detection — a failure here means we can't trust this
	// cycle, so preserve prior state rather than writing a partial view.
	allMachineDetails, err := nicoClient.GetMachines(ctx)
	if err != nil {
		log.Error().Msgf("Unable to retrieve machine details from NICo: %v", err)
		return 0, nil, false
	}
	received = len(allMachineDetails)

	detailByID := make(map[string]nicoapi.MachineDetail)
	for _, d := range allMachineDetails {
		detailByID[d.MachineID] = d
	}

	// Step 3: Direct-write external_id by BMC MAC matching
	syncMachineIDs(ctx, pool, allMachineDetails, components)

	// Re-read components to pick up any external_id updates
	allComponents, err := model.GetAllComponents(ctx, pool.DB)
	if err != nil {
		log.Error().Msgf("Unable to re-read components from db after machine ID update: %v", err)
		return received, nil, false
	}
	components = components[:0]
	for _, c := range allComponents {
		if isMachineComponentType(c.Type) {
			components = append(components, c)
		}
	}

	// Build lookup maps for matched components
	var machineIDs []string
	componentsByExternalID := make(map[string]*model.Component)
	for i := range components {
		comp := &components[i]
		if comp.ComponentID != nil && *comp.ComponentID != "" {
			machineIDs = append(machineIDs, *comp.ComponentID)
			componentsByExternalID[*comp.ComponentID] = comp
		}
	}

	if len(machineIDs) == 0 {
		return received, buildDriftsForUnmatchedComponents(components, allMachineDetails), true
	}

	// Step 4: Direct-write power_state (requires separate NICo API)
	syncPowerStates(ctx, pool, nicoClient, machineIDs, componentsByExternalID)

	// Step 5: Direct-write firmware_version (from pre-fetched details, no extra API call)
	syncFirmwareVersions(ctx, pool, detailByID, componentsByExternalID)

	// Step 5b: Direct-write derived ComponentOperationStatus (from pre-fetched detail.State).
	syncMachineStatuses(ctx, pool, detailByID, componentsByExternalID)

	// Step 6: Fetch positions and build drift records (requires separate NICo API)
	machinePositions, err := nicoClient.GetMachinePositionInfo(ctx, machineIDs)
	if err != nil {
		log.Error().Msgf("Unable to retrieve machine positions from NICo: %v", err)
		return received, nil, false
	}

	positionByID := make(map[string]nicoapi.MachinePosition)
	for _, p := range machinePositions {
		positionByID[p.MachineID] = p
	}

	now := time.Now()

	for i := range components {
		comp := &components[i]

		if comp.ComponentID == nil || *comp.ComponentID == "" {
			compID := comp.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  nil,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
			continue
		}

		externalID := *comp.ComponentID
		_, foundDetail := detailByID[externalID]
		position, foundPosition := positionByID[externalID]

		if !foundDetail {
			compID := comp.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  &externalID,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
			continue
		}

		var posPtr *nicoapi.MachinePosition
		if foundPosition {
			posPtr = &position
		}
		fieldDiffs := compareMachineFieldsForDrift(comp, posPtr)
		if len(fieldDiffs) > 0 {
			compID := comp.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  &externalID,
				DriftType:   model.DriftTypeMismatch,
				Diffs:       fieldDiffs,
				CheckedAt:   now,
			})
		}
	}

	// Detect missing_in_expected: machines in NICo but not in local DB
	for _, detail := range allMachineDetails {
		if _, found := componentsByExternalID[detail.MachineID]; !found {
			extID := detail.MachineID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: nil,
				ExternalID:  &extID,
				DriftType:   model.DriftTypeMissingInExpected,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
		}
	}

	log.Info().Msgf("Machine sync: %d drift(s) out of %d component(s)", len(drifts), len(components))
	return received, drifts, true
}

// buildDriftsForUnmatchedComponents returns missing_in_actual drifts for all
// components that have no external_id, plus missing_in_expected drifts for
// every NICo machine (since no DB component has an external_id, none can
// match).
func buildDriftsForUnmatchedComponents(
	components []model.Component,
	allMachineDetails []nicoapi.MachineDetail,
) []model.ComponentDrift {
	now := time.Now()
	var drifts []model.ComponentDrift
	for i := range components {
		if components[i].ComponentID == nil || *components[i].ComponentID == "" {
			compID := components[i].ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
		}
	}
	for _, detail := range allMachineDetails {
		extID := detail.MachineID
		drifts = append(drifts, model.ComponentDrift{
			ComponentID: nil,
			ExternalID:  &extID,
			DriftType:   model.DriftTypeMissingInExpected,
			Diffs:       []model.FieldDiff{},
			CheckedAt:   now,
		})
	}
	return drifts
}

// syncMachineIDs matches components by BMC MAC address against pre-fetched NICo
// machine details and direct-writes the external_id. BMC MAC is the stable
// identity Core populates on the discovered machine (Machine.bmc_info.mac,
// surfaced as MachineDetail.BmcMac), so linking no longer depends on serial
// number.
func syncMachineIDs(
	ctx context.Context,
	pool *cdb.Session,
	allDetails []nicoapi.MachineDetail,
	components []model.Component,
) {
	// Index discovered machines by normalized BMC MAC → Core MachineId.
	// Restrict to HOST machines: a compute component owns both a host BMC and
	// a DPU BMC, and Core exposes the DPU as its own MachineDetail whose BmcMac
	// is that DPU BMC. Including DPUs here would let a compute component's DPU
	// BMC resolve to the DPU's machine id instead of the host's.
	machineIDByBmcMac := make(map[string]string)
	for _, cur := range allDetails {
		if cur.MachineType != corev1.MachineType_HOST.String() {
			continue
		}
		if cur.BmcMac != "" && cur.MachineID != "" {
			machineIDByBmcMac[utils.NormalizeMAC(cur.BmcMac)] = cur.MachineID
		}
	}

	var toUpdate []model.Component
	for _, comp := range components {
		if len(comp.BMCs) == 0 {
			log.Error().
				Str("component_id", comp.ID.String()).
				Str("rack_id", comp.RackID.String()).
				Msg("Compute component has no BMCs; skipping")
			continue
		}
		// A compute component can legitimately expose several BMCs (e.g. host
		// and DPU). Core advertises only one of them as MachineDetail.BmcMac,
		// so try each BMC and link on the first that resolves to a machine.
		for _, bmc := range comp.BMCs {
			bmcMacAddr, err := net.ParseMAC(bmc.MacAddress)
			if err != nil {
				log.Error().
					Str("component_id", comp.ID.String()).
					Str("rack_id", comp.RackID.String()).
					Str("bmc_mac_address", bmc.MacAddress).
					Msg("Compute component has invalid BMC MAC address; skipping")
				continue
			}
			machineID, ok := machineIDByBmcMac[bmcMacAddr.String()]
			if !ok {
				continue
			}
			if comp.ComponentID == nil || *comp.ComponentID != machineID {
				componentID := machineID
				comp.ComponentID = &componentID
				toUpdate = append(toUpdate, comp)
			}
			break
		}
	}

	if len(toUpdate) > 0 {
		if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
			for _, cur := range toUpdate {
				if err := cur.Patch(ctx, tx); err != nil {
					return fmt.Errorf("Unable to update machine ID: %w", err)
				}
			}
			return nil
		}); err != nil {
			log.Error().Msgf("Unable to update components with BMC MAC: %v", err)
			return
		}

		log.Info().Msgf("Updated %d machine ID(s)", len(toUpdate))
	}
}

// syncPowerStates fetches power states from NICo and direct-writes to component table.
func syncPowerStates(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
	machineIDs []string,
	componentsByExternalID map[string]*model.Component,
) {
	machines, err := nicoClient.GetPowerStates(ctx, machineIDs)
	if err != nil {
		log.Error().Msgf("Unable to retrieve power states from nico-core-api: %v", err)
		return
	}

	var toUpdate []model.Component
	for _, cur := range machines {
		if comp, ok := componentsByExternalID[cur.MachineID]; ok {
			if comp.PowerState == nil || *comp.PowerState != cur.PowerState {
				powerState := cur.PowerState
				comp.PowerState = &powerState
				toUpdate = append(toUpdate, *comp)
			}
		}
	}

	if len(toUpdate) > 0 {
		if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
			for _, cur := range toUpdate {
				if err := cur.SetPowerStateByComponentID(ctx, tx); err != nil {
					return fmt.Errorf("Unable to update power state: %w", err)
				}
			}
			return nil
		}); err != nil {
			log.Error().Msgf("Unable to update components with power state: %v", err)
		}
	}
}

// syncFirmwareVersions direct-writes firmware_version from NICo machine details to component table.
func syncFirmwareVersions(
	ctx context.Context,
	pool *cdb.Session,
	detailByID map[string]nicoapi.MachineDetail,
	componentsByExternalID map[string]*model.Component,
) {
	var toUpdate []model.Component
	for machineID, detail := range detailByID {
		if comp, ok := componentsByExternalID[machineID]; ok {
			if detail.FirmwareVersion != "" && comp.FirmwareVersion != detail.FirmwareVersion {
				comp.FirmwareVersion = detail.FirmwareVersion
				toUpdate = append(toUpdate, *comp)
			}
		}
	}

	if len(toUpdate) > 0 {
		if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
			for _, cur := range toUpdate {
				if err := cur.SetFirmwareVersionByComponentID(ctx, tx); err != nil {
					return fmt.Errorf("unable to update firmware version: %w", err)
				}
			}
			return nil
		}); err != nil {
			log.Error().Msgf("Unable to update components with firmware version: %v", err)
		}
	}
}

// syncMachineStatuses derives a types.ComponentOperationStatus from each machine's
// controller_state (already fetched as detail.State) and direct-writes it to
// the component row. Only rows whose status actually changed are updated.
func syncMachineStatuses(
	ctx context.Context,
	pool *cdb.Session,
	detailByID map[string]nicoapi.MachineDetail,
	componentsByExternalID map[string]*model.Component,
) {
	statesByID := make(map[string]string, len(detailByID))
	for id, d := range detailByID {
		if d.State != "" {
			statesByID[id] = d.State
		}
	}
	persistComponentOperationStatuses(ctx, pool, types.ComponentTypeCompute, statesByID, componentsByExternalID)
}

// compareMachineFieldsForDrift compares validation fields between expected (DB) and actual (NICo).
// Validation fields: slot_id, tray_index, host_id. Serial number is not compared:
// correlation and drift are keyed on BMC MAC, and a hardware swap surfaces as a
// BMC-MAC presence change (missing_in_actual / missing_in_expected).
func compareMachineFieldsForDrift(
	expected *model.Component,
	position *nicoapi.MachinePosition,
) []model.FieldDiff {
	var diffs []model.FieldDiff

	if position != nil {
		if position.PhysicalSlotNum != nil && expected.SlotID != int(*position.PhysicalSlotNum) {
			diffs = append(diffs, model.FieldDiff{
				FieldName:     "slot_id",
				ExpectedValue: fmt.Sprintf("%d", expected.SlotID),
				ActualValue:   fmt.Sprintf("%d", *position.PhysicalSlotNum),
			})
		}
		if position.ComputeTrayIndex != nil && expected.TrayIndex != int(*position.ComputeTrayIndex) {
			diffs = append(diffs, model.FieldDiff{
				FieldName:     "tray_index",
				ExpectedValue: fmt.Sprintf("%d", expected.TrayIndex),
				ActualValue:   fmt.Sprintf("%d", *position.ComputeTrayIndex),
			})
		}
		if position.TopologyID != nil && expected.HostID != int(*position.TopologyID) {
			diffs = append(diffs, model.FieldDiff{
				FieldName:     "host_id",
				ExpectedValue: fmt.Sprintf("%d", expected.HostID),
				ActualValue:   fmt.Sprintf("%d", *position.TopologyID),
			})
		}
	} else {
		if expected.SlotID != 0 {
			diffs = append(diffs, model.FieldDiff{
				FieldName:     "slot_id",
				ExpectedValue: fmt.Sprintf("%d", expected.SlotID),
				ActualValue:   "<missing>",
			})
		}
		if expected.TrayIndex != 0 {
			diffs = append(diffs, model.FieldDiff{
				FieldName:     "tray_index",
				ExpectedValue: fmt.Sprintf("%d", expected.TrayIndex),
				ActualValue:   "<missing>",
			})
		}
		if expected.HostID != 0 {
			diffs = append(diffs, model.FieldDiff{
				FieldName:     "host_id",
				ExpectedValue: fmt.Sprintf("%d", expected.HostID),
				ActualValue:   "<missing>",
			})
		}
	}

	return diffs
}
