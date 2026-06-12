// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
)

func isMachineComponentType(t string) bool {
	return t == devicetypes.ComponentTypeToString(devicetypes.ComponentTypeCompute)
}

// ---------------------------------------------------------------------------
// syncMachines: sync machine components against NICo
// ---------------------------------------------------------------------------
//
// NICo API calls (3 round-trips):
//   - GetMachines (FindMachineIds + FindMachinesByIds): serial matching,
//     firmware_version direct-write, and drift comparison data
//   - GetPowerStates: power_state direct-write
//   - GetMachinePositionInfo: position validation fields for drift comparison
//
// Flow:
//  1. DB: get all machine components
//  2. NICo GetMachines: fetch all machine details (reused for steps 3, 5, and drift)
//  3. Match by serial → direct-write external_id
//  4. NICo GetPowerStates: direct-write power_state
//  5. Direct-write firmware_version (from step 2 data)
//  6. NICo GetMachinePositionInfo: compare validation fields, return drifts
//
// Validation fields (compared for drift): slot_id, tray_index, host_id, serial_number
// Direct-write fields (written to DB, not compared): external_id, power_state, firmware_version
func syncMachines(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) (received int, drifts []model.ComponentDrift, rpcOK bool) {
	log.Debug().Msg("Syncing machines...")

	// Step 1: Get all machine components from DB
	allComponents, err := model.GetAllComponents(ctx, pool.DB)
	if err != nil {
		log.Error().Msgf("Unable to retrieve components from db: %v", err)
		return 0, nil, false
	}

	var components []model.Component
	for _, c := range allComponents {
		if isMachineComponentType(c.Type) {
			components = append(components, c)
		}
	}

	if len(components) == 0 {
		return 0, nil, true
	}

	// Step 2: Fetch all machine details from NICo
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

	// Step 3: Direct-write external_id by serial matching
	syncMachineIDs(ctx, pool, allMachineDetails, components)

	// Re-read components to pick up any external_id updates
	allComponents, err = model.GetAllComponents(ctx, pool.DB)
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
		detail, foundDetail := detailByID[externalID]
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
		fieldDiffs := compareMachineFieldsForDrift(comp, detail, posPtr)
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

// syncMachineIDs matches components by serial number against pre-fetched NICo
// machine details and direct-writes the external_id.
func syncMachineIDs(
	ctx context.Context,
	pool *cdb.Session,
	allDetails []nicoapi.MachineDetail,
	components []model.Component,
) {
	containersBySerial := make(map[string]model.Component)
	for _, cur := range components {
		containersBySerial[cur.SerialNumber] = cur
	}

	var toUpdate []model.Component
	for _, cur := range allDetails {
		if cur.ChassisSerial == nil {
			continue
		}
		if container, ok := containersBySerial[*cur.ChassisSerial]; ok {
			if container.ComponentID == nil || *container.ComponentID != cur.MachineID {
				componentID := cur.MachineID
				container.ComponentID = &componentID
				toUpdate = append(toUpdate, container)
			}
		}
	}

	if len(toUpdate) > 0 {
		if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
			for _, cur := range toUpdate {
				if err := cur.SetComponentIDBySerial(ctx, tx); err != nil {
					return fmt.Errorf("Unable to update machine ID: %w", err)
				}
			}
			return nil
		}); err != nil {
			log.Error().Msgf("Unable to update components with serial: %v", err)
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
// Validation fields: slot_id, tray_index, host_id, serial_number.
func compareMachineFieldsForDrift(
	expected *model.Component,
	actual nicoapi.MachineDetail,
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

	// Compare serial_number (chassis_serial)
	if actual.ChassisSerial != nil && expected.SerialNumber != *actual.ChassisSerial {
		diffs = append(diffs, model.FieldDiff{
			FieldName:     driftFieldSerialNumber,
			ExpectedValue: expected.SerialNumber,
			ActualValue:   *actual.ChassisSerial,
		})
	}

	return diffs
}
