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

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/common/utils"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/nsmapi"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/psmapi"
	cmconfig "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/config"
	nicoprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/nico"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

const driftFieldSerialNumber = "serial_number"

// runInventoryOne is a single iteration for RunInventory.
// It syncs each resource type against its external source, collects all drifts,
// and persists them in one shot.
func runInventoryOne(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
	psmClient psmapi.Client,
	nsmClient nsmapi.Client,
	cmConfig cmconfig.Config,
) {
	var allDrifts []model.ComponentDrift

	// Sync machines against NICo
	machineDrifts := syncMachines(ctx, pool, nicoClient)
	allDrifts = append(allDrifts, machineDrifts...)

	// Sync NVSwitches: dispatch based on configured component manager
	var nvSwitchDrifts []model.ComponentDrift
	if cmConfig.ComponentManagers[devicetypes.ComponentTypeNVSwitch] == nicoprovider.ProviderName {
		nvSwitchDrifts = syncNVSwitchesNICo(ctx, pool, nicoClient)
	} else {
		nvSwitchDrifts = syncNVSwitches(ctx, pool, nicoClient, nsmClient)
	}
	allDrifts = append(allDrifts, nvSwitchDrifts...)

	// Sync powershelves: dispatch based on configured component manager
	var powershelfDrifts []model.ComponentDrift
	if cmConfig.ComponentManagers[devicetypes.ComponentTypePowerShelf] == nicoprovider.ProviderName {
		powershelfDrifts = syncPowershelvesNICo(ctx, pool, nicoClient)
	} else {
		powershelfDrifts = syncPowershelves(ctx, pool, nicoClient, psmClient)
	}
	allDrifts = append(allDrifts, powershelfDrifts...)

	// Persist all drifts atomically (replace entire table)
	if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return model.ReplaceAllDrifts(ctx, tx, allDrifts)
	}); err != nil {
		log.Error().Msgf("Unable to persist drift records: %v", err)
	} else {
		log.Info().Msgf("Drift detection complete: %d drift(s) detected", len(allDrifts))
	}
}

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
) []model.ComponentDrift {
	log.Debug().Msg("Syncing machines...")

	// Step 1: Get all machine components from DB
	allComponents, err := model.GetAllComponents(ctx, pool.DB)
	if err != nil {
		log.Error().Msgf("Unable to retrieve components from db: %v", err)
		return nil
	}

	var components []model.Component
	for _, c := range allComponents {
		if isMachineComponentType(c.Type) {
			components = append(components, c)
		}
	}

	if len(components) == 0 {
		return nil
	}

	// Step 2: Fetch all machine details from NICo
	allMachineDetails, err := nicoClient.GetMachines(ctx)
	if err != nil {
		log.Error().Msgf("Unable to retrieve machine details from NICo: %v", err)
		return nil
	}

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
		return nil
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
		return buildDriftsForUnmatchedComponents(components, allMachineDetails)
	}

	// Step 4: Direct-write power_state (requires separate NICo API)
	syncPowerStates(ctx, pool, nicoClient, machineIDs, componentsByExternalID)

	// Step 5: Direct-write firmware_version (from pre-fetched details, no extra API call)
	syncFirmwareVersions(ctx, pool, detailByID, componentsByExternalID)

	// Step 6: Fetch positions and build drift records (requires separate NICo API)
	machinePositions, err := nicoClient.GetMachinePositionInfo(ctx, machineIDs)
	if err != nil {
		log.Error().Msgf("Unable to retrieve machine positions from NICo: %v", err)
		return nil
	}

	positionByID := make(map[string]nicoapi.MachinePosition)
	for _, p := range machinePositions {
		positionByID[p.MachineID] = p
	}

	now := time.Now()
	var drifts []model.ComponentDrift

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
	return drifts
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

// ---------------------------------------------------------------------------
// syncNVSwitches: sync NVSwitch components against NSM
// ---------------------------------------------------------------------------
//
// NSM API calls (1-2 round-trips):
//   - GetNVSwitches: get registered switches (firmware_version direct-write)
//   - RegisterNVSwitches: register un-registered DHCPed switches
//
// NICo API calls (2 round-trips):
//   - GetAllExpectedSwitches: get credentials + NVOS MAC from metadata
//   - FindInterfaces: check which BMCs/NVOS hosts have DHCPed
//
// Flow:
//  1. DB: get all NVSwitch components with BMCs
//  2. NSM GetNVSwitches: get registered switches
//  3. NICo GetAllExpectedSwitches: get credentials and NVOS MAC (metadata label "host_mac_address")
//  4. NICo FindInterfaces: check which BMCs/NVOS hosts have DHCPed
//  5. Direct-write: firmware_version (from NSM)
//  6. Register un-registered DHCPed switches with NSM (BMC + NVOS subsystems)
//  7. Return drifts (missing_in_actual for unregistered switches)

func syncNVSwitches(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
	nsmClient nsmapi.Client,
) []model.ComponentDrift {
	if nsmClient == nil {
		log.Debug().Msg("NSM client not available, skipping NVSwitch sync")
		return nil
	}

	log.Debug().Msg("Syncing NV switches...")

	// Step 1: Get all NVSwitch components with their BMCs
	expectedSwitches, err := model.GetComponentsByType(ctx, pool.DB, devicetypes.ComponentTypeNVSwitch)
	if err != nil {
		log.Error().Msgf("Unable to retrieve NVSwitch components from db: %v", err)
		return nil
	}

	if len(expectedSwitches) == 0 {
		return nil
	}

	// Build map from BMC MAC to component.
	// Each NVSwitch should have exactly one BMC.
	expectedByBmcMac := make(map[string]*model.Component)
	for i := range expectedSwitches {
		sw := &expectedSwitches[i]
		if len(sw.BMCs) != 1 {
			log.Error().Msgf("NVSwitch %s has %d BMCs, expected exactly 1; skipping", sw.SerialNumber, len(sw.BMCs))
			continue
		}

		bmcMacAddr, err := net.ParseMAC(sw.BMCs[0].MacAddress)
		if err != nil || bmcMacAddr == nil {
			log.Error().Msgf("NVSwitch %s has invalid BMC MAC address %s; skipping", sw.SerialNumber, sw.BMCs[0].MacAddress)
			continue
		}

		expectedByBmcMac[bmcMacAddr.String()] = sw
	}

	// Step 2: Get registered switches from NSM
	registeredSwitches, err := nsmClient.GetNVSwitches(ctx, nil)
	if err != nil {
		log.Error().Msgf("Unable to retrieve registered switches from NSM: %v", err)
		return nil
	}

	registeredByMac := make(map[string]nsmapi.NVSwitchTray)
	for _, sw := range registeredSwitches {
		if sw.BMCMACAddress != "" {
			registeredByMac[utils.NormalizeMAC(sw.BMCMACAddress)] = sw
		}
	}

	// Step 3: Get expected switches from NICo for NVOS MAC metadata
	nicoByBmcMac, err := nicoClient.GetAllExpectedSwitches(ctx)
	if err != nil {
		log.Error().Msgf("Unable to retrieve expected switches from nico-core-api: %v", err)
		return nil
	}

	// Step 4: Get machine interfaces from NICo to check DHCP status
	interfacesByMac, err := nicoClient.FindInterfaces(ctx)
	if err != nil {
		log.Error().Msgf("Unable to retrieve interfaces from nico-core-api: %v", err)
		return nil
	}

	// Steps 5-7: Process each expected NVSwitch
	now := time.Now()
	var drifts []model.ComponentDrift
	var toRegister []nsmapi.RegisterNVSwitchRequest

	for bmcMac, nvswitch := range expectedByBmcMac {
		nvswitchID := nvswitch.ID.String()

		// Already registered with NSM — direct-write external_id and firmware_version
		if registeredSW, isRegistered := registeredByMac[bmcMac]; isRegistered {
			needsUpdate := false

			if registeredSW.UUID != "" && (nvswitch.ComponentID == nil || *nvswitch.ComponentID != registeredSW.UUID) {
				nsmUUID := registeredSW.UUID
				nvswitch.ComponentID = &nsmUUID
				needsUpdate = true
				log.Info().Msgf("NVSwitch %s (BMC %s): setting external_id to NSM UUID %s", nvswitchID, bmcMac, nsmUUID)
			}

			if registeredSW.BMCFirmware != "" && nvswitch.FirmwareVersion != registeredSW.BMCFirmware {
				nvswitch.FirmwareVersion = registeredSW.BMCFirmware
				needsUpdate = true
				log.Info().Msgf("NVSwitch %s (BMC %s): updating firmware version to %s", nvswitchID, bmcMac, registeredSW.BMCFirmware)
			}

			if needsUpdate {
				if err := nvswitch.Patch(ctx, pool.DB); err != nil {
					log.Error().Msgf("NVSwitch %s (BMC %s): unable to update: %v", nvswitchID, bmcMac, err)
				}
			}

			// Drift detection: compare chassis serial from NSM against expected serial in DB
			if registeredSW.ChassisSerial != "" && nvswitch.SerialNumber != registeredSW.ChassisSerial {
				compID := nvswitch.ID
				drifts = append(drifts, model.ComponentDrift{
					ComponentID: &compID,
					ExternalID:  &registeredSW.UUID,
					DriftType:   model.DriftTypeMismatch,
					Diffs: []model.FieldDiff{{
						FieldName:     driftFieldSerialNumber,
						ExpectedValue: nvswitch.SerialNumber,
						ActualValue:   registeredSW.ChassisSerial,
					}},
					CheckedAt: now,
				})
			}

			continue
		}

		// Not registered with NSM — check if BMC has DHCPed
		bmcIface, found := interfacesByMac[bmcMac]
		if !found || len(bmcIface.Addresses) == 0 {
			log.Warn().Msgf("NVSwitch %s (BMC %s): BMC has not DHCPed yet", nvswitchID, bmcMac)
			compID := nvswitch.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  nil,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
			continue
		}

		if len(bmcIface.Addresses) > 1 {
			log.Error().Msgf("NVSwitch %s (BMC %s): multiple IP addresses assigned (%v), skipping registration", nvswitchID, bmcMac, bmcIface.Addresses)
			continue
		}

		bmcIP := bmcIface.Addresses[0]

		nicoES, hasNICoInfo := nicoByBmcMac[bmcMac]
		if !hasNICoInfo {
			log.Warn().Msgf("NVSwitch %s (BMC %s): not found in NICo expected switches, skipping registration", nvswitchID, bmcMac)
			continue
		}

		nvosMacRaw, hasNvosMac := nicoES.Metadata["host_mac_address"]
		if !hasNvosMac || nvosMacRaw == "" {
			log.Warn().Msgf("NVSwitch %s (BMC %s): no host_mac_address in NICo metadata, skipping registration", nvswitchID, bmcMac)
			continue
		}
		nvosMac := utils.NormalizeMAC(nvosMacRaw)

		nvosIface, nvosFound := interfacesByMac[nvosMac]
		if !nvosFound || len(nvosIface.Addresses) == 0 {
			log.Warn().Msgf("NVSwitch %s (BMC %s): NVOS %s has not DHCPed yet, skipping registration", nvswitchID, bmcMac, nvosMac)
			compID := nvswitch.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  nil,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
			continue
		}

		if len(nvosIface.Addresses) > 1 {
			log.Error().Msgf("NVSwitch %s (BMC %s): NVOS %s has multiple IP addresses (%v), skipping registration", nvswitchID, bmcMac, nvosMac, nvosIface.Addresses)
			continue
		}

		nvosIP := nvosIface.Addresses[0]

		log.Info().Msgf("NVSwitch %s (BMC %s, IP %s) + NVOS %s (IP %s): registering with NSM", nvswitchID, bmcMac, bmcIP, nvosMac, nvosIP)

		toRegister = append(toRegister, nsmapi.RegisterNVSwitchRequest{
			BMCMACAddress:  bmcMac,
			BMCIPAddress:   bmcIP,
			NVOSMACAddress: nvosMac,
			NVOSIPAddress:  nvosIP,
		})
	}

	// Register un-registered switches with NSM
	if len(toRegister) > 0 {
		responses, err := nsmClient.RegisterNVSwitches(ctx, toRegister)
		if err != nil {
			log.Error().Msgf("Unable to register NVSwitches with NSM: %v", err)
		} else {
			for _, resp := range responses {
				if resp.Status != nsmapi.StatusSuccess {
					log.Error().Msgf("Failed to register NVSwitch with NSM (uuid=%s): %s", resp.UUID, resp.Error)
				} else if resp.IsNew {
					log.Info().Msgf("Successfully registered new NVSwitch with NSM (uuid=%s)", resp.UUID)
				} else {
					log.Debug().Msgf("NVSwitch was already registered with NSM (uuid=%s)", resp.UUID)
				}
			}
		}
	}

	log.Info().Msgf("NVSwitch sync: %d drift(s) out of %d expected", len(drifts), len(expectedSwitches))
	return drifts
}

// ---------------------------------------------------------------------------
// syncPowershelves: sync PowerShelf components against PSM
// ---------------------------------------------------------------------------
//
// Flow:
//  1. DB: get all PowerShelf components with BMCs
//  2. PSM GetPowershelves: get registered powershelves
//  3. NICo FindInterfaces: check which PMCs have DHCPed
//  4. Direct-write: firmware_version, power_state (from PSM)
//  5. Register un-registered DHCPed powershelves with PSM
//  6. Return drifts (missing_in_actual for unregistered powershelves)

// Default factory credentials for powershelf BMCs
const (
	powershelfDefaultUsername = "root"
	powershelfDefaultPassword = "0penBmc"
)

func syncPowershelves(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
	psmClient psmapi.Client,
) []model.ComponentDrift {
	if psmClient == nil {
		log.Debug().Msg("PSM client not available, skipping powershelf sync")
		return nil
	}

	log.Debug().Msg("Syncing powershelves...")

	// Step 1: Get all PowerShelf components with their PMCs
	expectedPowershelves, err := model.GetComponentsByType(ctx, pool.DB, devicetypes.ComponentTypePowerShelf)
	if err != nil {
		log.Error().Msgf("Unable to retrieve powershelf components from db: %v", err)
		return nil
	}

	if len(expectedPowershelves) == 0 {
		return nil
	}

	// Build map from PMC MAC to component
	// Each powershelf should have exactly one PMC (BMC)
	expectedByPmcMac := make(map[string]*model.Component)
	for i := range expectedPowershelves {
		ps := &expectedPowershelves[i]
		if len(ps.BMCs) != 1 {
			log.Error().Msgf("Powershelf %s has %d BMCs, expected exactly 1; skipping", ps.SerialNumber, len(ps.BMCs))
			continue
		}

		// Validate PMC MAC address
		pmcMacAddr, err := net.ParseMAC(ps.BMCs[0].MacAddress)
		if err != nil || pmcMacAddr == nil {
			log.Error().Msgf("Powershelf %s has invalid BMC MAC address %s; skipping", ps.SerialNumber, ps.BMCs[0].MacAddress)
			continue
		}

		expectedByPmcMac[pmcMacAddr.String()] = ps
	}

	// Get list of expected PMC MACs
	expectedPmcMacs := make([]string, 0, len(expectedByPmcMac))
	for mac := range expectedByPmcMac {
		expectedPmcMacs = append(expectedPmcMacs, mac)
	}

	// Step 2: Get registered powershelves from PSM
	registeredPowershelves, err := psmClient.GetPowershelves(ctx, expectedPmcMacs)
	if err != nil {
		log.Error().Msgf("Unable to retrieve registered powershelves from PSM: %v", err)
		return nil
	}

	registeredByMac := make(map[string]psmapi.PowerShelf)
	for _, ps := range registeredPowershelves {
		registeredByMac[utils.NormalizeMAC(ps.PMC.MACAddress)] = ps
	}

	// Step 3: Get machine interfaces from NICo to check DHCP status
	interfacesByMac, err := nicoClient.FindInterfaces(ctx)
	if err != nil {
		log.Error().Msgf("Unable to retrieve interfaces from nico-core-api: %v", err)
		return nil
	}

	// Steps 4 & 5: Process each expected powershelf
	now := time.Now()
	var drifts []model.ComponentDrift
	var toRegister []psmapi.RegisterPowershelfRequest

	for pmcMac, powershelf := range expectedByPmcMac {
		// Already registered with PSM — direct-write external_id, firmware_version + power_state
		if registeredPS, isRegistered := registeredByMac[pmcMac]; isRegistered {
			needsUpdate := false

			if powershelf.ComponentID == nil || *powershelf.ComponentID != pmcMac {
				extID := pmcMac
				powershelf.ComponentID = &extID
				needsUpdate = true
				log.Info().Msgf("Setting external_id for powershelf %s to PMC MAC", pmcMac)
			}

			// Direct-write: firmware_version
			if registeredPS.PMC.FirmwareVersion != "" && powershelf.FirmwareVersion != registeredPS.PMC.FirmwareVersion {
				powershelf.FirmwareVersion = registeredPS.PMC.FirmwareVersion
				needsUpdate = true
				log.Info().Msgf("Updating firmware version for powershelf %s to %s", pmcMac, registeredPS.PMC.FirmwareVersion)
			}

			// Direct-write: power_state (derived from PSUs)
			// All on → On, All off → Off, Mix or no PSUs → Unknown
			allOn := len(registeredPS.PSUs) > 0
			allOff := len(registeredPS.PSUs) > 0
			for _, psu := range registeredPS.PSUs {
				if psu.PowerState {
					allOff = false
				} else {
					allOn = false
				}
			}
			psuPowerState := nicoapi.PowerStateUnknown
			if allOn {
				psuPowerState = nicoapi.PowerStateOn
			} else if allOff {
				psuPowerState = nicoapi.PowerStateOff
			}
			if powershelf.PowerState == nil || *powershelf.PowerState != psuPowerState {
				powershelf.PowerState = &psuPowerState
				needsUpdate = true
				log.Info().Msgf("Updating power state for powershelf %s to %v", pmcMac, psuPowerState)
			}

			if needsUpdate {
				if err := powershelf.Patch(ctx, pool.DB); err != nil {
					log.Error().Msgf("Unable to update powershelf %s: %v", pmcMac, err)
				}
			}

			// TODO: add field-level drift detection for powershelves (serial_number, etc.)
			continue
		}

		// Not registered with PSM — check if DHCPed, register if possible
		iface, found := interfacesByMac[pmcMac]
		if !found || len(iface.Addresses) == 0 {
			// PMC hasn't DHCPed yet — record as missing_in_actual
			log.Warn().Msgf("Powershelf PMC %s has not DHCPed yet", pmcMac)
			compID := powershelf.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  nil,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
			continue
		}

		// Check for unexpected multiple IP addresses
		if len(iface.Addresses) > 1 {
			log.Error().Msgf("Powershelf PMC %s has multiple IP addresses assigned (%v), skipping registration", pmcMac, iface.Addresses)
			continue
		}

		ipAddress := iface.Addresses[0]
		log.Info().Msgf("Powershelf PMC %s has DHCPed with IP %s, registering with PSM", pmcMac, ipAddress)

		toRegister = append(toRegister, psmapi.RegisterPowershelfRequest{
			PMCMACAddress:  pmcMac,
			PMCIPAddress:   ipAddress,
			PMCVendor:      psmapi.PMCVendorLiteon,
			PMCCredentials: psmapi.Credentials{Username: powershelfDefaultUsername, Password: powershelfDefaultPassword},
		})
	}

	// Register un-registered powershelves with PSM
	if len(toRegister) > 0 {
		responses, err := psmClient.RegisterPowershelves(ctx, toRegister)
		if err != nil {
			log.Error().Msgf("Unable to register powershelves with PSM: %v", err)
		} else {
			for _, resp := range responses {
				if resp.Status != psmapi.StatusSuccess {
					log.Error().Msgf("Failed to register powershelf %s with PSM: %s", resp.PMCMACAddress, resp.Error)
				} else if resp.IsNew {
					log.Info().Msgf("Successfully registered new powershelf %s with PSM", resp.PMCMACAddress)
				} else {
					log.Debug().Msgf("Powershelf %s was already registered with PSM", resp.PMCMACAddress)
				}
			}
		}
	}

	log.Info().Msgf("Powershelf sync: %d drift(s) out of %d expected", len(drifts), len(expectedPowershelves))
	return drifts
}

// ---------------------------------------------------------------------------
// syncNVSwitchesNICo: sync NVSwitch components via Core (NICo)
// ---------------------------------------------------------------------------
//
// Uses Core's NICo API instead of talking directly to NSM.
// Core's NSM backend auto-registers switches, so no registration step is needed.
//
// NICo API calls (2 round-trips):
//   - GetAllExpectedSwitchesLinked: discover Core switch IDs by BMC MAC
//   - GetComponentInventory: get firmware, serial, power state from site explorer
//
// Flow:
//  1. DB: get all NVSwitch components with BMCs
//  2. NICo GetAllExpectedSwitchesLinked: map BMC MAC → Core SwitchId
//  3. Direct-write external_id (Core's SwitchId) for matched components
//  4. NICo GetComponentInventory: extract firmware_version, serial_number, power_state
//  5. Direct-write inventory fields to DB
//  6. Return drifts (missing_in_actual for components without a Core SwitchId)

func syncNVSwitchesNICo(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) []model.ComponentDrift {
	log.Debug().Msg("Syncing NV switches via NICo...")

	expectedSwitches, err := model.GetComponentsByType(ctx, pool.DB, devicetypes.ComponentTypeNVSwitch)
	if err != nil {
		log.Error().Msgf("Unable to retrieve NVSwitch components from db: %v", err)
		return nil
	}

	if len(expectedSwitches) == 0 {
		return nil
	}

	expectedByBmcMac := make(map[string]*model.Component)
	for i := range expectedSwitches {
		sw := &expectedSwitches[i]
		if len(sw.BMCs) != 1 {
			log.Error().Msgf("NVSwitch %s has %d BMCs, expected exactly 1; skipping", sw.SerialNumber, len(sw.BMCs))
			continue
		}
		bmcMacAddr, err := net.ParseMAC(sw.BMCs[0].MacAddress)
		if err != nil || bmcMacAddr == nil {
			log.Error().Msgf("NVSwitch %s has invalid BMC MAC address %s; skipping", sw.SerialNumber, sw.BMCs[0].MacAddress)
			continue
		}
		expectedByBmcMac[bmcMacAddr.String()] = sw
	}

	// ID discovery: map BMC MAC → Core SwitchId
	linked, err := nicoClient.GetAllExpectedSwitchesLinked(ctx)
	if err != nil {
		log.Error().Msgf("Unable to retrieve linked expected switches from NICo: %v", err)
		return nil
	}

	linkedByMac := make(map[string]nicoapi.LinkedExpectedSwitch)
	for _, les := range linked {
		if les.BMCMACAddress != "" {
			linkedByMac[utils.NormalizeMAC(les.BMCMACAddress)] = les
		}
	}

	// Direct-write external_id for matched components
	var switchIDs []*pb.SwitchId
	componentsBySwitchID := make(map[string]*model.Component)

	for bmcMac, sw := range expectedByBmcMac {
		les, found := linkedByMac[bmcMac]
		if !found || les.SwitchID == "" {
			continue
		}

		if sw.ComponentID == nil || *sw.ComponentID != les.SwitchID {
			switchID := les.SwitchID
			sw.ComponentID = &switchID
			if err := sw.Patch(ctx, pool.DB); err != nil {
				log.Error().Msgf("NVSwitch %s (BMC %s): unable to update external_id: %v", sw.ID, bmcMac, err)
				continue
			}
			log.Info().Msgf("NVSwitch %s (BMC %s): set external_id to Core SwitchId %s", sw.ID, bmcMac, switchID)
		}

		switchIDs = append(switchIDs, &pb.SwitchId{Id: les.SwitchID})
		componentsBySwitchID[les.SwitchID] = sw
	}

	// Fetch inventory from Core for all matched switches
	now := time.Now()
	var drifts []model.ComponentDrift
	if len(switchIDs) > 0 {
		invResp, err := nicoClient.GetComponentInventory(ctx, &pb.GetComponentInventoryRequest{
			Target: &pb.GetComponentInventoryRequest_SwitchIds{
				SwitchIds: &pb.SwitchIdList{Ids: switchIDs},
			},
		})
		if err != nil {
			log.Error().Msgf("Unable to retrieve switch inventory from NICo: %v", err)
		} else {
			drifts = append(drifts, applyInventoryToComponents(ctx, pool, invResp, componentsBySwitchID)...)
		}
	}

	// Build drifts for components that don't have a Core SwitchId yet
	for _, sw := range expectedByBmcMac {
		if sw.ComponentID == nil || *sw.ComponentID == "" {
			compID := sw.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  nil,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
		}
	}

	log.Info().Msgf("NVSwitch NICo sync: %d drift(s) out of %d expected", len(drifts), len(expectedSwitches))
	return drifts
}

// ---------------------------------------------------------------------------
// syncPowershelvesNICo: sync PowerShelf components via Core (NICo)
// ---------------------------------------------------------------------------
//
// Uses Core's NICo API instead of talking directly to PSM.
// Core's PSM backend auto-registers power shelves, so no registration step is needed.
//
// NICo API calls (2 round-trips):
//   - GetAllExpectedPowerShelvesLinked: discover Core power shelf IDs by PMC MAC
//   - GetComponentInventory: get firmware, power state from site explorer
//
// Flow:
//  1. DB: get all PowerShelf components with PMCs
//  2. NICo GetAllExpectedPowerShelvesLinked: map PMC MAC → Core PowerShelfId
//  3. Direct-write external_id (Core's PowerShelfId) for matched components
//  4. NICo GetComponentInventory: extract firmware_version, power_state
//  5. Direct-write inventory fields to DB
//  6. Return drifts (missing_in_actual for components without a Core PowerShelfId)

func syncPowershelvesNICo(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) []model.ComponentDrift {
	log.Debug().Msg("Syncing powershelves via NICo...")

	expectedPowershelves, err := model.GetComponentsByType(ctx, pool.DB, devicetypes.ComponentTypePowerShelf)
	if err != nil {
		log.Error().Msgf("Unable to retrieve powershelf components from db: %v", err)
		return nil
	}

	if len(expectedPowershelves) == 0 {
		return nil
	}

	expectedByPmcMac := make(map[string]*model.Component)
	for i := range expectedPowershelves {
		ps := &expectedPowershelves[i]
		if len(ps.BMCs) != 1 {
			log.Error().Msgf("Powershelf %s has %d BMCs, expected exactly 1; skipping", ps.SerialNumber, len(ps.BMCs))
			continue
		}
		pmcMacAddr, err := net.ParseMAC(ps.BMCs[0].MacAddress)
		if err != nil || pmcMacAddr == nil {
			log.Error().Msgf("Powershelf %s has invalid BMC MAC address %s; skipping", ps.SerialNumber, ps.BMCs[0].MacAddress)
			continue
		}
		expectedByPmcMac[pmcMacAddr.String()] = ps
	}

	// ID discovery: map PMC MAC → Core PowerShelfId
	linked, err := nicoClient.GetAllExpectedPowerShelvesLinked(ctx)
	if err != nil {
		log.Error().Msgf("Unable to retrieve linked expected power shelves from NICo: %v", err)
		return nil
	}

	linkedByMac := make(map[string]nicoapi.LinkedExpectedPowerShelf)
	for _, leps := range linked {
		if leps.BMCMACAddress != "" {
			linkedByMac[utils.NormalizeMAC(leps.BMCMACAddress)] = leps
		}
	}

	// Direct-write external_id for matched components
	var shelfIDs []*pb.PowerShelfId
	componentsByShelfID := make(map[string]*model.Component)

	for pmcMac, ps := range expectedByPmcMac {
		leps, found := linkedByMac[pmcMac]
		if !found || leps.PowerShelfID == "" {
			continue
		}

		if ps.ComponentID == nil || *ps.ComponentID != leps.PowerShelfID {
			shelfID := leps.PowerShelfID
			ps.ComponentID = &shelfID
			if err := ps.Patch(ctx, pool.DB); err != nil {
				log.Error().Msgf("Powershelf %s (PMC %s): unable to update external_id: %v", ps.ID, pmcMac, err)
				continue
			}
			log.Info().Msgf("Powershelf %s (PMC %s): set external_id to Core PowerShelfId %s", ps.ID, pmcMac, shelfID)
		}

		shelfIDs = append(shelfIDs, &pb.PowerShelfId{Id: leps.PowerShelfID})
		componentsByShelfID[leps.PowerShelfID] = ps
	}

	// Fetch inventory from Core for all matched power shelves
	now := time.Now()
	var drifts []model.ComponentDrift
	if len(shelfIDs) > 0 {
		invResp, err := nicoClient.GetComponentInventory(ctx, &pb.GetComponentInventoryRequest{
			Target: &pb.GetComponentInventoryRequest_PowerShelfIds{
				PowerShelfIds: &pb.PowerShelfIdList{Ids: shelfIDs},
			},
		})
		if err != nil {
			log.Error().Msgf("Unable to retrieve powershelf inventory from NICo: %v", err)
		} else {
			drifts = append(drifts, applyInventoryToComponents(ctx, pool, invResp, componentsByShelfID)...)
		}
	}

	// Build drifts for components that don't have a Core PowerShelfId yet
	for _, ps := range expectedByPmcMac {
		if ps.ComponentID == nil || *ps.ComponentID == "" {
			compID := ps.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  nil,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
		}
	}

	log.Info().Msgf("Powershelf NICo sync: %d drift(s) out of %d expected", len(drifts), len(expectedPowershelves))
	return drifts
}

// applyInventoryToComponents extracts firmware_version and power_state from
// GetComponentInventoryResponse and direct-writes them to the matching
// components. Serial numbers are compared (not overwritten) and returned as
// drift records. componentsByID maps the component_id echoed back in each
// ComponentResult to the DB component.
func applyInventoryToComponents(
	ctx context.Context,
	pool *cdb.Session,
	resp *pb.GetComponentInventoryResponse,
	componentsByID map[string]*model.Component,
) []model.ComponentDrift {
	now := time.Now()
	var drifts []model.ComponentDrift

	for _, entry := range resp.GetEntries() {
		result := entry.GetResult()
		if result == nil {
			continue
		}
		comp, ok := componentsByID[result.GetComponentId()]
		if !ok {
			continue
		}
		if result.GetStatus() != pb.ComponentManagerStatusCode_COMPONENT_MANAGER_STATUS_CODE_SUCCESS {
			log.Warn().Msgf("Component %s: inventory status %s: %s", result.GetComponentId(), result.GetStatus(), result.GetError())
			continue
		}

		report := entry.GetReport()
		if report == nil {
			continue
		}

		needsUpdate := false

		// Extract firmware_version from the "BMC image" inventory entry
		for _, svc := range report.GetService() {
			for _, inv := range svc.GetInventories() {
				if inv.GetDescription() == "BMC image" {
					if v := inv.GetVersion(); v != "" && comp.FirmwareVersion != v {
						comp.FirmwareVersion = v
						needsUpdate = true
					}
				}
			}
		}

		// Compare serial_number from first Chassis entry (drift, not overwrite)
		if chassisList := report.GetChassis(); len(chassisList) > 0 {
			if sn := chassisList[0].GetSerialNumber(); sn != "" && comp.SerialNumber != sn {
				compID := comp.ID
				extID := result.GetComponentId()
				drifts = append(drifts, model.ComponentDrift{
					ComponentID: &compID,
					ExternalID:  &extID,
					DriftType:   model.DriftTypeMismatch,
					Diffs: []model.FieldDiff{{
						FieldName:     driftFieldSerialNumber,
						ExpectedValue: comp.SerialNumber,
						ActualValue:   sn,
					}},
					CheckedAt: now,
				})
			}
		}

		// Extract power_state from first ComputerSystem entry
		if systems := report.GetSystems(); len(systems) > 0 {
			ps := computerSystemPowerStateToNICo(systems[0].GetPowerState())
			if comp.PowerState == nil || *comp.PowerState != ps {
				comp.PowerState = &ps
				needsUpdate = true
			}
		}

		if needsUpdate {
			if err := comp.Patch(ctx, pool.DB); err != nil {
				log.Error().Msgf("Component %s: unable to write inventory fields: %v", result.GetComponentId(), err)
			}
		}
	}

	return drifts
}

func computerSystemPowerStateToNICo(
	ps pb.ComputerSystemPowerState,
) nicoapi.PowerState {
	switch ps {
	case pb.ComputerSystemPowerState_On, pb.ComputerSystemPowerState_PoweringOn:
		return nicoapi.PowerStateOn
	case pb.ComputerSystemPowerState_Off, pb.ComputerSystemPowerState_PoweringOff:
		return nicoapi.PowerStateOff
	default:
		return nicoapi.PowerStateUnknown
	}
}
