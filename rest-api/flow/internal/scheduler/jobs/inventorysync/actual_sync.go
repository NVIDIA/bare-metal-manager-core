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
	pb "github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi/gen"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
)

// driftFieldSerialNumber is the canonical drift field name used by both the
// machine and inventory paths when chassis serial mismatches show up.
const driftFieldSerialNumber = "serial_number"

// runActualSync runs every per-type actual-vs-expected drift detector,
// concatenates their drifts, and logs a per-type "received from Core"
// summary. Each type-specific function handles its own errors internally
// and falls back to nil drifts; one type's RPC failure doesn't suppress the
// others.
//
// allRPCOK is true only when every type's drift-affecting RPCs succeeded. The
// drift table is a full-table replace with no per-type discriminator, so the
// caller must not overwrite it from a partial view: if any type's RPC failed,
// the previously persisted drifts are kept rather than being wiped. The
// returned drifts are not yet persisted — runInventoryOne owns the
// table-replacement transaction.
func runActualSync(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) (drifts []model.ComponentDrift, allRPCOK bool) {
	allRPCOK = true

	computeReceived, machineDrifts, machineOK := syncMachines(ctx, pool, nicoClient)
	drifts = append(drifts, machineDrifts...)
	allRPCOK = allRPCOK && machineOK

	switchesReceived, nvSwitchDrifts, switchOK := syncNVSwitchesNICo(ctx, pool, nicoClient)
	drifts = append(drifts, nvSwitchDrifts...)
	allRPCOK = allRPCOK && switchOK

	powershelvesReceived, powershelfDrifts, powershelfOK := syncPowershelvesNICo(ctx, pool, nicoClient)
	drifts = append(drifts, powershelfDrifts...)
	allRPCOK = allRPCOK && powershelfOK

	log.Info().
		Int("compute", computeReceived).
		Int("nvswitches", switchesReceived).
		Int("powershelves", powershelvesReceived).
		Bool("all_rpc_ok", allRPCOK).
		Msgf("Inventory received from Core: compute=%d nvswitches=%d powershelves=%d",
			computeReceived, switchesReceived, powershelvesReceived)

	return drifts, allRPCOK
}

// mapKeys returns the keys of a string-keyed component map in arbitrary
// order. Used by the switch / power-shelf syncs to build the id slice they
// pass to the controller-state RPCs.
func mapKeys(m map[string]*model.Component) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// persistComponentOperationStatuses maps raw core controller_state strings to
// ComponentOperationStatus values via the per-type mapper and writes any deltas to the
// component table. components are keyed by external_id (machineID / switchID /
// shelfID). Entries without a state in statesByID are skipped — missing data
// is not a status reset.
func persistComponentOperationStatuses(
	ctx context.Context,
	pool *cdb.Session,
	componentType types.ComponentType,
	statesByID map[string]string,
	componentsByExternalID map[string]*model.Component,
) {
	if len(statesByID) == 0 {
		return
	}

	var toUpdate []model.Component
	for externalID, raw := range statesByID {
		comp, ok := componentsByExternalID[externalID]
		if !ok {
			continue
		}
		newStatus := nicoapi.MapComponentOperationStatus(componentType, raw)
		if comp.Status != nil && comp.Status.Equal(newStatus) {
			continue
		}
		comp.Status = &newStatus
		toUpdate = append(toUpdate, *comp)
	}

	if len(toUpdate) == 0 {
		return
	}
	if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		for _, cur := range toUpdate {
			if err := cur.SetStatusByComponentID(ctx, tx); err != nil {
				return fmt.Errorf("set component status: %w", err)
			}
		}
		return nil
	}); err != nil {
		log.Error().Msgf("Unable to persist component statuses: %v", err)
	}
}

// applyInventoryToComponents extracts firmware_version and power_state from
// GetComponentInventoryResponse and direct-writes them to the matching
// components. Serial numbers are compared (not overwritten) and returned as
// drift records. componentsByID maps the component_id echoed back in each
// ComponentResult to the DB component. Shared by the switch and power-shelf
// syncs; the machine sync uses pre-fetched MachineDetail directly instead of
// going through GetComponentInventory.
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
