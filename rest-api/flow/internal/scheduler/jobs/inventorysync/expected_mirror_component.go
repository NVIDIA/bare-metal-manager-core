// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

// Well-known label keys cloud REST stuffs onto an expected component's
// Metadata when calling Core. Mirrored here so this package doesn't import the
// cloud REST DB-model crate. Keep in sync with rest-api/db/pkg/db/model/common.go
// (ExpectedComponentLabel* constants).
//
// firmware_version is intentionally absent: that column on Flow's component
// table is owned by the runtime sync (see syncFirmwareVersions in
// inventory.go), which reads what the BMC is actually running. Mirroring an
// "expected" version here would clobber the runtime value every cycle.
const (
	labelComponentManufacturer = "manufacturer"
	labelComponentModel        = "model"
	labelComponentSlotID       = "slot_id"
	labelComponentTrayIdx      = "tray_idx"
	labelComponentHostID       = "host_id"
)

// expectedComponentSpec is the normalised view of one Core expected_* row.
// Each Core type (ExpectedMachine / ExpectedSwitch / ExpectedPowerShelf) is
// flattened into this shape so mirrorExpectedComponents is single-typed.
//
// BMC credentials (bmc_username / bmc_password on the Core side) are
// intentionally omitted: those are factory-default creds whose live value is
// kept in Vault after site-explorer's password rotation. Copying the stale
// pre-rotation value into Flow's bmc table would just give a misleading
// fallback and spread secret material across one more store.
type expectedComponentSpec struct {
	Type           string
	Manufacturer   string
	SerialNumber   string
	Model          string
	Name           string
	SlotID         int
	TrayIndex      int
	HostID         int
	RackExternalID string
	BMC            expectedBMCSpec
}

type expectedBMCSpec struct {
	MACAddress string
	IPAddress  string
}

// fieldChange captures one before/after value pair for change-logging. The
// strings are pre-formatted so the log site doesn't have to switch on type.
type fieldChange struct {
	field string
	old   string
	new   string
}

// machineDetailToSpec maps a Core ExpectedMachineDetail to the normalised
// component spec. ChassisSerialNumber is the natural identity field; the
// label-carried Manufacturer / Model / FirmwareVersion / SlotID / TrayIdx /
// HostID are the per-row metadata cloud REST writes via
// expectedComponentLabelsInput.ToProto().
func machineDetailToSpec(d nicoapi.ExpectedMachineDetail) expectedComponentSpec {
	s := expectedComponentSpec{
		Type:           devicetypes.ComponentTypeToString(devicetypes.ComponentTypeCompute),
		SerialNumber:   d.ChassisSerialNumber,
		Name:           d.Name,
		RackExternalID: d.RackID,
		BMC: expectedBMCSpec{
			MACAddress: d.BMCMACAddress,
			IPAddress:  d.BMCIPAddress,
		},
	}
	populateLabelsIntoSpec(&s, d.Labels)
	return s
}

func switchDetailToSpec(d nicoapi.ExpectedSwitchDetail) expectedComponentSpec {
	s := expectedComponentSpec{
		Type:           devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
		SerialNumber:   d.SwitchSerialNumber,
		Name:           d.Name,
		RackExternalID: d.RackID,
		BMC: expectedBMCSpec{
			MACAddress: d.BMCMACAddress,
			IPAddress:  d.BMCIPAddress,
		},
	}
	populateLabelsIntoSpec(&s, d.Labels)
	return s
}

func powerShelfDetailToSpec(d nicoapi.ExpectedPowerShelfDetail) expectedComponentSpec {
	s := expectedComponentSpec{
		Type:           devicetypes.ComponentTypeToString(devicetypes.ComponentTypePowerShelf),
		SerialNumber:   d.ShelfSerialNumber,
		Name:           d.Name,
		RackExternalID: d.RackID,
		BMC: expectedBMCSpec{
			MACAddress: d.BMCMACAddress,
			IPAddress:  d.BMCIPAddress,
		},
	}
	populateLabelsIntoSpec(&s, d.Labels)
	return s
}

func populateLabelsIntoSpec(s *expectedComponentSpec, labels map[string]string) {
	s.Manufacturer = labels[labelComponentManufacturer]
	s.Model = labels[labelComponentModel]
	s.SlotID = parseLabelInt(labels[labelComponentSlotID])
	s.TrayIndex = parseLabelInt(labels[labelComponentTrayIdx])
	s.HostID = parseLabelInt(labels[labelComponentHostID])
}

// parseLabelInt returns 0 on either empty or malformed input. Cloud REST
// always emits these labels formatted by strconv.FormatInt, so malformed
// inputs are a data-integrity bug worth logging — but ergo cluttering every
// row with the same warn would be noisy, so we silently coerce and let the
// resulting drift surface in subsequent inventorysync runs.
func parseLabelInt(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// pullExpectedMachines / Switches / PowerShelves apply the same two-step
// guard as pullExpectedRacks (see expected_mirror.go for the rationale):
// (1) RPC error short-circuits the type, (2) empty success suppresses the
// delete phase to survive Core blips.

func pullExpectedMachines(ctx context.Context, c nicoapi.Client) (rows []nicoapi.ExpectedMachineDetail, rpcOK, hasRows bool) {
	rows, err := c.GetAllExpectedMachineDetails(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: pulling expected machines from Core failed; skipping machine mirror this cycle")
		return nil, false, false
	}
	if len(rows) == 0 {
		log.Warn().Msg("Expected-inventory mirror: Core returned zero expected machines; skipping machine delete phase this cycle")
		return nil, true, false
	}
	return rows, true, true
}

func pullExpectedSwitches(ctx context.Context, c nicoapi.Client) (rows []nicoapi.ExpectedSwitchDetail, rpcOK, hasRows bool) {
	rows, err := c.GetAllExpectedSwitchDetails(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: pulling expected switches from Core failed; skipping switch mirror this cycle")
		return nil, false, false
	}
	if len(rows) == 0 {
		log.Warn().Msg("Expected-inventory mirror: Core returned zero expected switches; skipping switch delete phase this cycle")
		return nil, true, false
	}
	return rows, true, true
}

func pullExpectedPowerShelves(ctx context.Context, c nicoapi.Client) (rows []nicoapi.ExpectedPowerShelfDetail, rpcOK, hasRows bool) {
	rows, err := c.GetAllExpectedPowerShelfDetails(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: pulling expected power shelves from Core failed; skipping power-shelf mirror this cycle")
		return nil, false, false
	}
	if len(rows) == 0 {
		log.Warn().Msg("Expected-inventory mirror: Core returned zero expected power shelves; skipping power-shelf delete phase this cycle")
		return nil, true, false
	}
	return rows, true, true
}

// mirrorExpectedComponents reconciles Flow's component table for a single
// component type against the supplied normalised specs. Matching key is
// (manufacturer, serial_number), the same unique key Flow's ingestion path
// already enforces; resurrect behaviour is symmetrical to the rack mirror so
// transient Core absence doesn't cause UUID churn.
//
// rackIDByExtID resolves a Core rack_id string (e.g. "a12") to the Flow rack
// UUID. A spec whose RackExternalID can't be resolved is skipped with a warn
// — usually because the rack mirror earlier in the same cycle dropped that
// rack for missing labels.
//
// componentType is the model.Component.Type value the caller is mirroring
// ("Compute" / "NVSwitch" / "PowerShelf"); it gates the per-type DB load and
// the delete scope so machines and switches never interfere with each other.
//
// All writes for one type's reconciliation land in a single transaction.
func mirrorExpectedComponents(
	ctx context.Context,
	pool *cdb.Session,
	componentType string,
	specs []expectedComponentSpec,
	rackIDByExtID map[string]uuid.UUID,
	skipDelete bool,
) mirrorResult {
	result := mirrorResult{resource: componentType, pulled: len(specs)}

	existing, err := getAllComponentsByTypeIncludingDeleted(ctx, pool.DB, componentType)
	if err != nil {
		log.Error().Err(err).Str("type", componentType).Msg("Expected-inventory mirror: loading Flow components failed; skipping component mirror this cycle")
		return result
	}

	flowBySerial := make(map[string]*model.Component, len(existing))
	for i := range existing {
		c := &existing[i]
		flowBySerial[rackNaturalKey(c.Manufacturer, c.SerialNumber)] = c
	}

	type bmcOp struct {
		insert *model.BMC
		update *model.BMC
		delete *model.BMC
	}
	type plan struct {
		toInsert     []model.Component
		toInsertBMCs []model.BMC // parallel to toInsert; component_id filled after insert
		toUpdate     []model.Component
		toUpdateBMCs []bmcOp // one per toUpdate entry (any/all of insert/update/delete may be set)
		toDelete     []model.Component
	}
	var p plan

	seenKeys := make(map[string]struct{}, len(specs))

	for _, s := range specs {
		if !specValid(s) {
			log.Warn().
				Str("type", componentType).
				Str("serial", s.SerialNumber).
				Str("manufacturer", s.Manufacturer).
				Str("bmc_mac", s.BMC.MACAddress).
				Msg("Expected-inventory mirror: skipping Core expected component missing required identity (manufacturer / serial / BMC MAC)")
			result.skippedNoIDOrKey++
			continue
		}

		rackID, ok := resolveRackID(s, rackIDByExtID)
		if !ok {
			log.Warn().
				Str("type", componentType).
				Str("serial", s.SerialNumber).
				Str("rack_external_id", s.RackExternalID).
				Msg("Expected-inventory mirror: skipping Core expected component whose rack is not in Flow (rack mirror dropped it or this is a Core/cycle skew)")
			result.skippedNoIDOrKey++
			continue
		}

		key := rackNaturalKey(s.Manufacturer, s.SerialNumber)
		seenKeys[key] = struct{}{}
		desired := componentFromSpec(s, rackID)

		if cur, ok := flowBySerial[key]; ok {
			candidate := *cur
			needUpdate := false
			if candidate.DeletedAt != nil {
				candidate.DeletedAt = nil
				needUpdate = true
				result.resurrected++
				log.Info().
					Str("type", componentType).
					Str("serial", candidate.SerialNumber).
					Str("component_id", candidate.ID.String()).
					Msg("Expected-inventory mirror: resurrecting soft-deleted component")
			}

			diffs := diffComponentFields(&candidate, &desired)
			if len(diffs) > 0 {
				applyComponentChanges(&candidate, &desired)
				needUpdate = true
				logComponentChanges(componentType, candidate.ID, candidate.SerialNumber, diffs)
			}

			bmcOps := planBMCReconciliation(&candidate, s.BMC)
			if needUpdate || bmcOps.insert != nil || bmcOps.update != nil || bmcOps.delete != nil {
				p.toUpdate = append(p.toUpdate, candidate)
				p.toUpdateBMCs = append(p.toUpdateBMCs, bmcOps)
			}
			continue
		}

		p.toInsert = append(p.toInsert, desired)
		p.toInsertBMCs = append(p.toInsertBMCs, model.BMC{
			MacAddress: s.BMC.MACAddress,
			Type:       devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
			IPAddress:  optionalString(s.BMC.IPAddress),
		})
		log.Info().
			Str("type", componentType).
			Str("serial", desired.SerialNumber).
			Str("manufacturer", desired.Manufacturer).
			Msg("Expected-inventory mirror: inserting new component from Core")
	}

	for i := range existing {
		c := &existing[i]
		if c.DeletedAt != nil {
			continue
		}
		if _, seen := seenKeys[rackNaturalKey(c.Manufacturer, c.SerialNumber)]; seen {
			continue
		}
		if skipDelete {
			continue
		}
		p.toDelete = append(p.toDelete, *c)
		log.Info().
			Str("type", componentType).
			Str("serial", c.SerialNumber).
			Str("component_id", c.ID.String()).
			Msg("Expected-inventory mirror: soft-deleting component absent from Core")
	}

	if len(p.toInsert) == 0 && len(p.toUpdate) == 0 && len(p.toDelete) == 0 {
		return result
	}

	if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		for i := range p.toInsert {
			if _, err := tx.NewInsert().Model(&p.toInsert[i]).Exec(ctx); err != nil {
				return fmt.Errorf("insert component %q: %w", p.toInsert[i].SerialNumber, err)
			}
			p.toInsertBMCs[i].ComponentID = p.toInsert[i].ID
			if _, err := tx.NewInsert().Model(&p.toInsertBMCs[i]).Exec(ctx); err != nil {
				return fmt.Errorf("insert BMC for component %q: %w", p.toInsert[i].SerialNumber, err)
			}
		}
		for i := range p.toUpdate {
			if _, err := tx.NewUpdate().Model(&p.toUpdate[i]).Where("id = ?", p.toUpdate[i].ID).Exec(ctx); err != nil {
				return fmt.Errorf("update component %q: %w", p.toUpdate[i].SerialNumber, err)
			}
			ops := p.toUpdateBMCs[i]
			if ops.delete != nil {
				if _, err := tx.NewDelete().Model(ops.delete).Where("mac_address = ?", ops.delete.MacAddress).ForceDelete().Exec(ctx); err != nil {
					return fmt.Errorf("delete BMC %q: %w", ops.delete.MacAddress, err)
				}
			}
			if ops.insert != nil {
				ops.insert.ComponentID = p.toUpdate[i].ID
				if _, err := tx.NewInsert().Model(ops.insert).Exec(ctx); err != nil {
					return fmt.Errorf("insert BMC for component %q: %w", p.toUpdate[i].SerialNumber, err)
				}
			}
			if ops.update != nil {
				if _, err := tx.NewUpdate().Model(ops.update).Where("mac_address = ?", ops.update.MacAddress).Exec(ctx); err != nil {
					return fmt.Errorf("update BMC %q: %w", ops.update.MacAddress, err)
				}
			}
		}
		for i := range p.toDelete {
			if _, err := tx.NewDelete().Model(&p.toDelete[i]).Where("id = ?", p.toDelete[i].ID).Exec(ctx); err != nil {
				return fmt.Errorf("soft-delete component %q: %w", p.toDelete[i].SerialNumber, err)
			}
		}
		return nil
	}); err != nil {
		log.Error().Err(err).Str("type", componentType).Msg("Expected-inventory mirror: component reconciliation transaction failed; mirror is no-op this cycle")
		return result
	}

	result.inserted = len(p.toInsert)
	result.updated = len(p.toUpdate)
	result.softDeleted = len(p.toDelete)
	return result
}

// specValid rejects rows missing fields the mirror needs to construct a row
// that both inserts cleanly (Component.Manufacturer / SerialNumber are
// NOT NULL and form a unique index) and reconciles BMC (MAC is BMC PK).
func specValid(s expectedComponentSpec) bool {
	return s.Manufacturer != "" && s.SerialNumber != "" && s.BMC.MACAddress != ""
}

// resolveRackID translates Core's rack_id string into the Flow Rack.ID
// resolved by the rack mirror earlier in the same cycle. An empty
// RackExternalID is allowed and resolves to uuid.Nil — the Component model
// already documents that "uuid.Nil when the component has been ingested but
// is not yet assigned to a rack". A non-empty value that doesn't resolve is
// rejected; risking a foreign-key violation (or worse, silently mis-routing
// a component into the wrong rack) is worse than skipping the row.
func resolveRackID(s expectedComponentSpec, rackIDByExtID map[string]uuid.UUID) (uuid.UUID, bool) {
	if s.RackExternalID == "" {
		return uuid.Nil, true
	}
	id, ok := rackIDByExtID[s.RackExternalID]
	return id, ok
}

// componentFromSpec builds the model.Component the mirror would insert for
// this spec. Mirror-managed fields only — ComponentID/external_id (runtime
// sync), PowerState (runtime), Status (lifecycle), IngestedAt are all left
// at their zero values so they don't clobber state owned by other code paths
// when this struct is used as the "desired" side of an UPDATE.
func componentFromSpec(s expectedComponentSpec, rackID uuid.UUID) model.Component {
	name := s.Name
	if name == "" {
		// Component.Name is part of the user-visible identity but the table
		// doesn't enforce non-empty; matching Flow's lenient default keeps
		// inserts safe when Core omits the name.
		name = s.SerialNumber
	}
	return model.Component{
		Name:         name,
		Type:         s.Type,
		Manufacturer: s.Manufacturer,
		SerialNumber: s.SerialNumber,
		Model:        s.Model,
		SlotID:       s.SlotID,
		TrayIndex:    s.TrayIndex,
		HostID:       s.HostID,
		RackID:       rackID,
	}
}

// applyComponentChanges copies mirror-managed fields from desired into
// existing. Identity (Manufacturer/SerialNumber/Type), runtime (ComponentID,
// PowerState, FirmwareVersion), lifecycle (Status, IngestedAt) and audit
// (CreatedAt, UpdatedAt) are intentionally not touched.
func applyComponentChanges(existing, desired *model.Component) {
	existing.Name = desired.Name
	existing.Model = desired.Model
	existing.SlotID = desired.SlotID
	existing.TrayIndex = desired.TrayIndex
	existing.HostID = desired.HostID
	existing.RackID = desired.RackID
}

// diffComponentFields returns the per-field deltas the mirror would apply.
// Used both to decide whether an UPDATE is needed and to log what changed.
// Fields the mirror doesn't manage (external_id / status / power_state /
// firmware_version / timestamps) are deliberately omitted; comparing them
// would queue UPDATE rows for state owned by other loops.
func diffComponentFields(existing, desired *model.Component) []fieldChange {
	var diffs []fieldChange
	if existing.Name != desired.Name {
		diffs = append(diffs, fieldChange{"name", existing.Name, desired.Name})
	}
	if existing.Model != desired.Model {
		diffs = append(diffs, fieldChange{"model", existing.Model, desired.Model})
	}
	if existing.SlotID != desired.SlotID {
		diffs = append(diffs, fieldChange{"slot_id", strconv.Itoa(existing.SlotID), strconv.Itoa(desired.SlotID)})
	}
	if existing.TrayIndex != desired.TrayIndex {
		diffs = append(diffs, fieldChange{"tray_index", strconv.Itoa(existing.TrayIndex), strconv.Itoa(desired.TrayIndex)})
	}
	if existing.HostID != desired.HostID {
		diffs = append(diffs, fieldChange{"host_id", strconv.Itoa(existing.HostID), strconv.Itoa(desired.HostID)})
	}
	if existing.RackID != desired.RackID {
		diffs = append(diffs, fieldChange{"rack_id", existing.RackID.String(), desired.RackID.String()})
	}
	return diffs
}

// logComponentChanges emits one INFO line per mirror cycle per component that
// actually changed, listing the fields the mirror is about to write. Done
// before the transaction so the line is preserved even if the tx rolls back
// (caller surfaces the rollback at ERROR separately).
func logComponentChanges(componentType string, id uuid.UUID, serial string, diffs []fieldChange) {
	evt := log.Info().
		Str("type", componentType).
		Str("component_id", id.String()).
		Str("serial", serial)
	for _, d := range diffs {
		evt = evt.Str("change."+d.field+".old", d.old).Str("change."+d.field+".new", d.new)
	}
	evt.Msg("Expected-inventory mirror: updating component from Core")
}

// planBMCReconciliation works out whether the component's host BMC needs an
// insert, update or replace to match the spec. Symmetric with the
// existing-component path: each call returns at most one insert, one update
// and one delete; the caller applies them inside the component-update tx.
//
// Only the BMC row of type='Host' is considered. A Compute component in Flow
// can also carry a type='DPU' BMC (and possibly others), but Core's
// ExpectedMachine only describes the host BMC — the DPU's MAC/IP isn't a
// field there. Touching non-host BMCs from here would hard-delete the DPU
// BMC row whenever the bun preload order happened to put it at BMCs[0].
//
//   - No existing host BMC: insert the spec'd one.
//   - Existing host BMC with the same MAC: update IP if it drifted.
//   - Existing host BMC with a different MAC: hard-delete the old (BMC has
//     no soft-delete) and insert the new one. MAC change is rare but
//     legal: the chassis got a new BMC board.
//
// Non-host BMC rows are left strictly alone; they're owned by the ingestion
// path or runtime discovery.
func planBMCReconciliation(component *model.Component, spec expectedBMCSpec) (ops struct {
	insert *model.BMC
	update *model.BMC
	delete *model.BMC
}) {
	hostType := devicetypes.BMCTypeToString(devicetypes.BMCTypeHost)
	want := model.BMC{
		MacAddress:  spec.MACAddress,
		Type:        hostType,
		IPAddress:   optionalString(spec.IPAddress),
		ComponentID: component.ID,
	}

	var cur *model.BMC
	for i := range component.BMCs {
		if component.BMCs[i].Type == hostType {
			cur = &component.BMCs[i]
			break
		}
	}

	if cur == nil {
		ops.insert = &want
		return ops
	}

	if cur.MacAddress == spec.MACAddress {
		updated := *cur
		if !equalOptionalString(cur.IPAddress, want.IPAddress) {
			updated.IPAddress = want.IPAddress
			ops.update = &updated
		}
		return ops
	}

	// MAC changed — hard-delete the old host BMC (BMC has no soft-delete)
	// and insert the new one. ComponentID stays the same so the FK from
	// any downstream references continues to resolve.
	old := *cur
	ops.delete = &old
	ops.insert = &want
	return ops
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	out := s
	return &out
}

func equalOptionalString(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// getAllComponentsByTypeIncludingDeleted loads every row of the given type,
// soft-deleted included, with BMCs preloaded so the per-component BMC
// reconciliation in mirrorExpectedComponents can read them without a second
// round-trip per row. The "including deleted" semantics matches the rack
// mirror's getAllRacksIncludingDeleted: it's how the resurrect path knows a
// row exists, and how the delete path avoids double-deleting.
func getAllComponentsByTypeIncludingDeleted(ctx context.Context, idb bun.IDB, componentType string) ([]model.Component, error) {
	var components []model.Component
	err := idb.NewSelect().
		Model(&components).
		Where("type = ?", componentType).
		WhereAllWithDeleted().
		Relation("BMCs").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return components, nil
}
