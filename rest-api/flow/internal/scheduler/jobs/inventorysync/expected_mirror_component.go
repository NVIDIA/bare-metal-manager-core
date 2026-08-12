// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

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
	// preserveFields names mirror-managed integer columns whose source Core
	// label was malformed (non-integer string). The mirror keeps Flow's
	// existing value for these columns on UPDATE instead of overwriting
	// with the zero left in the field above. INSERT still writes zero —
	// there's no existing row to preserve — but populateLabelsIntoSpec logs
	// the malformation either way so operators see the Core data bug.
	preserveFields map[string]bool
}

func (s *expectedComponentSpec) markPreserve(field string) {
	if s.preserveFields == nil {
		s.preserveFields = make(map[string]bool)
	}
	s.preserveFields[field] = true
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

// populateLabelsIntoSpec fills in the label-derived fields on spec. Each int
// label parsed by parseLabelInt that turns out to be non-integer is logged
// and marked in spec.preserveFields so the mirror's update path will keep
// Flow's existing value for that column instead of overwriting it with the
// zero strconv.Atoi left behind. spec.Type must already be set so the warn
// carries the component type for log filtering.
func populateLabelsIntoSpec(s *expectedComponentSpec, labels map[string]string) {
	s.Manufacturer = labels[labelComponentManufacturer]
	s.Model = labels[labelComponentModel]

	for _, lbl := range []struct {
		labelKey  string
		fieldName string
		assign    func(int)
	}{
		{labelComponentSlotID, "slot_id", func(v int) { s.SlotID = v }},
		{labelComponentTrayIdx, "tray_index", func(v int) { s.TrayIndex = v }},
		{labelComponentHostID, "host_id", func(v int) { s.HostID = v }},
	} {
		raw := labels[lbl.labelKey]
		v, ok := parseLabelInt(raw)
		if ok {
			lbl.assign(v)
			continue
		}
		s.markPreserve(lbl.fieldName)
		log.Warn().
			Str("type", s.Type).
			Str("serial", s.SerialNumber).
			Str("label", lbl.labelKey).
			Str("raw", raw).
			Msg("Expected-inventory mirror: Core label is not an integer; preserving Flow's existing value on update (insert path falls back to 0)")
	}
}

// parseLabelInt distinguishes "Core omitted the label" (empty input → 0,
// ok=true) from "Core sent something that isn't an integer" (non-empty
// non-numeric → 0, ok=false). The caller treats the first as Core
// authoritatively saying zero, and the second as a Core-side data bug
// worth logging + falling back on (preserve Flow's value on UPDATE).
func parseLabelInt(raw string) (int, bool) {
	if raw == "" {
		return 0, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return n, true
}

// pullExpectedMachines / Switches / PowerShelves apply the same single guard
// as pullExpectedRacks: an RPC error returns rpcOK=false so the caller leaves
// Flow untouched. A successful but empty result is authoritative and the
// caller soft-deletes every Flow row of that type (Core saying "none" is a
// real state, not a blip).

func pullExpectedMachines(ctx context.Context, c nicoapi.Client) (rows []nicoapi.ExpectedMachineDetail, rpcOK bool) {
	rows, err := c.GetAllExpectedMachineDetails(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: pulling expected machines from Core failed; skipping machine mirror this cycle")
		return nil, false
	}
	if len(rows) == 0 {
		log.Warn().Msg("Expected-inventory mirror: Core returned zero expected machines; mirror will soft-delete all Flow compute components this cycle")
	}
	return rows, true
}

func pullExpectedSwitches(ctx context.Context, c nicoapi.Client) (rows []nicoapi.ExpectedSwitchDetail, rpcOK bool) {
	rows, err := c.GetAllExpectedSwitchDetails(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: pulling expected switches from Core failed; skipping switch mirror this cycle")
		return nil, false
	}
	if len(rows) == 0 {
		log.Warn().Msg("Expected-inventory mirror: Core returned zero expected switches; mirror will soft-delete all Flow NVSwitch components this cycle")
	}
	return rows, true
}

func pullExpectedPowerShelves(ctx context.Context, c nicoapi.Client) (rows []nicoapi.ExpectedPowerShelfDetail, rpcOK bool) {
	rows, err := c.GetAllExpectedPowerShelfDetails(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: pulling expected power shelves from Core failed; skipping power-shelf mirror this cycle")
		return nil, false
	}
	if len(rows) == 0 {
		log.Warn().Msg("Expected-inventory mirror: Core returned zero expected power shelves; mirror will soft-delete all Flow power-shelf components this cycle")
	}
	return rows, true
}

// mirrorExpectedComponents reconciles Flow's component table for a single
// component type against the supplied normalised specs. Every Core row and
// every Flow row is reduced to one identity (identityKeyForSpec /
// identityKeyForComponent) and matched on that; the chassis labels are only
// consulted for a row no identity matched and no other spec claims.
//
// A matched row keeps its UUID while manufacturer / serial are rewritten as
// metadata, so a write can land on a pair another row holds; those are skipped
// rather than attempted (naturalKeySlotTaken).
//
// rackIDByExtID resolves a Core rack_id string (e.g. "a12") to the Flow rack
// UUID. A spec whose RackExternalID can't be resolved is mirrored with a NULL
// rack_id (the documented "ingested but not yet assigned to a rack" state) so
// the component isn't lost while the rack association heals on a later cycle.
//
// componentType is the model.Component.Type value the caller is mirroring
// ("Compute" / "NVSwitch" / "PowerShelf"); it gates the per-type DB load and
// the delete scope so machines and switches never interfere with each other.
//
// The caller only invokes this after a successful Core RPC, so an empty specs
// slice is authoritative: it means Core genuinely has no components of this
// type and every live Flow row of the type is soft-deleted. (Transient Core
// unavailability must surface as an RPC error, which short-circuits before
// this function is reached.)
//
// All writes for one type's reconciliation land in a single transaction.
func mirrorExpectedComponents(
	ctx context.Context,
	pool *cdb.Session,
	componentType string,
	specs []expectedComponentSpec,
	rackIDByExtID map[string]uuid.UUID,
) mirrorResult {
	result := mirrorResult{resource: componentType, pulled: len(specs)}

	existing, err := getAllComponentsByTypeIncludingDeleted(ctx, pool.DB, componentType)
	if err != nil {
		log.Error().Err(err).Str("type", componentType).Msg("Expected-inventory mirror: loading Flow components failed; skipping component mirror this cycle")
		return result
	}

	// flowByIdentityKey is the primary match index. A row the mirror never
	// wrote an identity for falls back to the derivation, landing under the
	// same key a Core spec produces, so it is adopted rather than duplicated.
	//
	// flowByNaturalKey backs the fallback for a spec whose identity matches
	// nothing — a replaced BMC board, or a row that never had an identity.
	// Re-inserting instead stays refused forever by the (manufacturer,
	// serial_number) slot the old row, or its tombstone, still occupies.
	flowByIdentityKey := make(map[string]*model.Component, len(existing))
	flowByNaturalKey := make(map[string]*model.Component, len(existing))
	naturalKeyOwners := make(map[string]uuid.UUID, len(existing))
	for i := range existing {
		c := &existing[i]
		if key := identityKeyForComponent(c); key != "" {
			flowByIdentityKey[key] = c
		}
		if naturalKey := naturalKeyOrEmpty(c.Manufacturer, c.SerialNumber); naturalKey != "" {
			flowByNaturalKey[naturalKey] = c
			naturalKeyOwners[naturalKey] = c.ID
		}
	}

	// Which Flow rows some spec claims by identity. Resolved up front because
	// the natural-key fallback cannot tell "spoken for" from "unmatched" until
	// every spec has been seen, and would otherwise steal a row from a later
	// spec.
	claimedByIdentity := make(map[uuid.UUID]struct{}, len(specs))
	for _, s := range specs {
		if key := identityKeyForSpec(s); key != "" {
			if c, ok := flowByIdentityKey[key]; ok {
				claimedByIdentity[c.ID] = struct{}{}
			}
		}
	}

	type plan struct {
		toInsert     []model.Component
		toInsertBMCs []model.BMC // parallel to toInsert; component_id filled after insert
		toUpdate     []model.Component
		toUpdateBMCs []bmcOps // one per toUpdate entry (any/all of insert/update/deletes may be set)
		toDelete     []model.Component
	}
	var p plan

	// seenIdentityKeys records every identity Core still reports, BEFORE any
	// skip, so the delete phase never drops a row Core still lists. The two
	// planned* sets keep writes queued in one cycle off a single slot in
	// component_identity_key_idx / component_manufacturer_serial_idx.
	seenIdentityKeys := make(map[string]struct{}, len(specs))
	plannedIdentityKeys := make(map[string]struct{}, len(specs))
	plannedNaturalKeys := make(map[string]struct{}, len(specs))
	touchedIDs := make(map[uuid.UUID]struct{}, len(specs))

	for _, s := range specs {
		key := identityKeyForSpec(s)
		if key != "" {
			seenIdentityKeys[key] = struct{}{}
		}

		if !specValid(s) {
			log.Warn().
				Str("type", componentType).
				Str("serial", s.SerialNumber).
				Str("manufacturer", s.Manufacturer).
				Str("bmc_mac", s.BMC.MACAddress).
				Msg("Expected-inventory mirror: skipping Core expected component the mirror cannot derive an identity for; a component it could not match back to Core on a later cycle would be worse than the gap")
			result.skippedNoIDOrKey++
			continue
		}

		if _, planned := plannedIdentityKeys[key]; planned {
			log.Warn().
				Str("type", componentType).
				Str("identity_key", key).
				Str("serial", s.SerialNumber).
				Msg("Expected-inventory mirror: Core returned two expected components with the same identity; skipping the later occurrence (Core-side duplicate)")
			continue
		}
		plannedIdentityKeys[key] = struct{}{}

		rackID, ok := resolveRackID(s, rackIDByExtID)
		if !ok {
			// Core references a rack Flow doesn't currently know about
			// (rack mirror dropped it this cycle, or Core/Flow have a
			// one-cycle skew). Per the mirror contract Core is the source
			// of truth and the component is still expected; soft-deleting
			// it would lose its UUID. component.rack_id is nullable and
			// has no FK, so writing uuid.Nil (NULL) is the documented
			// "ingested but not yet assigned to a rack" state and lets
			// the rack association heal on a subsequent cycle.
			log.Warn().
				Str("type", componentType).
				Str("serial", s.SerialNumber).
				Str("rack_external_id", s.RackExternalID).
				Msg("Expected-inventory mirror: Core's rack_id is not in Flow's rack table; mirroring component with NULL rack_id (rack association will heal next cycle once the rack reappears)")
			rackID = uuid.Nil
		}

		desired := componentFromSpec(s, rackID)
		desired.IdentityKey = key

		cur, matched := flowByIdentityKey[key]
		if !matched {
			// No identity match, but the chassis labels point at a row no
			// other spec claims: same component, new identity. Adopt it so the
			// UUID survives and the write isn't blocked by the natural key that
			// row already holds.
			if naturalKey := naturalKeyOrEmpty(desired.Manufacturer, desired.SerialNumber); naturalKey != "" {
				if byNaturalKey, ok := flowByNaturalKey[naturalKey]; ok {
					_, claimed := claimedByIdentity[byNaturalKey.ID]
					_, touched := touchedIDs[byNaturalKey.ID]
					if !claimed && !touched {
						cur, matched = byNaturalKey, true
					}
				}
			}
		}

		if matched {
			// Core's manufacturer/serial may already belong to a different row.
			// Attempting the write would abort the whole type's transaction
			// every cycle, so skip it and leave both rows for an operator.
			if naturalKeySlotTaken(naturalKeyOwners, plannedNaturalKeys, desired.Manufacturer, desired.SerialNumber, cur.ID) {
				log.Warn().
					Str("type", componentType).
					Str("identity_key", key).
					Str("manufacturer", desired.Manufacturer).
					Str("serial", desired.SerialNumber).
					Str("component_id", cur.ID.String()).
					Msg("Expected-inventory mirror: Core's manufacturer/serial for this component is already held by a different Flow row; skipping this update to avoid a unique-constraint abort (operator must resolve the duplicate serial)")
				result.skippedSerialTaken++
				touchedIDs[cur.ID] = struct{}{}
				continue
			}
			claimNaturalKeySlot(plannedNaturalKeys, desired.Manufacturer, desired.SerialNumber)

			if cur.IdentityKey == "" {
				result.adopted++
			}

			candidate := *cur
			needUpdate := false
			if candidate.DeletedAt != nil {
				candidate.DeletedAt = nil
				needUpdate = true
				result.resurrected++
				log.Info().
					Str("type", componentType).
					Str("serial", candidate.SerialNumber).
					Str("bmc_mac", s.BMC.MACAddress).
					Str("component_id", candidate.ID.String()).
					Msg("Expected-inventory mirror: resurrecting soft-deleted component")
			}

			diffs := diffComponentFields(&candidate, &desired, s)
			if len(diffs) > 0 {
				applyComponentChanges(&candidate, &desired, s)
				needUpdate = true
				logComponentChanges(componentType, candidate.ID, candidate.SerialNumber, diffs)
			}

			bmcOps := planBMCReconciliation(&candidate, s.BMC)
			if needUpdate || bmcOps.insert != nil || bmcOps.update != nil || len(bmcOps.deletes) > 0 {
				p.toUpdate = append(p.toUpdate, candidate)
				p.toUpdateBMCs = append(p.toUpdateBMCs, bmcOps)
			}
			touchedIDs[candidate.ID] = struct{}{}
			continue
		}

		// A new identity can still arrive carrying a (manufacturer, serial)
		// another row holds, or one this cycle already queued.
		if naturalKeySlotTaken(naturalKeyOwners, plannedNaturalKeys, desired.Manufacturer, desired.SerialNumber, uuid.Nil) {
			log.Warn().
				Str("type", componentType).
				Str("identity_key", key).
				Str("manufacturer", desired.Manufacturer).
				Str("serial", desired.SerialNumber).
				Msg("Expected-inventory mirror: Core's manufacturer/serial is already held by a different Flow component; skipping this insert to avoid a unique-constraint abort (operator must resolve the duplicate serial)")
			result.skippedSerialTaken++
			continue
		}
		claimNaturalKeySlot(plannedNaturalKeys, desired.Manufacturer, desired.SerialNumber)

		p.toInsert = append(p.toInsert, desired)
		p.toInsertBMCs = append(p.toInsertBMCs, model.BMC{
			MacAddress: s.BMC.MACAddress,
			Type:       devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
			IPAddress:  optionalString(s.BMC.IPAddress),
		})
		log.Info().
			Str("type", componentType).
			Str("identity_key", key).
			Str("serial", desired.SerialNumber).
			Str("manufacturer", desired.Manufacturer).
			Msg("Expected-inventory mirror: inserting new component from Core")
	}

	for i := range existing {
		c := &existing[i]
		if c.DeletedAt != nil {
			continue
		}
		if _, touched := touchedIDs[c.ID]; touched {
			continue
		}
		if key := identityKeyForComponent(c); key != "" {
			if _, seen := seenIdentityKeys[key]; seen {
				continue
			}
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

	now := time.Now()
	if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		for i := range p.toInsert {
			if _, err := tx.NewInsert().Model(&p.toInsert[i]).Exec(ctx); err != nil {
				return fmt.Errorf("insert component %q: %w", p.toInsert[i].SerialNumber, err)
			}
			p.toInsertBMCs[i].ComponentID = p.toInsert[i].ID
			proceed, err := evictHostBMCOrphanForInsert(ctx, tx, p.toInsertBMCs[i].MacAddress, p.toInsert[i].ID)
			if err != nil {
				return err
			}
			if proceed {
				if _, err := tx.NewInsert().Model(&p.toInsertBMCs[i]).Exec(ctx); err != nil {
					return fmt.Errorf("insert BMC for component %q: %w", p.toInsert[i].SerialNumber, err)
				}
			}
		}
		for i := range p.toUpdate {
			// Mirror-managed columns only. external_id / power_state /
			// firmware_version / status are owned by the actual-sync loop
			// and leak_status by the leak-detection loop; a full-model
			// UPDATE would clobber them with the snapshot read
			// at the top of this pass. WhereAllWithDeleted is required so a
			// resurrection (deleted_at cleared in Go) actually matches the
			// tombstone row — bun otherwise appends "deleted_at IS NULL" to
			// the UPDATE and the resurrect would silently match zero rows.
			p.toUpdate[i].UpdatedAt = now
			if _, err := tx.NewUpdate().
				Model(&p.toUpdate[i]).
				Column("name", "identity_key", "manufacturer", "serial_number", "model", "slot_id", "tray_index", "host_id", "rack_id", "deleted_at", "updated_at").
				WhereAllWithDeleted().
				Where("id = ?", p.toUpdate[i].ID).
				Exec(ctx); err != nil {
				return fmt.Errorf("update component %q: %w", p.toUpdate[i].SerialNumber, err)
			}
			ops := p.toUpdateBMCs[i]
			for j := range ops.deletes {
				if _, err := tx.NewDelete().Model(&ops.deletes[j]).Where("mac_address = ?", ops.deletes[j].MacAddress).ForceDelete().Exec(ctx); err != nil {
					return fmt.Errorf("delete BMC %q: %w", ops.deletes[j].MacAddress, err)
				}
			}
			if ops.insert != nil {
				ops.insert.ComponentID = p.toUpdate[i].ID
				proceed, err := evictHostBMCOrphanForInsert(ctx, tx, ops.insert.MacAddress, p.toUpdate[i].ID)
				if err != nil {
					return err
				}
				if proceed {
					if _, err := tx.NewInsert().Model(ops.insert).Exec(ctx); err != nil {
						return fmt.Errorf("insert BMC for component %q: %w", p.toUpdate[i].SerialNumber, err)
					}
				}
			}
			if ops.update != nil {
				if _, err := tx.NewUpdate().Model(ops.update).Column("ip_address").Where("mac_address = ?", ops.update.MacAddress).Exec(ctx); err != nil {
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
		// Tx rolled back, so the per-spec decisions logged above are intent,
		// not committed state. pulled and the skipped_* counters survive the
		// strip: both are decided before the tx opened.
		result.resurrected = 0
		result.adopted = 0
		return result
	}

	result.inserted = len(p.toInsert)
	result.updated = len(p.toUpdate)
	result.softDeleted = len(p.toDelete)
	return result
}

// specValid rejects a Core row the mirror cannot derive an identity for.
func specValid(s expectedComponentSpec) bool {
	return identityKeyForSpec(s) != ""
}

// identityKeyForSpec derives component.identity_key for a Core expected
// component, or "" when Core supplied nothing to identify the row by. Today
// that is the host BMC MAC, which Core always reports and which is 1:1 with a
// component.
//
// Redefining it is not a local edit: identity_key records no marker of which
// derivation wrote it, so during a rolling deploy two versions would write
// different keys for one component and collide. A change ships as a release
// that accepts both values, then a backfill, then the switch.
func identityKeyForSpec(s expectedComponentSpec) string {
	return s.BMC.MACAddress
}

// identityKeyForComponent returns the identity a stored row answers to: the
// persisted value once the mirror has written one, otherwise what the current
// derivation makes of the row itself. That fallback is how rows predating
// identity_key, or created by the ingestion gRPC paths, get adopted instead of
// duplicated — so a derivation has to be computable from a Flow row too.
func identityKeyForComponent(c *model.Component) string {
	if c.IdentityKey != "" {
		return c.IdentityKey
	}
	return hostBMCMac(c)
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
// sync), PowerState (runtime), Status (lifecycle), LeakStatus (leak-detection
// loop), IngestedAt are all left at their zero values so they don't clobber
// state owned by other code paths when this struct is used as the "desired"
// side of an UPDATE.
func componentFromSpec(s expectedComponentSpec, rackID uuid.UUID) model.Component {
	name := s.Name
	if name == "" {
		// Prefer Core's serial, then the host BMC MAC, so a component stays
		// labelled when Core omits the name.
		switch {
		case s.SerialNumber != "":
			name = s.SerialNumber
		default:
			name = s.BMC.MACAddress
		}
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
// existing. Type stays immutable (per-type reconciliation scope). Runtime
// (ComponentID, PowerState, FirmwareVersion), lifecycle (Status, IngestedAt)
// and audit timestamps are intentionally not touched. Manufacturer and serial
// are rewritten as metadata, so Core can fill a missing one later. Fields named
// in spec.preserveFields are skipped — their Core labels were malformed, so
// Flow's existing value beats the parseLabelInt fallback zero.
func applyComponentChanges(existing, desired *model.Component, spec expectedComponentSpec) {
	existing.Name = desired.Name
	existing.IdentityKey = desired.IdentityKey
	existing.Manufacturer = desired.Manufacturer
	existing.SerialNumber = desired.SerialNumber
	existing.Model = desired.Model
	existing.RackID = desired.RackID
	if !spec.preserveFields["slot_id"] {
		existing.SlotID = desired.SlotID
	}
	if !spec.preserveFields["tray_index"] {
		existing.TrayIndex = desired.TrayIndex
	}
	if !spec.preserveFields["host_id"] {
		existing.HostID = desired.HostID
	}
}

// diffComponentFields returns the per-field deltas the mirror would apply.
// Used both to decide whether an UPDATE is needed and to log what changed.
// Fields the mirror doesn't manage (external_id / status / power_state /
// firmware_version / timestamps) are deliberately omitted; comparing them
// would queue UPDATE rows for state owned by other loops. Fields named in
// spec.preserveFields are also skipped so a malformed Core label can't
// drive a spurious UPDATE that would clobber Flow's value with the
// fallback zero.
func diffComponentFields(existing, desired *model.Component, spec expectedComponentSpec) []fieldChange {
	var diffs []fieldChange
	if existing.Name != desired.Name {
		diffs = append(diffs, fieldChange{"name", existing.Name, desired.Name})
	}
	// Only differs when adopting a row that has no identity yet, or re-keying
	// one whose identity moved; an identity match already agrees.
	if existing.IdentityKey != desired.IdentityKey {
		diffs = append(diffs, fieldChange{"identity_key", existing.IdentityKey, desired.IdentityKey})
	}
	if existing.Manufacturer != desired.Manufacturer {
		diffs = append(diffs, fieldChange{"manufacturer", existing.Manufacturer, desired.Manufacturer})
	}
	if existing.SerialNumber != desired.SerialNumber {
		diffs = append(diffs, fieldChange{"serial_number", existing.SerialNumber, desired.SerialNumber})
	}
	if existing.Model != desired.Model {
		diffs = append(diffs, fieldChange{"model", existing.Model, desired.Model})
	}
	if !spec.preserveFields["slot_id"] && existing.SlotID != desired.SlotID {
		diffs = append(diffs, fieldChange{"slot_id", strconv.Itoa(existing.SlotID), strconv.Itoa(desired.SlotID)})
	}
	if !spec.preserveFields["tray_index"] && existing.TrayIndex != desired.TrayIndex {
		diffs = append(diffs, fieldChange{"tray_index", strconv.Itoa(existing.TrayIndex), strconv.Itoa(desired.TrayIndex)})
	}
	if !spec.preserveFields["host_id"] && existing.HostID != desired.HostID {
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

// bmcOps captures the set of writes the mirror plans against the BMC table
// for one component. deletes stays plural because the reconciliation also runs
// against rows written before bmc_one_host_per_component_idx existed.
type bmcOps struct {
	insert  *model.BMC
	update  *model.BMC
	deletes []model.BMC
}

// planBMCReconciliation works out the BMC writes needed to make this
// component's host-BMC row match the spec. Only type='Host' BMCs are
// considered: Core's ExpectedMachine describes the host BMC only, the DPU
// BMC's MAC/IP isn't a field there. Non-host rows are left strictly alone;
// they're owned by the ingestion path or runtime discovery.
//
// Cases:
//   - No existing host BMC: insert the spec'd one.
//   - Exactly one existing host BMC matching the spec MAC: update its IP if
//     it drifted.
//   - One or more existing host BMCs and at most one matches the spec MAC:
//     keep the matching one (IP-drift update if needed); hard-delete every
//     non-matching host BMC. Multiple host BMCs is an ingestion bug; the
//     mirror cleans it up since Core's authoritative view is one.
//   - One or more existing host BMCs and none match the spec MAC: hard-delete
//     all of them and insert the spec'd one. This is the MAC-change path
//     (chassis got a new BMC board) generalised over an existing dirty state.
func planBMCReconciliation(component *model.Component, spec expectedBMCSpec) (ops bmcOps) {
	hostType := devicetypes.BMCTypeToString(devicetypes.BMCTypeHost)
	want := model.BMC{
		MacAddress:  spec.MACAddress,
		Type:        hostType,
		IPAddress:   optionalString(spec.IPAddress),
		ComponentID: component.ID,
	}

	var hosts []model.BMC
	for i := range component.BMCs {
		if component.BMCs[i].Type == hostType {
			hosts = append(hosts, component.BMCs[i])
		}
	}

	if len(hosts) > 1 {
		log.Warn().
			Str("component_id", component.ID.String()).
			Str("serial", component.SerialNumber).
			Int("host_bmc_count", len(hosts)).
			Msg("Expected-inventory mirror: component has multiple type='Host' BMC rows (Flow data should have at most one); extras will be hard-deleted to match Core")
	}

	// Pick the one matching the spec MAC; that's the keeper.
	var keeper *model.BMC
	for i := range hosts {
		if hosts[i].MacAddress == spec.MACAddress {
			keeper = &hosts[i]
			break
		}
	}

	if keeper != nil {
		for i := range hosts {
			if hosts[i].MacAddress == keeper.MacAddress {
				continue
			}
			ops.deletes = append(ops.deletes, hosts[i])
		}
		if !equalOptionalString(keeper.IPAddress, want.IPAddress) {
			updated := *keeper
			updated.IPAddress = want.IPAddress
			ops.update = &updated
		}
		return ops
	}

	// No host BMC matches the spec MAC. Insert the new one; hard-delete
	// any stale host rows. ComponentID stays the same so downstream FKs
	// keep resolving.
	ops.insert = &want
	for i := range hosts {
		ops.deletes = append(ops.deletes, hosts[i])
	}
	return ops
}

// evictHostBMCOrphanForInsert clears the way to INSERT a host BMC whose
// mac_address may already be taken. The bmc table's PK is the MAC alone, so a
// collision would fail the INSERT and roll back the whole component-mirror tx.
// It returns whether the caller should proceed with the INSERT:
//
//   - No existing row with that MAC: proceed (nothing in the way).
//   - Existing row is type='Host' on a different component: hard-delete it
//     (Core's claim wins; a host BMC card physically moved chassis) and
//     proceed. Logged loudly as a data-corruption signal.
//   - Existing row is type='Host' on the same component: don't re-insert
//     (it's already there); proceed=false.
//   - Existing row is NOT type='Host' (e.g. a DPU BMC): refuse. The mirror
//     never owns non-host BMCs, and the bmc table has no soft-delete, so
//     hard-deleting another component's DPU row would be unrecoverable data
//     loss. Skip this one host-BMC insert and log an error instead of
//     aborting the whole type's mirror.
func evictHostBMCOrphanForInsert(ctx context.Context, tx bun.Tx, mac string, newOwnerID uuid.UUID) (proceed bool, err error) {
	hostType := devicetypes.BMCTypeToString(devicetypes.BMCTypeHost)

	var orphan model.BMC
	err = tx.NewSelect().
		Model(&orphan).
		Where("mac_address = ?", mac).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("look up potential BMC orphan %q: %w", mac, err)
	}

	if orphan.Type != hostType {
		log.Error().
			Str("bmc_mac", mac).
			Str("existing_type", orphan.Type).
			Str("existing_owner_component_id", orphan.ComponentID.String()).
			Str("new_owner_component_id", newOwnerID.String()).
			Msg("Expected-inventory mirror: Core's host BMC MAC collides with an existing non-host BMC; refusing to evict it, skipping this host BMC insert (manual data cleanup required)")
		return false, nil
	}

	if orphan.ComponentID == newOwnerID {
		return false, nil
	}

	if _, err := tx.NewDelete().
		Model(&orphan).
		Where("mac_address = ?", mac).
		ForceDelete().
		Exec(ctx); err != nil {
		return false, fmt.Errorf("evict orphan host BMC %q from component %s: %w", mac, orphan.ComponentID, err)
	}
	log.Warn().
		Str("bmc_mac", mac).
		Str("orphan_owner_component_id", orphan.ComponentID.String()).
		Str("new_owner_component_id", newOwnerID.String()).
		Msg("Expected-inventory mirror: host BMC MAC already owned by a different component; evicted to honour Core's claim")
	return true, nil
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

// hostBMCMac returns the Host BMC MAC for a component, or "" when none is
// attached. bmc_one_host_per_component_idx makes the match unambiguous; DPU
// and other BMC types are ignored.
func hostBMCMac(c *model.Component) string {
	if c == nil {
		return ""
	}
	hostType := devicetypes.BMCTypeToString(devicetypes.BMCTypeHost)
	for i := range c.BMCs {
		if c.BMCs[i].Type == hostType {
			return c.BMCs[i].MacAddress
		}
	}
	return ""
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
