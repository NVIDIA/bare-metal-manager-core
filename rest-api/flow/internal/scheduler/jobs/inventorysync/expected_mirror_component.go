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
// component type against the supplied normalised specs. Matching key is
// (manufacturer, serial_number), the same unique key Flow's ingestion path
// already enforces; resurrect behaviour is symmetrical to the rack mirror so
// transient Core absence doesn't cause UUID churn.
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

	flowBySerial := make(map[string]*model.Component, len(existing))
	for i := range existing {
		c := &existing[i]
		flowBySerial[rackNaturalKey(c.Manufacturer, c.SerialNumber)] = c
	}

	type plan struct {
		toInsert     []model.Component
		toInsertBMCs []model.BMC // parallel to toInsert; component_id filled after insert
		toUpdate     []model.Component
		toUpdateBMCs []bmcOps // one per toUpdate entry (any/all of insert/update/deletes may be set)
		toDelete     []model.Component
	}
	var p plan

	// seenKeys: every (manufacturer, serial) Core is still reporting this
	// cycle, recorded BEFORE any validity / dedup skip. The delete phase
	// treats a row whose key is absent from this set as "Core dropped it".
	// plannedKeys: keys we've already queued an insert/update for, used to
	// drop Core duplicates before they hit the (manufacturer, serial)
	// unique index and roll back the whole type's transaction.
	seenKeys := make(map[string]struct{}, len(specs))
	plannedKeys := make(map[string]struct{}, len(specs))

	for _, s := range specs {
		// Record the natural key as "still reported by Core" as early as
		// possible. The key needs only (manufacturer, serial); a missing
		// BMC MAC is a partial-row blip, not an absence, so it must not
		// let the delete phase soft-delete a row Core is still listing.
		keyDerivable := s.Manufacturer != "" && s.SerialNumber != ""
		var key string
		if keyDerivable {
			key = rackNaturalKey(s.Manufacturer, s.SerialNumber)
			seenKeys[key] = struct{}{}
		}

		if !specValid(s) {
			log.Warn().
				Str("type", componentType).
				Str("serial", s.SerialNumber).
				Str("manufacturer", s.Manufacturer).
				Str("bmc_mac", s.BMC.MACAddress).
				Msg("Expected-inventory mirror: skipping Core expected component missing required identity (manufacturer / serial / BMC MAC); row preserved if its key is still reported")
			result.skippedNoIDOrKey++
			continue
		}

		// specValid guarantees manufacturer and serial are set, so key is
		// populated here. Drop Core duplicates: planning the same key twice
		// would queue two INSERTs that collide on the unique index.
		if _, planned := plannedKeys[key]; planned {
			log.Warn().
				Str("type", componentType).
				Str("manufacturer", s.Manufacturer).
				Str("serial", s.SerialNumber).
				Msg("Expected-inventory mirror: Core returned duplicate spec for this component; skipping the later occurrence to avoid a unique-constraint abort (Cloud REST is producing duplicates)")
			continue
		}
		plannedKeys[key] = struct{}{}

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
				Column("name", "model", "slot_id", "tray_index", "host_id", "rack_id", "deleted_at", "updated_at").
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
		// Tx rolled back: every per-spec decision logged above represents
		// intent, not committed state. Strip success-side counters so the
		// summary log line reflects what actually landed. pulled and
		// skippedNoIDOrKey survive: pulled is input size; skippedNoIDOrKey
		// is decided before we ever opened the tx, so neither is
		// invalidated by the rollback.
		result.resurrected = 0
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
// sync), PowerState (runtime), Status (lifecycle), LeakStatus (leak-detection
// loop), IngestedAt are all left at their zero values so they don't clobber
// state owned by other code paths when this struct is used as the "desired"
// side of an UPDATE.
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
// (CreatedAt, UpdatedAt) are intentionally not touched. Fields named in
// spec.preserveFields are also skipped — those are the columns whose Core
// labels were malformed and so should keep Flow's existing value rather
// than be overwritten with the parseLabelInt fallback zero.
func applyComponentChanges(existing, desired *model.Component, spec expectedComponentSpec) {
	existing.Name = desired.Name
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
// for one component. The deletes slice can be longer than one entry: a
// well-formed component carries exactly one type='Host' BMC, but ingestion
// bugs and data drift can leave several, and the mirror hard-deletes the
// stale ones so Core's "exactly one host BMC" view is enforced.
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
