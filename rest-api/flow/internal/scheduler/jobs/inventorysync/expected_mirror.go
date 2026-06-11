// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"
	"reflect"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

// Well-known label keys Core writes on ExpectedRack.metadata.labels. Mirrored
// here so this package doesn't pull in the api-model crate's Rust constants.
// Keep in sync with crates/api-model/src/rack.rs.
const (
	labelChassisManufacturer = "chassis.manufacturer"
	labelChassisSerialNumber = "chassis.serial-number"
	labelChassisModel        = "chassis.model"
	labelLocationRegion      = "location.region"
	labelLocationDatacenter  = "location.datacenter"
	labelLocationRoom        = "location.room"
	labelLocationPosition    = "location.position"
)

// mirrorResult summarises one mirror pass for a single resource type. Used for
// structured logging so the operator can tell at a glance whether a sync was
// well-behaved (mostly updates, no surprises) or alarming (large delete
// counts).
type mirrorResult struct {
	resource         string
	pulled           int
	inserted         int
	updated          int
	adopted          int
	resurrected      int
	softDeleted      int
	legacyExempt     int
	skippedNoIDOrKey int
}

func (r mirrorResult) log() {
	log.Info().
		Str("resource", r.resource).
		Int("pulled", r.pulled).
		Int("inserted", r.inserted).
		Int("updated", r.updated).
		Int("adopted", r.adopted).
		Int("resurrected", r.resurrected).
		Int("soft_deleted", r.softDeleted).
		Int("legacy_exempt", r.legacyExempt).
		Int("skipped_invalid", r.skippedNoIDOrKey).
		Msgf("Expected-inventory mirror: %s", r.resource)
}

// syncExpectedFromCore pulls Core's expected inventory and reconciles each
// of Flow's tables to mirror it. Racks are reconciled first so a per-cycle
// rack_id → Rack.UUID map is available to resolve every component's
// RackExternalID into the FK Flow needs. Each resource type is independent:
// an RPC failure on machines doesn't stop switches from being reconciled.
//
// Runs immediately before runInventoryOne's drift detection so the drift
// loop sees a Flow inventory that's already aligned with Core's expected
// view.
func syncExpectedFromCore(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) {
	racks, rackOK, rackHasRows := pullExpectedRacks(ctx, nicoClient)
	if rackOK {
		result := mirrorExpectedRacks(ctx, pool, racks, !rackHasRows)
		result.log()
	}

	// Build the cross-reference map after rack mirror so component specs
	// referencing rack_id strings can resolve them to Flow Rack.UUIDs. Done
	// via a fresh DB read instead of returning the map from
	// mirrorExpectedRacks so the rack mirror's signature stays focused; the
	// read is cheap (rack count is small) and includes adoptions / inserts
	// the mirror just made.
	rackIDByExtID, err := loadRackIDByExternalID(ctx, pool.DB)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: loading rack external_id map failed; skipping component mirror this cycle")
		return
	}

	if machines, ok, hasRows := pullExpectedMachines(ctx, nicoClient); ok {
		specs := make([]expectedComponentSpec, 0, len(machines))
		for _, m := range machines {
			specs = append(specs, machineDetailToSpec(m))
		}
		result := mirrorExpectedComponents(ctx, pool,
			devicetypes.ComponentTypeToString(devicetypes.ComponentTypeCompute),
			specs, rackIDByExtID, !hasRows)
		result.log()
	}

	if switches, ok, hasRows := pullExpectedSwitches(ctx, nicoClient); ok {
		specs := make([]expectedComponentSpec, 0, len(switches))
		for _, s := range switches {
			specs = append(specs, switchDetailToSpec(s))
		}
		result := mirrorExpectedComponents(ctx, pool,
			devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
			specs, rackIDByExtID, !hasRows)
		result.log()
	}

	if shelves, ok, hasRows := pullExpectedPowerShelves(ctx, nicoClient); ok {
		specs := make([]expectedComponentSpec, 0, len(shelves))
		for _, ps := range shelves {
			specs = append(specs, powerShelfDetailToSpec(ps))
		}
		result := mirrorExpectedComponents(ctx, pool,
			devicetypes.ComponentTypeToString(devicetypes.ComponentTypePowerShelf),
			specs, rackIDByExtID, !hasRows)
		result.log()
	}
}

// loadRackIDByExternalID returns a map keyed by rack.external_id (Core's
// rack_id string) of the matching Flow Rack.UUID. Soft-deleted rows are
// excluded because component specs that reference a deleted rack would
// inherit a stale FK; better to skip the component spec with a warn.
func loadRackIDByExternalID(ctx context.Context, idb bun.IDB) (map[string]uuid.UUID, error) {
	var rows []struct {
		ID         uuid.UUID `bun:"id"`
		ExternalID *string   `bun:"external_id"`
	}
	if err := idb.NewSelect().
		Model((*model.Rack)(nil)).
		Column("id", "external_id").
		Where("external_id IS NOT NULL AND external_id <> ''").
		Scan(ctx, &rows); err != nil {
		return nil, err
	}
	out := make(map[string]uuid.UUID, len(rows))
	for _, r := range rows {
		if r.ExternalID != nil && *r.ExternalID != "" {
			out[*r.ExternalID] = r.ID
		}
	}
	return out, nil
}

// pullExpectedRacks wraps the nicoapi RPC with the two safety guards the
// mirror needs:
//
//  1. RPC-failure guard. If GetAllExpectedRackDetails errors, return rpcOK
//     false so the caller skips reconciliation entirely. Treating an RPC
//     error as "Core has no racks" would soft-delete every Flow rack on the
//     next pass.
//
//  2. Empty-response guard. If the RPC succeeds but returns zero rows, return
//     hasRows false so the caller can apply inserts/updates (no-ops in this
//     case) but skip the delete phase. Core sometimes briefly serves an empty
//     expected_* table during restarts and schema upgrades; leaving deletes
//     to a subsequent run that still sees the table empty makes the mirror
//     tolerant of those transients.
func pullExpectedRacks(
	ctx context.Context,
	nicoClient nicoapi.Client,
) (rows []nicoapi.ExpectedRackDetail, rpcOK bool, hasRows bool) {
	rows, err := nicoClient.GetAllExpectedRackDetails(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: pulling expected racks from Core failed; skipping rack mirror this cycle")
		return nil, false, false
	}
	if len(rows) == 0 {
		log.Warn().Msg("Expected-inventory mirror: Core returned zero expected racks; skipping rack delete phase this cycle")
		return nil, true, false
	}
	return rows, true, true
}

// mirrorExpectedRacks reconciles Flow's rack table against Core's
// expected_racks view. The algorithm is, in order:
//
//  1. Index every Flow rack — including soft-deleted ones — by external_id
//     (mirror-owned) and by (manufacturer, serial_number) (the natural key
//     shared with Core). Including soft-deleted rows is what makes
//     resurrection work: a rack that briefly disappeared from Core and came
//     back keeps its UUID, and a re-insert would otherwise collide on the
//     (manufacturer, serial_number) unique index that the soft-deleted row
//     still occupies.
//
//  2. For each Core row, find the matching Flow row preferring external_id
//     and falling back to (manufacturer, serial_number) to adopt rows that
//     predate the mirror. New rows are inserted. A matched row that's
//     currently soft-deleted is resurrected by clearing deleted_at;
//     mirror-managed fields are updated alongside on real deltas.
//
//  3. If skipDelete is false, live Flow rows whose external_id is set but no
//     longer appear in Core are soft-deleted. Soft-deleted rows that Core
//     doesn't report either are left alone (already gone). Rows with a NULL
//     external_id (legacy ingestion-gRPC rows the mirror has never adopted)
//     are exempted and warn-logged so the operator has a visible signal of
//     pending cleanup.
//
// All writes for one pass happen in a single transaction so partial failures
// can't leave the table half-mirrored.
func mirrorExpectedRacks(
	ctx context.Context,
	pool *cdb.Session,
	coreRacks []nicoapi.ExpectedRackDetail,
	skipDelete bool,
) mirrorResult {
	result := mirrorResult{resource: "rack", pulled: len(coreRacks)}

	flowRacks, err := getAllRacksIncludingDeleted(ctx, pool.DB)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: loading Flow racks failed; skipping rack mirror this cycle")
		return result
	}

	flowByExtID := make(map[string]*model.Rack, len(flowRacks))
	flowBySerial := make(map[string]*model.Rack, len(flowRacks))
	for i := range flowRacks {
		r := &flowRacks[i]
		if r.ExternalID != nil && *r.ExternalID != "" {
			flowByExtID[*r.ExternalID] = r
		}
		flowBySerial[rackNaturalKey(r.Manufacturer, r.SerialNumber)] = r
	}

	type plan struct {
		toInsert []model.Rack
		toUpdate []model.Rack
		toDelete []model.Rack
	}
	var p plan

	// Tombstones (soft-deleted rows) indexed by name. Used to GC stale rows
	// that occupy the full unique rack_name_idx index before INSERT/UPDATE
	// statements that would otherwise collide. Same row can be matched at
	// most once: gcTombstoneForNameReuse deletes the entry after firing so
	// we don't attempt to GC the same tombstone twice in the same cycle.
	tombstonesByName := make(map[string]*model.Rack)
	for i := range flowRacks {
		r := &flowRacks[i]
		if r.DeletedAt != nil {
			tombstonesByName[r.Name] = r
		}
	}

	seenExtID := make(map[string]struct{}, len(coreRacks))

	for _, cr := range coreRacks {
		built, ok := buildRackFromCore(cr)
		if !ok {
			// Required fields (manufacturer / serial) missing in Core's labels;
			// inserting would violate NOT NULL or the (manufacturer, serial)
			// unique constraint. Skip and let the operator fix the Core data.
			log.Warn().
				Str("rack_id", cr.RackID).
				Str("name", cr.Name).
				Msg("Expected-inventory mirror: skipping Core expected rack missing chassis manufacturer or serial-number labels")
			result.skippedNoIDOrKey++
			continue
		}

		// Track which Core rack_ids are present so the delete phase can spot
		// Flow rows whose external_id is no longer covered. Empty rack_ids
		// can't be tracked (would collide on the partial unique index too);
		// the warn below makes the operator gap visible.
		if cr.RackID != "" {
			seenExtID[cr.RackID] = struct{}{}
		} else {
			log.Warn().
				Str("rack_profile_id", cr.RackProfileID).
				Str("name", cr.Name).
				Str("manufacturer", built.Manufacturer).
				Str("serial", built.SerialNumber).
				Msg("Expected-inventory mirror: Core expected rack has no rack_id; rack will be mirrored but components can't reference it")
		}

		// Prefer external_id match (already adopted on a previous cycle).
		// Empty rack_ids never hit flowByExtID by construction.
		if existing, ok := flowByExtID[cr.RackID]; ok && cr.RackID != "" {
			candidate := *existing
			needUpdate := false
			if candidate.DeletedAt != nil {
				candidate.DeletedAt = nil
				needUpdate = true
				result.resurrected++
			}
			if patched := rackUpdatedFromCore(&candidate, &built); patched != nil {
				candidate = *patched
				needUpdate = true
			}
			if needUpdate {
				p.toUpdate = append(p.toUpdate, candidate)
			}
			continue
		}

		// Fall back to natural key (legacy ingestion-gRPC rows the mirror has
		// never adopted; adopt by writing external_id alongside any deltas).
		// A serial match that's also soft-deleted gets resurrected at the
		// same time — see the function-level comment for why this matters.
		if existing, ok := flowBySerial[rackNaturalKey(built.Manufacturer, built.SerialNumber)]; ok {
			candidate := *existing
			candidate.ExternalID = built.ExternalID
			if candidate.DeletedAt != nil {
				candidate.DeletedAt = nil
				result.resurrected++
			}
			if patched := rackUpdatedFromCore(&candidate, &built); patched != nil {
				candidate = *patched
			}
			p.toUpdate = append(p.toUpdate, candidate)
			result.adopted++
			continue
		}

		p.toInsert = append(p.toInsert, built)
	}

	// Reconcile the delete side. Already soft-deleted rows are skipped: if
	// Core still lists them, the match path above resurrected them; if not,
	// they're correctly gone already. Live Flow rows whose external_id is set
	// but absent from Core get soft-deleted; legacy (NULL external_id) rows
	// are exempted with a warn so the operator notices.
	for i := range flowRacks {
		r := &flowRacks[i]
		if r.DeletedAt != nil {
			continue
		}
		hasExt := r.ExternalID != nil && *r.ExternalID != ""
		if hasExt {
			if _, present := seenExtID[*r.ExternalID]; present {
				continue
			}
			if skipDelete {
				continue
			}
			p.toDelete = append(p.toDelete, *r)
			continue
		}
		// External_id is NULL — never adopted. Only legacy-warn if the
		// (manufacturer, serial) doesn't appear in Core's set either,
		// otherwise it'll be picked up by the adoption path above and a
		// "future GC" warn would be misleading.
		if _, adoptable := flowBySerialInCore(r, coreRacks); !adoptable {
			result.legacyExempt++
			log.Warn().
				Str("rack_name", r.Name).
				Str("rack_serial", r.SerialNumber).
				Str("rack_manufacturer", r.Manufacturer).
				Msg("Expected-inventory mirror: legacy Flow rack not present in Core's expected inventory; left in place for now (a follow-up will GC these once all sites have migrated)")
		}
	}

	if len(p.toInsert) == 0 && len(p.toUpdate) == 0 && len(p.toDelete) == 0 {
		return result
	}

	if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		for i := range p.toInsert {
			if err := gcTombstoneForNameReuse(ctx, tx, tombstonesByName, p.toInsert[i].Name, uuid.Nil); err != nil {
				return err
			}
			if _, err := tx.NewInsert().Model(&p.toInsert[i]).Exec(ctx); err != nil {
				return fmt.Errorf("insert rack %q: %w", p.toInsert[i].Name, err)
			}
		}
		for i := range p.toUpdate {
			if err := gcTombstoneForNameReuse(ctx, tx, tombstonesByName, p.toUpdate[i].Name, p.toUpdate[i].ID); err != nil {
				return err
			}
			if _, err := tx.NewUpdate().Model(&p.toUpdate[i]).Where("id = ?", p.toUpdate[i].ID).Exec(ctx); err != nil {
				return fmt.Errorf("update rack %q: %w", p.toUpdate[i].Name, err)
			}
		}
		for i := range p.toDelete {
			if _, err := tx.NewDelete().Model(&p.toDelete[i]).Where("id = ?", p.toDelete[i].ID).Exec(ctx); err != nil {
				return fmt.Errorf("soft-delete rack %q: %w", p.toDelete[i].Name, err)
			}
		}
		return nil
	}); err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: rack reconciliation transaction failed; mirror is no-op this cycle")
		return result
	}

	result.inserted = len(p.toInsert)
	result.updated = len(p.toUpdate)
	result.softDeleted = len(p.toDelete)
	return result
}

// gcTombstoneForNameReuse hard-deletes a soft-deleted rack that's occupying
// the supplied name so the caller's INSERT or UPDATE doesn't collide on
// rack_name_idx (which is a full unique constraint and so applies to
// tombstones too). excludeID lets the UPDATE path skip the row that's
// itself being resurrected (the tombstone IS that row; deleting it would
// erase what we're about to write). uuid.Nil for INSERT — no exclusion
// needed. The map entry is removed on hit so a later op against the same
// name doesn't replay the same delete.
func gcTombstoneForNameReuse(
	ctx context.Context,
	tx bun.Tx,
	tombstonesByName map[string]*model.Rack,
	name string,
	excludeID uuid.UUID,
) error {
	tomb, ok := tombstonesByName[name]
	if !ok || tomb.ID == excludeID {
		return nil
	}
	if _, err := tx.NewDelete().Model(tomb).Where("id = ?", tomb.ID).ForceDelete().Exec(ctx); err != nil {
		return fmt.Errorf("GC stale rack tombstone occupying name %q: %w", name, err)
	}
	delete(tombstonesByName, name)
	log.Info().
		Str("rack_name", name).
		Str("tombstone_id", tomb.ID.String()).
		Str("tombstone_manufacturer", tomb.Manufacturer).
		Str("tombstone_serial", tomb.SerialNumber).
		Msg("Expected-inventory mirror: GC'd stale rack tombstone to free up name for reuse")
	return nil
}

// getAllRacksIncludingDeleted returns every rack in the Flow DB, soft-deleted
// rows included. The mirror needs the deleted ones so it can (a) resurrect a
// rack that comes back in Core instead of attempting an INSERT that would
// collide on the (manufacturer, serial_number) unique index the tombstone
// still holds, and (b) not double-delete a row that's already gone.
func getAllRacksIncludingDeleted(ctx context.Context, idb bun.IDB) ([]model.Rack, error) {
	var racks []model.Rack
	if err := idb.NewSelect().Model(&racks).WhereAllWithDeleted().Scan(ctx); err != nil {
		return nil, err
	}
	return racks, nil
}

// rackNaturalKey joins manufacturer and serial number with a NUL byte. NUL
// can't appear inside either component, so this is collision-free without
// having to escape.
func rackNaturalKey(manufacturer, serialNumber string) string {
	return manufacturer + "\x00" + serialNumber
}

// flowBySerialInCore is a small helper: it scans Core's racks and returns
// whether any of them shares this Flow rack's (manufacturer, serial_number).
// Used to suppress the "legacy not in Core" warn for rows that the adoption
// path will pick up on this same cycle.
func flowBySerialInCore(r *model.Rack, coreRacks []nicoapi.ExpectedRackDetail) (string, bool) {
	want := rackNaturalKey(r.Manufacturer, r.SerialNumber)
	for _, cr := range coreRacks {
		manufacturer := cr.Labels[labelChassisManufacturer]
		serial := cr.Labels[labelChassisSerialNumber]
		if manufacturer == "" || serial == "" {
			continue
		}
		if rackNaturalKey(manufacturer, serial) == want {
			return cr.RackID, true
		}
	}
	return "", false
}

// buildRackFromCore translates one Core ExpectedRackDetail into the Flow Rack
// shape the mirror will insert. Returns false if the Core row is missing
// fields that Flow's rack table requires (manufacturer / serial_number are
// NOT NULL and form a unique key).
func buildRackFromCore(cr nicoapi.ExpectedRackDetail) (model.Rack, bool) {
	manufacturer := cr.Labels[labelChassisManufacturer]
	serial := cr.Labels[labelChassisSerialNumber]
	if manufacturer == "" || serial == "" {
		return model.Rack{}, false
	}

	name := cr.Name
	if name == "" {
		// Flow's rack.name is NOT NULL with a unique index. Fall back to
		// Core's stable rack_id first (operator-meaningful), then to
		// manufacturer-serial so the row is still insertable when Core has
		// neither. Operators can always rename later via the existing rack
		// PATCH path.
		switch {
		case cr.RackID != "":
			name = cr.RackID
		default:
			name = manufacturer + "-" + serial
		}
	}

	r := model.Rack{
		Name:         name,
		Manufacturer: manufacturer,
		SerialNumber: serial,
	}
	// Leave ExternalID NULL when Core has no rack_id. Storing an empty
	// string would still hit the partial unique index (which excludes NULL
	// but not the empty string), so two such racks would collide.
	if cr.RackID != "" {
		extID := cr.RackID
		r.ExternalID = &extID
	}

	if desc := rackDescriptionFromLabels(cr.Labels, cr.Description); len(desc) > 0 {
		r.Description = desc
	}
	if loc := rackLocationFromLabels(cr.Labels); len(loc) > 0 {
		r.Location = loc
	}
	return r, true
}

// rackDescriptionFromLabels extracts the JSONB-bound description fields the
// existing GetListOfRacks filter knows about (currently just "model") and
// preserves Core's free-form description text under "text". Returns an empty
// map when there's nothing to record so the caller can leave Description as
// SQL NULL.
func rackDescriptionFromLabels(labels map[string]string, description string) map[string]any {
	out := map[string]any{}
	if v := labels[labelChassisModel]; v != "" {
		out["model"] = v
	}
	if description != "" {
		out["text"] = description
	}
	return out
}

// rackLocationFromLabels extracts the well-known location.* labels into the
// JSONB Location column. Returns an empty map when none are present.
func rackLocationFromLabels(labels map[string]string) map[string]any {
	out := map[string]any{}
	if v := labels[labelLocationRegion]; v != "" {
		out["region"] = v
	}
	if v := labels[labelLocationDatacenter]; v != "" {
		out["datacenter"] = v
	}
	if v := labels[labelLocationRoom]; v != "" {
		out["room"] = v
	}
	if v := labels[labelLocationPosition]; v != "" {
		out["position"] = v
	}
	return out
}

// rackUpdatedFromCore returns a copy of `existing` with mirror-managed fields
// overwritten from `fromCore`. It deliberately does not touch identity
// (manufacturer / serial_number), lifecycle (status / ingested_at), or fields
// the mirror has no opinion on (nvldomain_id is out of scope for this PR; the
// runtime sync owns it).
//
// Returns nil when no patchable field changed so the caller can skip a no-op
// UPDATE.
func rackUpdatedFromCore(existing, fromCore *model.Rack) *model.Rack {
	patched := *existing
	changed := false

	if fromCore.Name != "" && existing.Name != fromCore.Name {
		patched.Name = fromCore.Name
		changed = true
	}
	if !reflect.DeepEqual(existing.Description, fromCore.Description) {
		patched.Description = fromCore.Description
		changed = true
	}
	if !reflect.DeepEqual(existing.Location, fromCore.Location) {
		patched.Location = fromCore.Location
		changed = true
	}
	// Adopt: existing.ExternalID was nil but fromCore now provides one.
	if (existing.ExternalID == nil || *existing.ExternalID == "") && fromCore.ExternalID != nil && *fromCore.ExternalID != "" {
		patched.ExternalID = fromCore.ExternalID
		changed = true
	}

	if !changed {
		return nil
	}
	return &patched
}
