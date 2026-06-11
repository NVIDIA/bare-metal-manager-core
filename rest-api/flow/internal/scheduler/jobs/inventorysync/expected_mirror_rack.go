// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
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

// pullExpectedRacks wraps the nicoapi RPC with the single safety guard the
// mirror needs: an RPC failure returns rpcOK=false so the caller skips
// reconciliation entirely and leaves Flow untouched. A *successful* RPC is
// authoritative even when it returns zero rows — the caller then soft-deletes
// every mirror-adopted Flow rack, because Core saying "no racks" is a real
// state, not a blip. This relies on Core surfacing transient unavailability
// (restarts, mid-migration) as an RPC error rather than an empty result.
func pullExpectedRacks(
	ctx context.Context,
	nicoClient nicoapi.Client,
) (rows []nicoapi.ExpectedRackDetail, rpcOK bool) {
	rows, err := nicoClient.GetAllExpectedRackDetails(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Expected-inventory mirror: pulling expected racks from Core failed; skipping rack mirror this cycle")
		return nil, false
	}
	if len(rows) == 0 {
		log.Warn().Msg("Expected-inventory mirror: Core returned zero expected racks; mirror will soft-delete all mirror-adopted Flow racks this cycle")
	}
	return rows, true
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
//  3. Live Flow rows whose external_id is set but no longer appear in Core
//     are soft-deleted (including the case where Core returned zero racks —
//     the caller only invokes this after a successful RPC, so empty is
//     authoritative). Soft-deleted rows Core doesn't report either are left
//     alone (already gone). Rows with a NULL external_id (legacy
//     ingestion-gRPC rows the mirror has never adopted) are exempted and
//     warn-logged so the operator has a visible signal of pending cleanup.
//
// All writes for one pass happen in a single transaction so partial failures
// can't leave the table half-mirrored.
func mirrorExpectedRacks(
	ctx context.Context,
	pool *cdb.Session,
	coreRacks []nicoapi.ExpectedRackDetail,
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
	// liveByName: name -> id of every live (non-deleted) rack. rack_name_idx
	// is a full unique index, so an INSERT or UPDATE that writes a name a
	// different live rack already holds would roll back the whole cycle.
	// The mirror skips the colliding write and logs instead. A soft-deleted
	// row holding the name is handled separately by gcTombstoneForNameReuse.
	liveByName := make(map[string]uuid.UUID)
	for i := range flowRacks {
		r := &flowRacks[i]
		if r.DeletedAt != nil {
			tombstonesByName[r.Name] = r
			continue
		}
		liveByName[r.Name] = r.ID
	}

	// seenExtID: every Core rack_id still reported this cycle, recorded
	// BEFORE any skip so the delete phase never drops a Flow rack Core is
	// still listing (even one whose labels are momentarily incomplete).
	// touchedIDs: Flow rack UUIDs the match path adopted / updated this
	// cycle; the delete phase skips them so a rack_id rename (update to the
	// new external_id) isn't immediately undone by a soft-delete keyed off
	// the stale in-memory external_id. plannedSerial: natural keys already
	// queued, to drop Core duplicates before they collide on the
	// (manufacturer, serial) unique index.
	seenExtID := make(map[string]struct{}, len(coreRacks))
	touchedIDs := make(map[uuid.UUID]struct{}, len(coreRacks))
	plannedSerial := make(map[string]struct{}, len(coreRacks))

	for _, cr := range coreRacks {
		// Record the rack_id as "still reported" before any skip below.
		if cr.RackID != "" {
			seenExtID[cr.RackID] = struct{}{}
		}

		built, ok := buildRackFromCore(cr)
		if !ok {
			// Required fields (manufacturer / serial) missing in Core's labels;
			// inserting would violate NOT NULL or the (manufacturer, serial)
			// unique constraint. Skip the write, but the rack_id is already in
			// seenExtID so we don't soft-delete an existing Flow rack over a
			// transient label gap.
			log.Warn().
				Str("rack_id", cr.RackID).
				Str("name", cr.Name).
				Msg("Expected-inventory mirror: skipping Core expected rack missing chassis manufacturer or serial-number labels; existing Flow rack preserved")
			result.skippedNoIDOrKey++
			continue
		}

		if cr.RackID == "" {
			log.Warn().
				Str("rack_profile_id", cr.RackProfileID).
				Str("name", cr.Name).
				Str("manufacturer", built.Manufacturer).
				Str("serial", built.SerialNumber).
				Msg("Expected-inventory mirror: Core expected rack has no rack_id; rack will be mirrored but components can't reference it")
		}

		// Drop Core duplicates: planning the same chassis twice would queue a
		// second INSERT that collides on the (manufacturer, serial) unique
		// index and roll back the whole rack mirror.
		natKey := rackNaturalKey(built.Manufacturer, built.SerialNumber)
		if _, planned := plannedSerial[natKey]; planned {
			log.Warn().
				Str("rack_id", cr.RackID).
				Str("manufacturer", built.Manufacturer).
				Str("serial", built.SerialNumber).
				Msg("Expected-inventory mirror: Core returned duplicate expected racks for the same chassis; skipping the later occurrence")
			continue
		}
		plannedSerial[natKey] = struct{}{}

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
			if needUpdate && nameTakenByOtherLiveRack(liveByName, candidate.Name, existing.ID) {
				log.Warn().
					Str("rack_id", cr.RackID).
					Str("name", candidate.Name).
					Str("rack_serial", candidate.SerialNumber).
					Msg("Expected-inventory mirror: Core rack name already held by a different live Flow rack; skipping this update to avoid a unique-name abort (operator must resolve the duplicate name)")
				result.skippedNameTaken++
				touchedIDs[existing.ID] = struct{}{}
				continue
			}
			if needUpdate {
				p.toUpdate = append(p.toUpdate, candidate)
			}
			touchedIDs[existing.ID] = struct{}{}
			continue
		}

		// Fall back to natural key (legacy ingestion-gRPC rows the mirror has
		// never adopted; adopt by writing external_id alongside any deltas).
		// A serial match that's also soft-deleted gets resurrected at the
		// same time — see the function-level comment for why this matters.
		if existing, ok := flowBySerial[natKey]; ok {
			candidate := *existing
			candidate.ExternalID = built.ExternalID
			if candidate.DeletedAt != nil {
				candidate.DeletedAt = nil
				result.resurrected++
			}
			if patched := rackUpdatedFromCore(&candidate, &built); patched != nil {
				candidate = *patched
			}
			if nameTakenByOtherLiveRack(liveByName, candidate.Name, existing.ID) {
				log.Warn().
					Str("rack_id", cr.RackID).
					Str("name", candidate.Name).
					Str("rack_serial", candidate.SerialNumber).
					Msg("Expected-inventory mirror: Core rack name already held by a different live Flow rack; skipping this adoption to avoid a unique-name abort (operator must resolve the duplicate name)")
				result.skippedNameTaken++
				touchedIDs[existing.ID] = struct{}{}
				continue
			}
			p.toUpdate = append(p.toUpdate, candidate)
			touchedIDs[existing.ID] = struct{}{}
			result.adopted++
			continue
		}

		if nameTakenByOtherLiveRack(liveByName, built.Name, uuid.Nil) {
			log.Warn().
				Str("rack_id", cr.RackID).
				Str("name", built.Name).
				Str("rack_serial", built.SerialNumber).
				Msg("Expected-inventory mirror: Core rack name already held by a different live Flow rack; skipping this insert to avoid a unique-name abort (operator must resolve the duplicate name)")
			result.skippedNameTaken++
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
		// Skip rows the match path already adopted / updated this cycle. A
		// rack_id rename updates the row to the new external_id; without this
		// guard the delete phase would see the stale in-memory external_id
		// (not in seenExtID) and soft-delete the row we just renamed.
		if _, touched := touchedIDs[r.ID]; touched {
			continue
		}
		hasExt := r.ExternalID != nil && *r.ExternalID != ""
		if hasExt {
			if _, present := seenExtID[*r.ExternalID]; present {
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

	now := time.Now()
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
			// Mirror-managed columns only; status / ingested_at / nvldomain_id
			// belong to other paths. WhereAllWithDeleted is required so a
			// resurrection (deleted_at cleared in Go) matches the tombstone —
			// bun otherwise appends "deleted_at IS NULL" to the UPDATE and the
			// resurrect silently matches zero rows.
			p.toUpdate[i].UpdatedAt = now
			if _, err := tx.NewUpdate().
				Model(&p.toUpdate[i]).
				Column("name", "description", "location", "external_id", "deleted_at", "updated_at").
				WhereAllWithDeleted().
				Where("id = ?", p.toUpdate[i].ID).
				Exec(ctx); err != nil {
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
		// Tx rolled back: per-spec decisions logged above describe intent,
		// not committed state. Strip success-side counters so the summary
		// log reflects what actually landed (nothing). pulled,
		// skippedNoIDOrKey and legacyExempt survive: they're decided
		// before the tx opened and aren't invalidated by the rollback.
		result.resurrected = 0
		result.adopted = 0
		return result
	}

	result.inserted = len(p.toInsert)
	result.updated = len(p.toUpdate)
	result.softDeleted = len(p.toDelete)
	return result
}

// nameTakenByOtherLiveRack reports whether a live (non-deleted) Flow rack
// other than selfID already holds name. selfID is uuid.Nil for an INSERT.
func nameTakenByOtherLiveRack(liveByName map[string]uuid.UUID, name string, selfID uuid.UUID) bool {
	id, ok := liveByName[name]
	return ok && id != selfID
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
	// Only overwrite Description / Location when Core actually carries a
	// value. buildRackFromCore leaves these nil when the labels are absent;
	// overwriting with an empty/nil map would wipe operator-set rack metadata
	// every cycle (and DeepEqual(nil, map{}) would also churn a no-op UPDATE).
	if len(fromCore.Description) > 0 && !reflect.DeepEqual(existing.Description, fromCore.Description) {
		patched.Description = fromCore.Description
		changed = true
	}
	if len(fromCore.Location) > 0 && !reflect.DeepEqual(existing.Location, fromCore.Location) {
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
