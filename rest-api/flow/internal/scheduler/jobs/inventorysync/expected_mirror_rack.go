// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
)

// rackNameReservation is a comparable description of the rack that owns one
// name during planning. Equality means the same Flow row or Core identity may
// safely reserve its own name again; any different value is a collision.
type rackNameReservation struct {
	flowID       uuid.UUID
	coreRackID   string
	manufacturer string
	serialNumber string
}

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
	// An exact external-ID owner always outranks natural-key adoption of the
	// same Flow row. Record those claims before validating labels or planning
	// names so a temporarily malformed owner still protects its row. When the
	// old external ID is absent from Core, no claim is recorded and the normal
	// natural-key path can adopt a legitimate rack-ID rename.
	exactCoreRackIDByFlowID := make(map[uuid.UUID]string)
	for _, rack := range coreRacks {
		if rack.RackID == "" {
			continue
		}
		existing, exists := flowByExtID[rack.RackID]
		if !exists {
			continue
		}
		exactCoreRackIDByFlowID[existing.ID] = rack.RackID
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
	// `reservedByName` starts with every live row and grows with each accepted
	// INSERT or UPDATE. Keeping the whole plan in the same index is what stops
	// two pending writes from reaching `rack_name_idx` with the same target
	// name and rolling back an unrelated rack change. Names are deliberately
	// not released when a rack plans to rename: INSERTs execute before UPDATEs,
	// so an insert claiming the old name would still hit the live row before
	// its rename runs. That conservative reservation defers reuse to a later
	// cycle instead of risking a transaction-wide rollback. A true name swap
	// remains a conflict and needs operator resolution.
	reservedByName := make(map[string]rackNameReservation)
	for i := range flowRacks {
		r := &flowRacks[i]
		if r.DeletedAt != nil {
			tombstonesByName[r.Name] = r
			continue
		}
		reservedByName[r.Name] = rackNameReservationForFlowRack(r)
	}
	// Protect the current name of every tombstone Core still identifies. A
	// renamed resurrection runs after INSERTs, so allowing an insert to reuse
	// that old name would make tombstone GC erase the row before its UPDATE.
	// Unmatched tombstones stay unreserved and can still be collected for name
	// reuse. Match precedence must remain identical to the main planner:
	// external_id first (even when Core's labels are malformed), then a valid
	// natural key. An external-ID match stays protected across a temporary label
	// gap even though the malformed Core row cannot be mirrored that cycle.
	reserveMatchedTombstoneNames(coreRacks, flowByExtID, flowBySerial, reservedByName)

	// seenExtID: every Core rack_id still reported this cycle, recorded
	// BEFORE any skip so the delete phase never drops a Flow rack Core is
	// still listing (even one whose labels are momentarily incomplete).
	// touchedIDs: Flow rack UUIDs matched by a valid Core row. The delete phase
	// skips them so a rack_id rename (update to the new external_id) isn't
	// immediately undone by a soft-delete keyed off the stale in-memory
	// external_id. plannedExtID and plannedSerial drop Core duplicates before
	// they collide on Flow's unique external-ID or (manufacturer, serial)
	// indexes.
	seenExtID := make(map[string]struct{}, len(coreRacks))
	touchedIDs := make(map[uuid.UUID]struct{}, len(coreRacks))
	plannedExtID := make(map[string]struct{}, len(coreRacks))
	plannedSerial := make(map[string]struct{}, len(coreRacks))

	for _, cr := range orderCoreRacksForPlanning(coreRacks) {
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
		} else {
			_, planned := plannedExtID[cr.RackID]
			if planned {
				log.Warn().
					Str("rack_id", cr.RackID).
					Str("rack_name", built.Name).
					Str("rack_manufacturer", built.Manufacturer).
					Str("rack_serial", built.SerialNumber).
					Msg("Expected-inventory mirror: Core returned duplicate expected racks with the same rack_id; skipping the later occurrence")
				continue
			}
			plannedExtID[cr.RackID] = struct{}{}
		}

		// Prefer external_id match (already adopted on a previous cycle), then
		// fall back to the natural key. matchFlowRackForCore is also used by the
		// tombstone source-name pre-reservation above so both passes select the
		// same row.
		existing, matchedByExternalID := matchFlowRackForCore(cr, flowByExtID, flowBySerial)
		if existing != nil && !matchedByExternalID {
			exactOwnerRackID, claimed := exactCoreRackIDByFlowID[existing.ID]
			if claimed {
				log.Warn().
					Str("rack_id", cr.RackID).
					Str("rack_name", built.Name).
					Str("rack_manufacturer", built.Manufacturer).
					Str("rack_serial", built.SerialNumber).
					Str("flow_rack_id", existing.ID.String()).
					Str("exact_owner_rack_id", exactOwnerRackID).
					Msg("Expected-inventory mirror: Core rack natural identity resolves to a Flow rack still owned by another reported rack_id; skipping adoption")
				continue
			}
		}

		// Drop Core duplicates: planning the same chassis twice would queue a
		// second INSERT that collides on the (manufacturer, serial) unique
		// index and roll back the whole rack mirror. This check follows the
		// exact-owner guard so a natural-key claimant cannot preempt the Flow
		// row's reported external-ID owner merely by sorting first.
		natKey := rackNaturalKey(built.Manufacturer, built.SerialNumber)
		_, planned := plannedSerial[natKey]
		if planned {
			log.Warn().
				Str("rack_id", cr.RackID).
				Str("manufacturer", built.Manufacturer).
				Str("serial", built.SerialNumber).
				Msg("Expected-inventory mirror: Core returned duplicate expected racks for the same chassis; skipping the later occurrence")
			continue
		}
		plannedSerial[natKey] = struct{}{}

		if existing != nil {
			touchedIDs[existing.ID] = struct{}{}
		}
		if existing != nil && matchedByExternalID {
			candidate := *existing
			needUpdate := false
			wasDeleted := candidate.DeletedAt != nil
			if wasDeleted {
				candidate.DeletedAt = nil
				needUpdate = true
			}
			if patched := rackUpdatedFromCore(&candidate, &built); patched != nil {
				candidate = *patched
				needUpdate = true
			}
			if needUpdate {
				reservation := rackNameReservationForFlowRack(existing)
				nameOwner, reserved := reserveRackName(reservedByName, candidate.Name, reservation)
				if !reserved {
					logRackNameCollision("update", cr, candidate, nameOwner)
					result.skippedNameTaken++
					continue
				}
				p.toUpdate = append(p.toUpdate, candidate)
				if wasDeleted {
					result.resurrected++
				}
			}
			continue
		}

		// Fall back to natural key (legacy ingestion-gRPC rows the mirror has
		// never adopted; adopt by writing external_id alongside any deltas).
		// A serial match that's also soft-deleted gets resurrected at the
		// same time — see the function-level comment for why this matters.
		if existing != nil {
			candidate := *existing
			reservation := rackNameReservationForFlowRack(existing)
			candidate.ExternalID = built.ExternalID
			wasDeleted := candidate.DeletedAt != nil
			if wasDeleted {
				candidate.DeletedAt = nil
			}
			if patched := rackUpdatedFromCore(&candidate, &built); patched != nil {
				candidate = *patched
			}
			nameOwner, reserved := reserveRackName(reservedByName, candidate.Name, reservation)
			if !reserved {
				logRackNameCollision("adoption", cr, candidate, nameOwner)
				result.skippedNameTaken++
				continue
			}
			p.toUpdate = append(p.toUpdate, candidate)
			if wasDeleted {
				result.resurrected++
			}
			result.adopted++
			continue
		}

		reservation := rackNameReservationForFlowRack(&built)
		nameOwner, reserved := reserveRackName(reservedByName, built.Name, reservation)
		if !reserved {
			logRackNameCollision("insert", cr, built, nameOwner)
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
			updateResult, updateErr := tx.NewUpdate().
				Model(&p.toUpdate[i]).
				Column("name", "description", "location", "external_id", "deleted_at", "updated_at").
				WhereAllWithDeleted().
				Where("id = ?", p.toUpdate[i].ID).
				Exec(ctx)
			if updateErr != nil {
				return fmt.Errorf("update rack %q: %w", p.toUpdate[i].Name, updateErr)
			}
			rowsAffected, rowsErr := updateResult.RowsAffected()
			if rowsErr != nil {
				return fmt.Errorf("read affected rows after updating rack %q: %w", p.toUpdate[i].Name, rowsErr)
			}
			if rowsAffected != 1 {
				// The plan was built from one coherent snapshot. If that row no
				// longer exists, roll the transaction back and let the next cycle
				// rebuild from fresh state instead of reporting partial success.
				return fmt.Errorf(
					"update rack %q (id %s) affected %d rows, expected 1",
					p.toUpdate[i].Name,
					p.toUpdate[i].ID,
					rowsAffected,
				)
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

// orderCoreRacksForPlanning returns a copy in deterministic identity order.
// Rows with a Core `rack_id` come first; rows missing one fall back to the
// chassis key.
// The remaining mirrored and diagnostic fields provide deterministic tie
// breakers, including every label in sorted key order. This makes the same
// rack win a contested name even if the RPC response order changes between
// reconciliation cycles.
func orderCoreRacksForPlanning(coreRacks []nicoapi.ExpectedRackDetail) []nicoapi.ExpectedRackDetail {
	type keyedRack struct {
		rack nicoapi.ExpectedRackDetail
		key  []string
	}
	keyed := make([]keyedRack, len(coreRacks))
	for i, rack := range coreRacks {
		keyed[i] = keyedRack{rack: rack, key: rackPlanningKey(rack)}
	}
	slices.SortFunc(keyed, func(a, b keyedRack) int {
		return slices.Compare(a.key, b.key)
	})
	ordered := make([]nicoapi.ExpectedRackDetail, len(keyed))
	for i := range keyed {
		ordered[i] = keyed[i].rack
	}
	return ordered
}

func rackPlanningKey(rack nicoapi.ExpectedRackDetail) []string {
	idPresence := "0"
	if rack.RackID == "" {
		idPresence = "1"
	}
	key := []string{
		idPresence,
		rack.RackID,
		rack.Labels[labelChassisManufacturer],
		rack.Labels[labelChassisSerialNumber],
		rack.Name,
		rack.RackProfileID,
		rack.Description,
	}
	labelKeys := slices.Sorted(maps.Keys(rack.Labels))
	for _, labelKey := range labelKeys {
		if labelKey == labelChassisManufacturer || labelKey == labelChassisSerialNumber {
			continue
		}
		key = append(key, labelKey, rack.Labels[labelKey])
	}
	return key
}

// matchFlowRackForCore applies the planner's authoritative identity precedence.
// An external-id match wins even when the Core row lacks the labels required to
// update it; this lets the pre-planning pass protect that row from tombstone GC.
// Natural-key fallback is only possible with both required chassis labels.
func matchFlowRackForCore(
	rack nicoapi.ExpectedRackDetail,
	flowByExtID map[string]*model.Rack,
	flowBySerial map[string]*model.Rack,
) (*model.Rack, bool) {
	if rack.RackID != "" {
		existing, exists := flowByExtID[rack.RackID]
		if exists {
			return existing, true
		}
	}
	manufacturer := rack.Labels[labelChassisManufacturer]
	serialNumber := rack.Labels[labelChassisSerialNumber]
	if manufacturer == "" || serialNumber == "" {
		return nil, false
	}
	existing, exists := flowBySerial[rackNaturalKey(manufacturer, serialNumber)]
	if !exists {
		return nil, false
	}
	return existing, false
}

// reserveMatchedTombstoneNames protects the source names of tombstones Core
// still identifies so an earlier INSERT cannot delete a row queued for
// resurrection later in the same transaction.
func reserveMatchedTombstoneNames(
	coreRacks []nicoapi.ExpectedRackDetail,
	flowByExtID map[string]*model.Rack,
	flowBySerial map[string]*model.Rack,
	reservedByName map[string]rackNameReservation,
) {
	for _, rack := range coreRacks {
		existing, _ := matchFlowRackForCore(rack, flowByExtID, flowBySerial)
		if existing == nil || existing.DeletedAt == nil {
			continue
		}
		reservedByName[existing.Name] = rackNameReservationForFlowRack(existing)
	}
}

func rackNameReservationForFlowRack(rack *model.Rack) rackNameReservation {
	reservation := rackNameReservation{
		flowID:       rack.ID,
		manufacturer: rack.Manufacturer,
		serialNumber: rack.SerialNumber,
	}
	if rack.ExternalID != nil {
		reservation.coreRackID = *rack.ExternalID
	}
	return reservation
}

// reserveRackName records one accepted target name. The returned values identify
// the winning owner and whether the candidate won. A rejected candidate leaves
// the existing reservation untouched so the caller can skip only that operation.
func reserveRackName(
	reservedByName map[string]rackNameReservation,
	name string,
	reservation rackNameReservation,
) (rackNameReservation, bool) {
	existing, ok := reservedByName[name]
	if ok && existing != reservation {
		return existing, false
	}
	reservedByName[name] = reservation
	return reservation, true
}

func logRackNameCollision(
	operation string,
	coreRack nicoapi.ExpectedRackDetail,
	candidate model.Rack,
	nameOwner rackNameReservation,
) {
	event := log.Warn().
		Str("rack_id", coreRack.RackID).
		Str("rack_name", candidate.Name).
		Str("rack_manufacturer", candidate.Manufacturer).
		Str("rack_serial", candidate.SerialNumber).
		Str("operation", operation)
	if candidate.ID != uuid.Nil {
		event.Str("skipped_flow_id", candidate.ID.String())
	}
	if nameOwner.flowID != uuid.Nil {
		event.Str("name_owner_flow_id", nameOwner.flowID.String())
	}
	if nameOwner.coreRackID != "" {
		event.Str("name_owner_core_rack_id", nameOwner.coreRackID)
	}
	if nameOwner.manufacturer != "" {
		event.Str("name_owner_manufacturer", nameOwner.manufacturer)
	}
	if nameOwner.serialNumber != "" {
		event.Str("name_owner_serial", nameOwner.serialNumber)
	}
	event.Msg("Expected-inventory mirror: Core rack name already held or reserved by another rack; skipping this operation to avoid a unique-name abort (operator must resolve the duplicate name)")
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
