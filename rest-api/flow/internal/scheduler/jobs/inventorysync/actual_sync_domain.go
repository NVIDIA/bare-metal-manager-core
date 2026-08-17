// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
)

// domainMirrorResult summarizes one committed actual domain-topology reconciliation.
type domainMirrorResult struct {
	pulled              int
	domainsInserted     int
	domainsResurrected  int
	domainsSoftDeleted  int
	membershipsAssigned int
	membershipsCleared  int
}

type clearedDomainMembership struct {
	rackExternalID string
	rackID         uuid.UUID
	domainID       uuid.UUID
}

type domainTopologySnapshot struct {
	domainByRack map[uuid.UUID]uuid.UUID
	domainIDs    map[uuid.UUID]struct{}
}

func (r domainMirrorResult) log() {
	log.Info().
		Str("resource", "nvlink_domains").
		Int("pulled", r.pulled).
		Int("domains_inserted", r.domainsInserted).
		Int("domains_resurrected", r.domainsResurrected).
		Int("domains_soft_deleted", r.domainsSoftDeleted).
		Int("memberships_assigned", r.membershipsAssigned).
		Int("memberships_cleared", r.membershipsCleared).
		Msg("Actual-inventory sync: NVLink domains")
}

func pullObservedNVLinkDomainMemberships(
	ctx context.Context,
	nicoClient nicoapi.Client,
) (rows []nicoapi.NVLinkDomainMembership, rpcOK bool) {
	rows, err := nicoClient.GetObservedNVLinkDomainMemberships(ctx)
	if err != nil {
		log.Error().Err(err).
			Msg("Actual-inventory sync: pulling observed NVLink domain memberships failed; preserving existing topology")
		return nil, false
	}
	return rows, true
}

func syncObservedNVLinkDomainTopology(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) {
	memberships, membershipsOK := pullObservedNVLinkDomainMemberships(ctx, nicoClient)
	if !membershipsOK {
		return
	}

	rackIDByExternalID, err := loadRackIDByExternalID(ctx, pool.DB)
	if err != nil {
		log.Error().Err(err).
			Msg("Actual-inventory sync: loading rack external_id map failed; preserving existing NVLink domain topology")
		return
	}

	result, err := mirrorObservedNVLinkDomainMemberships(ctx, pool, memberships, rackIDByExternalID)
	if err != nil {
		log.Error().Err(err).
			Msg("Actual-inventory sync: NVLink domain reconciliation failed; preserving existing topology")
		return
	}
	result.log()
}

// mirrorObservedNVLinkDomainMemberships reconciles a complete observed
// domain-topology snapshot into Flow. rackIDByExternalID translates inventory
// rack IDs into Flow rack UUIDs.
//
// A rack omitted from a successful snapshot has no observed domain membership
// and is cleared. Domain rows and rack memberships are committed together. A
// displaced domain is soft-deleted only when no active rack references it;
// unrelated unreferenced domains are preserved because Flow supports manual
// domain creation. Observations for racks absent from active Flow inventory are
// skipped with a warning without invalidating observations for known racks.
func mirrorObservedNVLinkDomainMemberships(
	ctx context.Context,
	pool *cdb.Session,
	memberships []nicoapi.NVLinkDomainMembership,
	rackIDByExternalID map[string]uuid.UUID,
) (domainMirrorResult, error) {
	result := domainMirrorResult{pulled: len(memberships)}
	snapshot, err := buildDomainTopologySnapshot(memberships, rackIDByExternalID)
	if err != nil {
		return result, err
	}

	rackExternalIDByID := make(map[uuid.UUID]string, len(rackIDByExternalID))
	for externalID, rackID := range rackIDByExternalID {
		rackExternalIDByID[rackID] = externalID
	}
	clearedMemberships := make([]clearedDomainMembership, 0)

	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		var existingDomains []model.NVLDomain
		err := tx.NewSelect().
			Model(&existingDomains).
			WhereAllWithDeleted().
			Scan(ctx)
		if err != nil {
			return fmt.Errorf("load existing NVLink domains: %w", err)
		}

		existingByID := make(map[uuid.UUID]*model.NVLDomain, len(existingDomains))
		for i := range existingDomains {
			existingByID[existingDomains[i].ID] = &existingDomains[i]
		}

		rackIDs := sortedUUIDValues(rackIDByExternalID)
		currentDomainByRack := make(map[uuid.UUID]uuid.UUID, len(rackIDs))
		if len(rackIDs) > 0 {
			var currentRacks []model.Rack
			err = tx.NewSelect().
				Model(&currentRacks).
				Column("id", "nvldomain_id").
				Where("id IN (?)", bun.In(rackIDs)).
				Scan(ctx)
			if err != nil {
				return fmt.Errorf("load current rack NVLink domain memberships: %w", err)
			}
			for i := range currentRacks {
				currentDomainByRack[currentRacks[i].ID] = currentRacks[i].NVLDomainID
			}
		}

		domainIDs := sortedUUIDKeys(snapshot.domainIDs)
		for _, domainID := range domainIDs {
			existing, found := existingByID[domainID]
			if !found {
				domain := model.NVLDomain{ID: domainID, Name: domainID.String()}
				_, err = tx.NewInsert().Model(&domain).Exec(ctx)
				if err != nil {
					return fmt.Errorf("insert NVLink domain %s: %w", domainID, err)
				}
				result.domainsInserted++
				continue
			}

			if existing.DeletedAt == nil {
				continue
			}

			updateResult, updateErr := tx.NewUpdate().
				Model(existing).
				Set("deleted_at = NULL").
				WhereAllWithDeleted().
				Where("id = ?", domainID).
				Where("deleted_at IS NOT NULL").
				Exec(ctx)
			if updateErr != nil {
				return fmt.Errorf("restore NVLink domain %s: %w", domainID, updateErr)
			}
			changed, rowsErr := updateResult.RowsAffected()
			if rowsErr != nil {
				return fmt.Errorf("count restored NVLink domains for %s: %w", domainID, rowsErr)
			}
			result.domainsResurrected += int(changed)
		}

		now := time.Now()
		displacedDomainIDs := make(map[uuid.UUID]struct{})
		for _, rackID := range rackIDs {
			domainID, assigned := snapshot.domainByRack[rackID]
			currentDomainID := currentDomainByRack[rackID]
			if currentDomainID != uuid.Nil && (!assigned || currentDomainID != domainID) {
				displacedDomainIDs[currentDomainID] = struct{}{}
			}
			query := tx.NewUpdate().
				Model((*model.Rack)(nil)).
				Set("updated_at = ?", now).
				Where("id = ?", rackID)
			if assigned {
				query = query.
					Set("nvldomain_id = ?", domainID).
					Where("nvldomain_id IS DISTINCT FROM ?", domainID)
			} else {
				query = query.
					Set("nvldomain_id = NULL").
					Where("nvldomain_id IS NOT NULL")
			}

			updateResult, updateErr := query.Exec(ctx)
			if updateErr != nil {
				return fmt.Errorf("reconcile NVLink domain for rack %s: %w", rackID, updateErr)
			}
			changed, rowsErr := updateResult.RowsAffected()
			if rowsErr != nil {
				return fmt.Errorf("count NVLink domain changes for rack %s: %w", rackID, rowsErr)
			}
			if changed == 0 {
				continue
			}
			if assigned {
				result.membershipsAssigned += int(changed)
			} else {
				result.membershipsCleared += int(changed)
				clearedMemberships = append(clearedMemberships, clearedDomainMembership{
					rackExternalID: rackExternalIDByID[rackID],
					rackID:         rackID,
					domainID:       currentDomainID,
				})
			}
		}

		var referencedDomainIDs []uuid.UUID
		err = tx.NewSelect().
			Model((*model.Rack)(nil)).
			Column("nvldomain_id").
			Where("nvldomain_id IS NOT NULL").
			Group("nvldomain_id").
			Scan(ctx, &referencedDomainIDs)
		if err != nil {
			return fmt.Errorf("load active rack NVLink domain references: %w", err)
		}
		referencedDomainIDSet := make(map[uuid.UUID]struct{}, len(referencedDomainIDs))
		for _, domainID := range referencedDomainIDs {
			referencedDomainIDSet[domainID] = struct{}{}
		}

		for i := range existingDomains {
			existing := &existingDomains[i]
			if existing.DeletedAt != nil {
				continue
			}
			_, displaced := displacedDomainIDs[existing.ID]
			if !displaced {
				continue
			}
			_, referenced := referencedDomainIDSet[existing.ID]
			if referenced {
				continue
			}

			deleteResult, deleteErr := tx.NewDelete().
				Model(existing).
				Where("id = ?", existing.ID).
				Exec(ctx)
			if deleteErr != nil {
				return fmt.Errorf("soft-delete stale NVLink domain %s: %w", existing.ID, deleteErr)
			}
			changed, rowsErr := deleteResult.RowsAffected()
			if rowsErr != nil {
				return fmt.Errorf("count stale NVLink domain deletes for %s: %w", existing.ID, rowsErr)
			}
			result.domainsSoftDeleted += int(changed)
		}

		return nil
	})
	if err != nil {
		return domainMirrorResult{pulled: len(memberships)}, err
	}
	for _, cleared := range clearedMemberships {
		log.Info().
			Str("rack_external_id", cleared.rackExternalID).
			Stringer("rack_id", cleared.rackID).
			Stringer("previous_domain_id", cleared.domainID).
			Msg("Actual-inventory sync: cleared rack NVLink domain membership because the observed snapshot contained no valid membership")
	}

	return result, nil
}

func buildDomainTopologySnapshot(
	memberships []nicoapi.NVLinkDomainMembership,
	rackIDByExternalID map[string]uuid.UUID,
) (domainTopologySnapshot, error) {
	domainByRack := make(map[uuid.UUID]uuid.UUID)
	domainIDs := make(map[uuid.UUID]struct{})
	unknownRackIDs := make(map[string]struct{})
	skippedUnknownMemberships := 0

	for _, membership := range memberships {
		domainID, err := uuid.Parse(membership.DomainID)
		if err != nil || domainID == uuid.Nil {
			return domainTopologySnapshot{}, fmt.Errorf("invalid observed NVLink domain ID %q", membership.DomainID)
		}

		rackID, ok := rackIDByExternalID[membership.RackID]
		if !ok {
			unknownRackIDs[membership.RackID] = struct{}{}
			skippedUnknownMemberships++
			continue
		}

		currentDomainID, exists := domainByRack[rackID]
		if exists && currentDomainID != domainID {
			return domainTopologySnapshot{}, fmt.Errorf(
				"rack %q has conflicting observed NVLink domains %s and %s",
				membership.RackID, currentDomainID, domainID,
			)
		}

		domainByRack[rackID] = domainID
		domainIDs[domainID] = struct{}{}
	}

	if skippedUnknownMemberships > 0 {
		unknownRacks := make([]string, 0, len(unknownRackIDs))
		for rackID := range unknownRackIDs {
			unknownRacks = append(unknownRacks, rackID)
		}
		sort.Strings(unknownRacks)
		log.Warn().
			Int("skipped_memberships", skippedUnknownMemberships).
			Strs("rack_external_ids", unknownRacks).
			Msg("Actual-inventory sync: skipped observed NVLink domain memberships for racks absent from Flow rack inventory")
	}

	return domainTopologySnapshot{domainByRack: domainByRack, domainIDs: domainIDs}, nil
}

func sortedUUIDKeys(values map[uuid.UUID]struct{}) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	return ids
}

func sortedUUIDValues(values map[string]uuid.UUID) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(values))
	for _, id := range values {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	return ids
}
