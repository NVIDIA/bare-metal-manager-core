// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package vpcpeering

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"

	sc "github.com/NVIDIA/infra-controller-rest/workflow/pkg/client/site"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"

	cwutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
)

// ManageVpcPeering is an activity wrapper for managing VPC Peering lifecycle
// that allows injecting DB access
type ManageVpcPeering struct {
	dbSession      *cdb.Session
	siteClientPool *sc.ClientPool
}

// Activity functions

// UpdateVpcPeeringsInDB is a Temporal activity that takes a collection of
// VpcPeering data pushed by Site Agent and updates the DB
func (mvp ManageVpcPeering) UpdateVpcPeeringsInDB(
	ctx context.Context,
	siteID uuid.UUID,
	vpcPeeringInventory *cwssaws.VPCPeeringInventory,
) error {
	logger := log.With().Str("Activity", "UpdateVpcPeeringsInDB").Str("Site ID", siteID.String()).Logger()

	logger.Info().Msg("starting activity")

	if vpcPeeringInventory == nil {
		logger.Error().Msg("UpdateVpcPeeringsInDB called with nil inventory")
		return errors.New("UpdateVpcPeeringsInDB called with nil inventory")
	}

	// Check if Site exists in DB
	stDAO := cdbm.NewSiteDAO(mvp.dbSession)
	site, err := stDAO.GetByID(ctx, nil, siteID, nil, false)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			logger.Warn().Err(err).Msg("received VPC Peering inventory for unknown or deleted Site")
		} else {
			logger.Error().Err(err).Msg("failed to retrieve Site from DB")
		}
		return err
	}

	// Check if inventory status is correct
	if vpcPeeringInventory.InventoryStatus == cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED {
		logger.Warn().Msg("received failed inventory status from Site Agent, skipping inventory processing")
		return nil
	}

	vpcPeeringDAO := cdbm.NewVpcPeeringDAO(mvp.dbSession)
	existingVpcPeerings, _, err := vpcPeeringDAO.GetAll(ctx, nil, cdbm.VpcPeeringFilterInput{SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get VPC Peeringes for site from DB")
		return err
	}

	// Map of existing VPC Peerings in Cloud DB
	existingVpcPeeringIDMap := make(map[string]*cdbm.VpcPeering)
	for _, vpcPeering := range existingVpcPeerings {
		curVpcPeering := vpcPeering
		existingVpcPeeringIDMap[vpcPeering.ID.String()] = &curVpcPeering
	}

	// Map of VPC Peerings reported by Site Agent
	reportedVpcPeeringIDMap := map[uuid.UUID]bool{}
	// If inventory paging is enabled, we can get this list of item IDs from the inventory page's ItemIds field;
	// otherwise, we'll have to iterate through all VPC Peerings in the inventory later.
	if vpcPeeringInventory.InventoryPage != nil {
		logger.Info().Msgf("received VPC Peering inventory page: %d of %d, page size: %d, total count: %d",
			vpcPeeringInventory.InventoryPage.CurrentPage, vpcPeeringInventory.InventoryPage.TotalPages,
			vpcPeeringInventory.InventoryPage.PageSize, vpcPeeringInventory.InventoryPage.TotalItems)

		for _, strId := range vpcPeeringInventory.InventoryPage.ItemIds {
			id, serr := uuid.Parse(strId)
			if serr != nil {
				logger.Error().Err(serr).Str("ID", strId).Msg("failed to parse VPC Peering ID from inventory page")
				continue
			}
			reportedVpcPeeringIDMap[id] = true
		}
	}

	// Iterate through VpcPeering Inventory and update DB
	for _, controllerVpcPeering := range vpcPeeringInventory.VpcPeerings {
		slogger := logger.With().Str("controller VpcPeering ID", controllerVpcPeering.Id.Value).Logger()

		vpcPeering, found := existingVpcPeeringIDMap[controllerVpcPeering.Id.Value]
		if !found {
			slogger.Warn().Msg("VpcPeering does not have a record in DB, possibly created directly on Site. Creating in cloud DB.")

			// TODO: Create a new VPC Peering record in DB

			continue
		}

		// In the case inventory paging is not enabled, we build reportedVpcPeeringIdMap here.
		// This is redundant if paging is used, but isn't expensive.
		reportedVpcPeeringIDMap[vpcPeering.ID] = true

		// If VPC Peering is not in Deleting state, then update status to Ready
		if vpcPeering.Status != cdbm.VpcPeeringStatusDeleting && vpcPeering.Status != cdbm.VpcPeeringStatusReady {
			err = mvp.updateVpcPeeringStatusInDB(ctx, nil, vpcPeering.ID, cdb.GetStrPtr(cdbm.VpcPeeringStatusReady), cdb.GetStrPtr("VPC Peering has been re-detected on Site"))
			if err != nil {
				slogger.Error().Err(err).Msg("failed to update VPC Peering status detail in DB")
			}
		}

	}

	// Delete VPC Peerings that are not in the inventory. If inventory paging is enabled, we only need to do this once and we do it on the last page
	if vpcPeeringInventory.InventoryPage == nil || vpcPeeringInventory.InventoryPage.TotalPages == 0 || (vpcPeeringInventory.InventoryPage.CurrentPage == vpcPeeringInventory.InventoryPage.TotalPages) {
		for _, vpcPeering := range existingVpcPeeringIDMap {
			slogger := logger.With().Str("VPC Peering ID", vpcPeering.ID.String()).Logger()
			slogger.Info().Msg("checking for deletion")
			_, found := reportedVpcPeeringIDMap[vpcPeering.ID]
			if !found {

				// The Vpc Peering was not found in the VPC Peering Inventory,
				// so we should delete it, but we might be processing an older
				// inventory, so make sure the object has existed for at least as
				// long as our inventory interval with a little buffer to make
				// sure we aren't in lock-step.
				if time.Since(vpcPeering.Created) < cwutil.InventoryReceiptInterval {
					slogger.Info().Msg("not going to delete yet because VPC Peering is newer than the inventory interval")
					continue
				}

				slogger.Info().Msg("going to delete")

				serr := vpcPeeringDAO.Delete(ctx, nil, vpcPeering.ID)
				if serr != nil {
					slogger.Error().Err(serr).Msg("failed to delete VPC Peering from DB")
				}
			}
		}
	}

	return nil
}

// updateVpcPeeringStatusInDB is helper function to write VpcPeering updates to DB
func (mvp ManageVpcPeering) updateVpcPeeringStatusInDB(ctx context.Context, tx *cdb.Tx, vpcPeeringID uuid.UUID, status *string, statusMessage *string) error {
	if status != nil {
		VpcPeeringDAO := cdbm.NewVpcPeeringDAO(mvp.dbSession)

		err := VpcPeeringDAO.UpdateStatusByID(ctx, tx, vpcPeeringID, *status)
		if err != nil {
			return err
		}

		statusDetailDAO := cdbm.NewStatusDetailDAO(mvp.dbSession)
		_, err = statusDetailDAO.CreateFromParams(ctx, tx, vpcPeeringID.String(), *status, statusMessage)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewManageVpcPeering returns a new ManageVpcPeering activity
func NewManageVpcPeering(dbSession *cdb.Session, siteClientPool *sc.ClientPool) ManageVpcPeering {
	return ManageVpcPeering{
		dbSession:      dbSession,
		siteClientPool: siteClientPool,
	}
}
