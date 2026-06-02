// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package vpcprefix

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/ipam"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"

	sc "github.com/NVIDIA/infra-controller-rest/workflow/pkg/client/site"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"

	cwutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
)

// ManageVpcPrefix is an activity wrapper for managing VPC Prefix lifecycle that allows
// injecting DB access
type ManageVpcPrefix struct {
	dbSession      *cdb.Session
	siteClientPool *sc.ClientPool
}

// Activity functions
// UpdateVpcPrefixesInDB is a Temporal activity that takes a collection of VPC Prefix data pushed by Site Agent and updates the DB
func (mvp ManageVpcPrefix) UpdateVpcPrefixesInDB(ctx context.Context, siteID uuid.UUID, vpcPrefixInventory *cwssaws.VpcPrefixInventory) error {
	logger := log.With().Str("Activity", "UpdateVpcPrefixesInDB").Str("Site ID", siteID.String()).Logger()

	logger.Info().Msg("starting activity")

	stDAO := cdbm.NewSiteDAO(mvp.dbSession)

	site, err := stDAO.GetByID(ctx, nil, siteID, nil, false)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			logger.Warn().Err(err).Msg("received VPC Prefix inventory for unknown or deleted Site")
		} else {
			logger.Error().Err(err).Msg("failed to retrieve Site from DB")
		}
		return err
	}

	if vpcPrefixInventory.InventoryStatus == cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED {
		logger.Warn().Msg("received failed inventory status from Site Agent, skipping inventory processing")
		return nil
	}

	vpcPrefixDAO := cdbm.NewVpcPrefixDAO(mvp.dbSession)

	existingVpcPrefixes, _, err := vpcPrefixDAO.GetAll(ctx, nil, cdbm.VpcPrefixFilterInput{SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get VPC Prefixes for Site from DB")
		return err
	}

	// Construct a map of Controller VPC Prefix ID to VPC Prefix
	existingVpcPrefixIDMap := make(map[string]*cdbm.VpcPrefix)
	for _, vpcPrefix := range existingVpcPrefixes {
		curVpcPrefix := vpcPrefix
		existingVpcPrefixIDMap[vpcPrefix.ID.String()] = &curVpcPrefix
	}

	reportedVpcPrefixIDMap := map[uuid.UUID]bool{}

	if vpcPrefixInventory.InventoryPage != nil {
		logger.Info().Msgf("Received VPC Prefix inventory page: %d of %d, page size: %d, total count: %d",
			vpcPrefixInventory.InventoryPage.CurrentPage, vpcPrefixInventory.InventoryPage.TotalPages,
			vpcPrefixInventory.InventoryPage.PageSize, vpcPrefixInventory.InventoryPage.TotalItems)

		for _, strId := range vpcPrefixInventory.InventoryPage.ItemIds {
			id, serr := uuid.Parse(strId)
			if serr != nil {
				logger.Error().Err(serr).Str("ID", strId).Msg("failed to parse VPC Prefix ID from inventory page")
				continue
			}
			reportedVpcPrefixIDMap[id] = true
		}
	}

	// Iterate through VpcPrefix Inventory and update DB
	for _, controllerVpcPrefix := range vpcPrefixInventory.VpcPrefixes {
		slogger := logger.With().Str("VPC Prefix Controller ID", controllerVpcPrefix.Id.Value).Logger()

		vpcPrefix := existingVpcPrefixIDMap[controllerVpcPrefix.Id.Value]
		if vpcPrefix == nil {
			logger.Warn().Str("Controller VPC Prefix ID", controllerVpcPrefix.Id.Value).Msg("VPC Prefix does not have a record in DB, possibly created directly on Site")
			continue
		}

		reportedVpcPrefixIDMap[vpcPrefix.ID] = true

		// Reset missing flag if necessary
		var isMissingOnSite *bool
		if vpcPrefix.IsMissingOnSite {
			isMissingOnSite = cdb.GetBoolPtr(false)
		}

		if isMissingOnSite != nil {
			_, serr := vpcPrefixDAO.Update(ctx, nil, cdbm.VpcPrefixUpdateInput{VpcPrefixID: vpcPrefix.ID, IsMissingOnSite: isMissingOnSite})
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to update missing on Site flag/controller VPC Prefix ID in DB")
				continue
			}
		}

		// If VPC Prefix is not in Deleting state, then update status to Ready
		if vpcPrefix.Status != cdbm.VpcPrefixStatusDeleting && vpcPrefix.Status != cdbm.VpcPrefixStatusReady {
			err = mvp.updateVpcPrefixStatusInDB(ctx, nil, vpcPrefix.ID, cdb.GetStrPtr(cdbm.VpcPrefixStatusReady), cdb.GetStrPtr("VPC Prefix has been re-detected on Site"))
			if err != nil {
				slogger.Error().Err(err).Msg("failed to update VPC Prefix status detail in DB")
			}
		}

	}

	// Populate list of VpcPrefixes that were not found
	vpcPrefixesToDelete := []*cdbm.VpcPrefix{}

	// If inventory paging is enabled, we only need to do this once and we do it on the last page
	if vpcPrefixInventory.InventoryPage == nil || vpcPrefixInventory.InventoryPage.TotalPages == 0 || (vpcPrefixInventory.InventoryPage.CurrentPage == vpcPrefixInventory.InventoryPage.TotalPages) {
		for _, vpcPrefix := range existingVpcPrefixIDMap {
			found := false

			_, found = reportedVpcPrefixIDMap[vpcPrefix.ID]
			if !found {
				// The VpcPrefix was not found in the VpcPrefix Inventory, so add it to list of VpcPrefixes to potentially terminate
				vpcPrefixesToDelete = append(vpcPrefixesToDelete, vpcPrefix)
			}
		}
	}

	// Loop through VpcPrefixes for deletion
	for _, vpcPrefix := range vpcPrefixesToDelete {
		slogger := logger.With().Str("VPC Prefix ID", vpcPrefix.ID.String()).Logger()

		// If the VpcPrefix was already being deleted, we can proceed with removing it from the DB
		if vpcPrefix.Status == cdbm.VpcPrefixStatusDeleting {
			// Retrieve Subnet with IPBlock
			curVpcPrefix, serr := vpcPrefixDAO.GetByID(ctx, nil, vpcPrefix.ID, []string{cdbm.IPBlockRelationName})
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to get VPC Prefix from DB")
				continue
			}

			// The Subnet was being deleted, so delete it from DB
			tx, terr := cdb.BeginTx(ctx, mvp.dbSession, &sql.TxOptions{})
			if terr != nil {
				slogger.Error().Err(terr).Msg("failed to start transaction")
				return terr
			}

			serr = mvp.deleteVpcPrefixFromDB(ctx, tx, curVpcPrefix, logger)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to delete VPC Prefix from DB")
				terr := tx.Rollback()
				if terr != nil {
					slogger.Error().Err(terr).Msg("failed to rollback transaction")
				}
			} else {
				err = tx.Commit()
				if err != nil {
					slogger.Error().Err(err).Msg("error committing VPC Prefix delete transaction to DB")
				}
			}
		} else {
			// Was this created within inventory receipt interval? If so, we may be processing an older inventory
			if time.Since(vpcPrefix.Created) < cwutil.InventoryReceiptInterval {
				continue
			}

			// Set isMissingOnSite flag to true and update status, user can decide on deletion
			_, serr := vpcPrefixDAO.Update(ctx, nil, cdbm.VpcPrefixUpdateInput{VpcPrefixID: vpcPrefix.ID, IsMissingOnSite: cdb.GetBoolPtr(true)})
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to set missing on Site flag in DB")
				continue
			}

			serr = mvp.updateVpcPrefixStatusInDB(ctx, nil, vpcPrefix.ID, cdb.GetStrPtr(cdbm.VpcPrefixStatusError), cdb.GetStrPtr("VPC Prefix is missing on Site"))
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to update VPC Prefix status detail in DB")
			}
		}
	}

	return nil
}

// deleteVpcPrefixFromDB is a helper function to delete VPC Prefix from DB
func (mvp ManageVpcPrefix) deleteVpcPrefixFromDB(ctx context.Context, tx *cdb.Tx, vpcPrefix *cdbm.VpcPrefix, logger zerolog.Logger) error {
	// Acquire an advisory lock on the parent IP block ID on which there could be contention
	// this lock is released when the transaction commits or rollsback
	err := tx.AcquireAdvisoryLock(ctx, cdb.GetAdvisoryLockIDFromString(vpcPrefix.IPBlockID.String()), false)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to acquire advisory lock on IP Block")
		return err
	}
	logger.Info().Msg("acquired advisory lock on IP Block for VPC Prefix")

	// Delete IPAM entry for this subnet
	ipamStorage := ipam.NewIpamStorage(mvp.dbSession.DB, tx.GetBunTx())
	err = ipam.DeleteChildIpamEntryFromCidr(ctx, tx, mvp.dbSession, ipamStorage, vpcPrefix.IPBlock, vpcPrefix.Prefix)
	if err != nil {
		logger.Error().Err(err).Msg("failed to delete ipam record for Subnet")
		return err
	}
	logger.Info().Msg("deleted VPC Prefix IPAM entry")

	// Soft-delete VPC Prefix
	vpcPrefixDAO := cdbm.NewVpcPrefixDAO(mvp.dbSession)

	err = vpcPrefixDAO.Delete(ctx, tx, vpcPrefix.ID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to delete VPC Prefix from DB")
		return err
	}

	return nil
}

// updateVpcPrefixStatusInDB is helper function to write VpcPrefix updates to DB
func (mvp ManageVpcPrefix) updateVpcPrefixStatusInDB(ctx context.Context, tx *cdb.Tx, vpcPrefixID uuid.UUID, status *string, statusMessage *string) error {
	if status != nil {
		VpcPrefixDAO := cdbm.NewVpcPrefixDAO(mvp.dbSession)

		_, err := VpcPrefixDAO.Update(ctx, tx, cdbm.VpcPrefixUpdateInput{VpcPrefixID: vpcPrefixID, Status: status})
		if err != nil {
			return err
		}

		statusDetailDAO := cdbm.NewStatusDetailDAO(mvp.dbSession)
		_, err = statusDetailDAO.CreateFromParams(ctx, tx, vpcPrefixID.String(), *status, statusMessage)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewManageVpcPrefix returns a new ManageVpcPrefix activity
func NewManageVpcPrefix(dbSession *cdb.Session, siteClientPool *sc.ClientPool) ManageVpcPrefix {
	return ManageVpcPrefix{
		dbSession:      dbSession,
		siteClientPool: siteClientPool,
	}
}
