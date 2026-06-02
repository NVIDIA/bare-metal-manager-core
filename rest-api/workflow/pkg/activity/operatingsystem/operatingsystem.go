// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operatingsystem

import (
	"context"
	"database/sql"
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

const (
	MsgOsImageSynced = "Operating System successfully synced to Site"
)

var (
	// ControllerOsImageStatusMap is a list of valid status for the Controller Os Image
	ControllerOsImageStatusMap = map[cwssaws.OsImageStatus]bool{
		cwssaws.OsImageStatus_ImageInProgress:    true,
		cwssaws.OsImageStatus_ImageUninitialized: true,
		cwssaws.OsImageStatus_ImageDisabled:      true,
		cwssaws.OsImageStatus_ImageReady:         true,
		cwssaws.OsImageStatus_ImageFailed:        true,
	}
)

// ManageOsImage is an activity wrapper for managing Image based OS lifecycle for a Site and allows
// injecting DB access
type ManageOsImage struct {
	dbSession      *cdb.Session
	siteClientPool *sc.ClientPool
}

// Activity functions

// UpdateOsImagesInDB takes information pushed by Site Agent for a collection of image based OSs associated with the Site and updates the DB
func (mskg ManageOsImage) UpdateOsImagesInDB(ctx context.Context, siteID uuid.UUID, osImageInventory *cwssaws.OsImageInventory) ([]uuid.UUID, error) {
	logger := log.With().Str("Activity", "UpdateOsImagesInDB").Str("Site ID", siteID.String()).Logger()

	logger.Info().Msg("starting activity")

	stDAO := cdbm.NewSiteDAO(mskg.dbSession)

	site, err := stDAO.GetByID(ctx, nil, siteID, nil, false)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			logger.Warn().Err(err).Msg("received Os Image inventory for unknown or deleted Site")
		} else {
			logger.Error().Err(err).Msg("failed to retrieve Site from DB")
		}
		return nil, err
	}

	if osImageInventory.InventoryStatus == cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED {
		logger.Warn().Msg("received failed inventory status from Site Agent, skipping inventory processing")
		return nil, nil
	}

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mskg.dbSession)

	existingOssas, _, err := ossaDAO.GetAll(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{
			SiteIDs: []uuid.UUID{site.ID},
		},
		cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)},
		[]string{cdbm.OperatingSystemRelationName},
	)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get OS Image Site Associations for Site from DB")
		return nil, err
	}

	// Construct a map ID of Operating System Site Association to Operating System
	existingOsImageMap := make(map[string]*cdbm.OperatingSystemSiteAssociation)
	for _, ossa := range existingOssas {
		curossa := ossa
		existingOsImageMap[ossa.OperatingSystemID.String()] = &curossa
	}

	reportedOsImageIDMap := map[uuid.UUID]bool{}

	if osImageInventory.InventoryPage != nil {
		logger.Info().Msgf("Received OS Image inventory page: %d of %d, page size: %d, total count: %d",
			osImageInventory.InventoryPage.CurrentPage, osImageInventory.InventoryPage.TotalPages,
			osImageInventory.InventoryPage.PageSize, osImageInventory.InventoryPage.TotalItems)

		for _, strId := range osImageInventory.InventoryPage.ItemIds {
			id, serr := uuid.Parse(strId)
			if serr != nil {
				logger.Error().Err(serr).Str("ID", strId).Msg("failed to parse OS Image ID from inventory page")
				continue
			}
			reportedOsImageIDMap[id] = true
		}
	}

	updatedOperatingSystemMap := map[uuid.UUID]bool{}

	// Iterate through OS Image Inventory and update DB
	for _, controllerOsImage := range osImageInventory.OsImages {
		if controllerOsImage != nil && controllerOsImage.Attributes != nil {

			osImageIDStr := controllerOsImage.Attributes.Id.GetValue()
			slogger := logger.With().Str("OS Image ID", osImageIDStr).Logger()

			ossa, ok := existingOsImageMap[osImageIDStr]
			if !ok {
				slogger.Error().Str("OS Image ID", controllerOsImage.Attributes.Id.Value).Msg("OS Image Site Association does not have a record in DB, possibly created directly on Site")
				continue
			}

			reportedOsImageIDMap[ossa.OperatingSystemID] = true

			// Reset missing flag if necessary
			if ossa.IsMissingOnSite {
				// Update Operating System Site Association missing flag as it is now found on Site
				_, serr := ossaDAO.Update(
					ctx,
					nil,
					cdbm.OperatingSystemSiteAssociationUpdateInput{
						OperatingSystemSiteAssociationID: ossa.ID,
						IsMissingOnSite:                  cdb.GetBoolPtr(false),
					},
				)
				if serr != nil {
					slogger.Error().Err(serr).Msg("failed to update OS Image Site Association missing flag in DB")
					continue
				}
			}

			if ossa.Status == cdbm.OperatingSystemSiteAssociationStatusDeleting {
				continue
			}

			// Update Operating System Site Association status if necessary
			ossaStatus := cdbm.OperatingSystemSiteAssociationStatusSyncing
			ossaStatusMessage := controllerOsImage.StatusMessage

			ok = ControllerOsImageStatusMap[controllerOsImage.Status]
			if !ok {
				slogger.Error().Str("OS Image ID", controllerOsImage.Attributes.Id.Value).Str("OS Image Status", controllerOsImage.Status.String()).Msg("received unknown OS Image status from Site Agent")
			}

			switch controllerOsImage.Status {
			case cwssaws.OsImageStatus_ImageInProgress, cwssaws.OsImageStatus_ImageUninitialized, cwssaws.OsImageStatus_ImageDisabled:
				ossaStatusMessage = cdb.GetStrPtr("OS Image is still syncing")
			case cwssaws.OsImageStatus_ImageReady:
				ossaStatus = cdbm.OperatingSystemSiteAssociationStatusSynced
				ossaStatusMessage = cdb.GetStrPtr("OS Image is ready to use")
			case cwssaws.OsImageStatus_ImageFailed:
				ossaStatus = cdbm.OperatingSystemSiteAssociationStatusError
				if ossaStatusMessage == nil || *ossaStatusMessage == "" {
					ossaStatusMessage = cdb.GetStrPtr("OS Image failed to sync on Site")
				}
			}

			// if determined status is different that current
			// only that case update
			if ossaStatus != ossa.Status {
				serr := mskg.updateOperatingSystemSiteAssociationStatusInDB(ctx, nil, ossa.ID, cdb.GetStrPtr(ossaStatus), ossaStatusMessage)
				if serr != nil {
					slogger.Error().Err(err).Msg("failed to update OS Image Site Association status detail in DB")
				}
				updatedOperatingSystemMap[ossa.OperatingSystemID] = true
			}
		}
	}

	// Populate list of ossas that were not found
	ossasToDelete := []*cdbm.OperatingSystemSiteAssociation{}

	// If inventory paging is enabled, we only need to do this once and we do it on the last page
	if osImageInventory.InventoryPage == nil || osImageInventory.InventoryPage.TotalPages == 0 || (osImageInventory.InventoryPage.CurrentPage == osImageInventory.InventoryPage.TotalPages) {
		for _, ossa := range existingOsImageMap {
			found := false
			_, found = reportedOsImageIDMap[ossa.OperatingSystemID]
			if !found || ossa.Status == cdbm.OperatingSystemSiteAssociationStatusDeleting {
				// The OS Image was not found in the Os Image Inventory, so add it to list of OS Image to potentially delete
				ossasToDelete = append(ossasToDelete, ossa)
			}
		}
	}

	// Process all Operating Site Associations in DB
	for _, ossa := range ossasToDelete {
		slogger := logger.With().Str("OS Image Site Association ID", ossa.ID.String()).Logger()

		// Operating System was not found on Site
		if ossa.Status == cdbm.OperatingSystemSiteAssociationStatusDeleting {
			// If the OperatingSystemSiteAssociation was being deleted, we can proceed with removing it from the DB
			serr := ossaDAO.Delete(ctx, nil, ossa.ID)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to delete Operating System Site Association from DB")
				continue
			}
			// Trigger re-evaluation of Operating System status (delete if no association exists)
			serr = mskg.UpdateOperatingSystemStatusInDB(ctx, ossa.OperatingSystemID)
			if serr != nil {
				slogger.Error().Err(err).Msg("failed to trigger Operating System status update in DB")
			}
		} else {
			// Was this created within inventory receipt interval? If so, we may be processing an older inventory
			if time.Since(ossa.Created) < cwutil.InventoryReceiptInterval {
				continue
			}

			// Set isMissingOnSite flag to true and update status, user can decide on deletion
			_, serr := ossaDAO.Update(
				ctx,
				nil,
				cdbm.OperatingSystemSiteAssociationUpdateInput{
					OperatingSystemSiteAssociationID: ossa.ID,
					IsMissingOnSite:                  cdb.GetBoolPtr(true),
				},
			)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to set missing on Site flag in DB for Operating System Site Association")
				continue
			}

			serr = mskg.updateOperatingSystemSiteAssociationStatusInDB(ctx, nil, ossa.ID, cdb.GetStrPtr(cdbm.OperatingSystemSiteAssociationStatusError), cdb.GetStrPtr("Operating System is missing on Site"))
			if serr != nil {
				slogger.Error().Err(err).Msg("failed to update Operating System Site Association status detail in DB")
			}

			updatedOperatingSystemMap[ossa.OperatingSystemID] = true
		}
	}

	updatedOsIDs := []uuid.UUID{}
	for osID := range updatedOperatingSystemMap {
		updatedOsIDs = append(updatedOsIDs, osID)
	}

	return updatedOsIDs, nil
}

// updateOperatingSystemSiteAssociationStatusInDB is helper function to write OperatingSystemSiteAssociation updates to DB
func (mskg ManageOsImage) updateOperatingSystemSiteAssociationStatusInDB(ctx context.Context, tx *cdb.Tx, ossaID uuid.UUID, status *string, statusMessage *string) error {
	if status != nil {
		ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mskg.dbSession)

		_, err := ossaDAO.Update(
			ctx,
			tx,
			cdbm.OperatingSystemSiteAssociationUpdateInput{
				OperatingSystemSiteAssociationID: ossaID,
				Status:                           status,
			},
		)
		if err != nil {
			return err
		}

		statusDetailDAO := cdbm.NewStatusDetailDAO(mskg.dbSession)
		_, err = statusDetailDAO.CreateFromParams(ctx, tx, ossaID.String(), *status, statusMessage)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateOperatingSystemStatusInDB is helper function to write Operating System updates to DB
func (mskg ManageOsImage) UpdateOperatingSystemStatusInDB(ctx context.Context, osID uuid.UUID) error {
	logger := log.With().Str("Activity", "UpdateOperatingSystemStatusInDB").Str("Operating System ID", osID.String()).Logger()

	logger.Info().Msg("starting activity")

	osDAO := cdbm.NewOperatingSystemDAO(mskg.dbSession)

	os, err := osDAO.GetByID(ctx, nil, osID, nil)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			logger.Warn().Err(err).Msg("received request for unknown or deleted Operating System")
		} else {
			logger.Error().Err(err).Msg("failed to retrieve Operating System from DB")
		}
		return nil
	}

	logger.Info().Msg("retrieved Operating System from DB")

	var osStatus *string
	var osMessage *string

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mskg.dbSession)
	ossas, ossaTotal, err := ossaDAO.GetAll(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{
			OperatingSystemIDs: []uuid.UUID{osID},
		},
		cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)},
		nil,
	)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get Operating System Site Associations from DB for Operating System")
		return err
	}

	// Operating System is in deleting state
	if os.Status == cdbm.OperatingSystemStatusDeleting {
		if ossaTotal == 0 {
			// Start a db tx
			tx, err := cdb.BeginTx(ctx, mskg.dbSession, &sql.TxOptions{})
			if err != nil {
				logger.Error().Err(err).Msg("failed to start transaction")
				return err
			}

			// No more associations left, we can delete the Operating System
			serr := osDAO.Delete(ctx, tx, osID)
			if serr != nil {
				logger.Error().Err(serr).Msg("failed to delete Operating System from DB")
				terr := tx.Rollback()
				if terr != nil {
					logger.Error().Err(terr).Msg("failed to rollback transaction")
				}
				return serr
			}

			// Commit transaction
			err = tx.Commit()
			if err != nil {
				logger.Error().Err(err).Msg("error committing transaction to DB")
				return err
			}
		}

		// One or more associations left to delete from Sites
		return nil
	}

	if ossaTotal == 0 {
		if os.Status == cdbm.OperatingSystemStatusReady {
			return nil
		}
		osStatus = cdb.GetStrPtr(cdbm.OperatingSystemStatusReady)
		osMessage = cdb.GetStrPtr("Operating System successfully synced to all Sites")
	} else {
		statusCountMap := map[string]int{}
		for _, dbossa := range ossas {
			statusCountMap[dbossa.Status]++
		}

		if statusCountMap[cdbm.OperatingSystemSiteAssociationStatusError] > 0 {
			if os.Status == cdbm.OperatingSystemStatusError {
				return nil
			}
			osStatus = cdb.GetStrPtr(cdbm.OperatingSystemStatusError)
			osMessage = cdb.GetStrPtr("Failed to sync Operating System to one or more Sites")
		} else if statusCountMap[cdbm.OperatingSystemSiteAssociationStatusSyncing] > 0 {
			if os.Status == cdbm.OperatingSystemStatusSyncing {
				return nil
			}
			osStatus = cdb.GetStrPtr(cdbm.OperatingSystemStatusSyncing)
			osMessage = cdb.GetStrPtr("Operating System syncing to one or more Sites")
		} else {
			if os.Status == cdbm.OperatingSystemStatusReady {
				return nil
			}
			osStatus = cdb.GetStrPtr(cdbm.OperatingSystemStatusReady)
			osMessage = cdb.GetStrPtr("Operating System successfully synced to all Sites")
		}
	}

	// Update status
	_, err = osDAO.Update(
		ctx,
		nil,
		cdbm.OperatingSystemUpdateInput{
			OperatingSystemId: osID,
			Status:            osStatus,
		},
	)
	if err != nil {
		return err
	}

	statusDetailDAO := cdbm.NewStatusDetailDAO(mskg.dbSession)
	_, err = statusDetailDAO.CreateFromParams(ctx, nil, osID.String(), *osStatus, osMessage)
	if err != nil {
		return err
	}

	logger.Info().Msg("successfully completed activity")

	return nil
}

// NewManageOsImage returns a new ManageOsImage activity
func NewManageOsImage(dbSession *cdb.Session, siteClientPool *sc.ClientPool) ManageOsImage {
	return ManageOsImage{
		dbSession:      dbSession,
		siteClientPool: siteClientPool,
	}
}
