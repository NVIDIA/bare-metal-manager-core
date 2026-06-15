// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operatingsystem

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/client"
	tp "go.temporal.io/sdk/temporal"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"

	sc "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/client/site"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/util"

	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
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

// ManageOperatingSystem is an activity wrapper for managing Operating System lifecycle for a Site and allows
// injecting DB access
type ManageOperatingSystem struct {
	dbSession      *cdb.Session
	siteClientPool *sc.ClientPool
}

// Activity functions

// UpdateOsImagesInDB takes information pushed by Site Agent for a collection of image based OSs associated with the Site and updates the DB
func (mos ManageOperatingSystem) UpdateOsImagesInDB(ctx context.Context, siteID uuid.UUID, osImageInventory *cwssaws.OsImageInventory) ([]uuid.UUID, error) {
	logger := log.With().Str("Activity", "UpdateOsImagesInDB").Str("Site ID", siteID.String()).Logger()

	logger.Info().Msg("starting activity")

	stDAO := cdbm.NewSiteDAO(mos.dbSession)

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

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mos.dbSession)

	existingOssas, _, err := ossaDAO.GetAll(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{
			SiteIDs: []uuid.UUID{site.ID},
		},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)},
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
						IsMissingOnSite:                  cutil.GetPtr(false),
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
				ossaStatusMessage = cutil.GetPtr("OS Image is still syncing")
			case cwssaws.OsImageStatus_ImageReady:
				ossaStatus = cdbm.OperatingSystemSiteAssociationStatusSynced
				ossaStatusMessage = cutil.GetPtr("OS Image is ready to use")
			case cwssaws.OsImageStatus_ImageFailed:
				ossaStatus = cdbm.OperatingSystemSiteAssociationStatusError
				if ossaStatusMessage == nil || *ossaStatusMessage == "" {
					ossaStatusMessage = cutil.GetPtr("OS Image failed to sync on Site")
				}
			}

			// if determined status is different that current
			// only that case update
			if ossaStatus != ossa.Status {
				serr := mos.updateOperatingSystemSiteAssociationStatusInDB(ctx, nil, ossa.ID, cutil.GetPtr(ossaStatus), ossaStatusMessage)
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
			serr = mos.UpdateOperatingSystemStatusInDB(ctx, ossa.OperatingSystemID)
			if serr != nil {
				slogger.Error().Err(err).Msg("failed to trigger Operating System status update in DB")
			}
		} else {
			// Was this created within inventory receipt interval? If so, we may be processing an older inventory
			if time.Since(ossa.Created) < cutil.InventoryReceiptInterval {
				continue
			}

			// Set isMissingOnSite flag to true and update status, user can decide on deletion
			_, serr := ossaDAO.Update(
				ctx,
				nil,
				cdbm.OperatingSystemSiteAssociationUpdateInput{
					OperatingSystemSiteAssociationID: ossa.ID,
					IsMissingOnSite:                  cutil.GetPtr(true),
				},
			)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to set missing on Site flag in DB for Operating System Site Association")
				continue
			}

			serr = mos.updateOperatingSystemSiteAssociationStatusInDB(ctx, nil, ossa.ID, cutil.GetPtr(cdbm.OperatingSystemSiteAssociationStatusError), cutil.GetPtr("Operating System is missing on Site"))
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
func (mos ManageOperatingSystem) updateOperatingSystemSiteAssociationStatusInDB(ctx context.Context, tx *cdb.Tx, ossaID uuid.UUID, status *string, statusMessage *string) error {
	if status != nil {
		ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mos.dbSession)

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

		statusDetailDAO := cdbm.NewStatusDetailDAO(mos.dbSession)
		_, err = statusDetailDAO.CreateFromParams(ctx, tx, ossaID.String(), *status, statusMessage)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateOperatingSystemStatusInDB is helper function to write Operating System updates to DB
func (mos ManageOperatingSystem) UpdateOperatingSystemStatusInDB(ctx context.Context, osID uuid.UUID) error {
	logger := log.With().Str("Activity", "UpdateOperatingSystemStatusInDB").Str("Operating System ID", osID.String()).Logger()

	logger.Info().Msg("starting activity")

	osDAO := cdbm.NewOperatingSystemDAO(mos.dbSession)

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

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mos.dbSession)
	ossas, ossaTotal, err := ossaDAO.GetAll(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{
			OperatingSystemIDs: []uuid.UUID{osID},
		},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)},
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
			tx, err := cdb.BeginTx(ctx, mos.dbSession, &sql.TxOptions{})
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
		osStatus = cutil.GetPtr(cdbm.OperatingSystemStatusReady)
		osMessage = cutil.GetPtr("Operating System successfully synced to all Sites")
	} else {
		statusCountMap := map[string]int{}
		for _, dbossa := range ossas {
			statusCountMap[dbossa.Status]++
		}

		if statusCountMap[cdbm.OperatingSystemSiteAssociationStatusError] > 0 {
			if os.Status == cdbm.OperatingSystemStatusError {
				return nil
			}
			osStatus = cutil.GetPtr(cdbm.OperatingSystemStatusError)
			osMessage = cutil.GetPtr("Failed to sync Operating System to one or more Sites")
		} else if statusCountMap[cdbm.OperatingSystemSiteAssociationStatusSyncing] > 0 {
			if os.Status == cdbm.OperatingSystemStatusSyncing {
				return nil
			}
			osStatus = cutil.GetPtr(cdbm.OperatingSystemStatusSyncing)
			osMessage = cutil.GetPtr("Operating System syncing to one or more Sites")
		} else {
			if os.Status == cdbm.OperatingSystemStatusReady {
				return nil
			}
			osStatus = cutil.GetPtr(cdbm.OperatingSystemStatusReady)
			osMessage = cutil.GetPtr("Operating System successfully synced to all Sites")
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

	statusDetailDAO := cdbm.NewStatusDetailDAO(mos.dbSession)
	_, err = statusDetailDAO.CreateFromParams(ctx, nil, osID.String(), *osStatus, osMessage)
	if err != nil {
		return err
	}

	logger.Info().Msg("successfully completed activity")

	return nil
}

// UpdateOperatingSystemsInDB reconciles the operating_system table for a Site based on Operating Systems reported from Site
func (mos ManageOperatingSystem) UpdateOperatingSystemsInDB(ctx context.Context, siteID uuid.UUID, inventory *cwssaws.OperatingSystemInventory) error {
	logger := log.With().Str("Activity", "UpdateOperatingSystemsInDB").Str("Site ID", siteID.String()).Logger()
	logger.Info().Msg("Starting activity")

	if inventory == nil {
		return errors.New("UpdateOperatingSystemsInDB called with nil inventory")
	}

	if inventory.InventoryStatus == cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED {
		logger.Warn().Msg("Received failed inventory status from Site Agent, skipping")
		return nil
	}

	stDAO := cdbm.NewSiteDAO(mos.dbSession)
	site, err := stDAO.GetByID(ctx, nil, siteID, nil, false)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			logger.Warn().Err(err).Msg("Received inventory for unknown or deleted Site")
		} else {
			logger.Error().Err(err).Msg("Failed to retrieve Site from DB")
		}
		return err
	}

	// OSes that originate in nico-core are owned by the infrastructure provider, not by
	// any individual tenant. We tag them with the site's InfrastructureProviderID so that
	// ProviderAdmin can update them and all tenants of that provider can read them.
	logger.Debug().Str("InfrastructureProviderID", site.InfrastructureProviderID.String()).Msg("Resolved Infrastructure Provider from Site")

	osDAO := cdbm.NewOperatingSystemDAO(mos.dbSession)
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mos.dbSession)
	itsaDAO := cdbm.NewIpxeTemplateSiteAssociationDAO(mos.dbSession)

	// Collect the UUIDs of all reported OS records (active only — the new Find APIs do not
	// return deleted records). Site and REST share the same UUID as PK.
	reportedOSIDs := mapset.NewSet[uuid.UUID]()
	for _, reportedOS := range inventory.GetOperatingSystems() {
		if reportedOS == nil {
			logger.Error().Msg("Received nil OS record in inventory, skipping")
			continue
		}

		controllerOSID := reportedOS.GetId().GetValue()
		if controllerOSID == "" {
			logger.Error().Msg("Received OS record with empty ID, skipping")
			continue
		}

		reportedOSID, parseErr := uuid.Parse(controllerOSID)
		if parseErr != nil {
			logger.Error().Err(parseErr).Str("ControllerOperatingSystemID", controllerOSID).Msg("Received OS record with invalid UUID, skipping")
			continue
		}
		reportedOSIDs.Add(reportedOSID)
	}

	// Fetch DB records matching the reported IDs (including soft-deleted so we can detect
	// the case where REST already deleted an OS that Site still reports active).
	existingOSes, _, err := osDAO.GetAll(ctx, nil, cdbm.OperatingSystemFilterInput{
		OperatingSystemIds: reportedOSIDs.ToSlice(),
		IncludeDeleted:     true,
	}, cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)}, nil)

	if err != nil {
		logger.Error().Err(err).Msg("Failed to get Operating Systems from DB")
		return err
	}

	existingOSByID := map[uuid.UUID]*cdbm.OperatingSystem{}
	for i := range existingOSes {
		existingOSByID[existingOSes[i].ID] = &existingOSes[i]
	}

	// Track global/limited OS IDs that need aggregate status recomputation.
	globalOrLimitedOSIDs := map[uuid.UUID]struct{}{}

	// Create or update OSes based on the Site inventory.
	for _, reportedOS := range inventory.GetOperatingSystems() {
		if reportedOS == nil || reportedOS.GetId().GetValue() == "" {
			continue
		}

		reportedOSID, parseErr := uuid.Parse(reportedOS.GetId().GetValue())
		if parseErr != nil {
			continue
		}

		slogger := logger.With().Str("ControllerOperatingSystemID", reportedOSID.String()).Logger()

		coreUpdated, _ := time.Parse(time.RFC3339, reportedOS.Updated)

		ipxeTemplateParams := []cdbm.OperatingSystemIpxeParameter{}
		for _, param := range reportedOS.IpxeTemplateParameters {
			ipxeTemplateParam := cdbm.OperatingSystemIpxeParameter{}
			ipxeTemplateParam.FromProto(param)
			ipxeTemplateParams = append(ipxeTemplateParams, ipxeTemplateParam)
		}

		ipxeTemplateArtifacts := []cdbm.OperatingSystemIpxeArtifact{}
		for _, artifact := range reportedOS.IpxeTemplateArtifacts {
			ipxeTemplateArtifact := cdbm.OperatingSystemIpxeArtifact{}
			ipxeTemplateArtifact.FromProto(artifact)
			ipxeTemplateArtifacts = append(ipxeTemplateArtifacts, ipxeTemplateArtifact)
		}

		osType := cdbm.OperatingSystemTypeFromProtoMap[reportedOS.Type]
		if osType == "" {
			slogger.Error().Str("Type", reportedOS.Type.String()).Msg("Received unknown OS type from Site, skipping")
			continue
		}

		existingOS, found := existingOSByID[reportedOSID]
		if !found {
			// Templated iPXE OS: verify the referenced template is available at this site
			// before creating the OS record. Skip silently if not available.
			if osType == cdbm.OperatingSystemTypeTemplatedIPXE && reportedOS.IpxeTemplateId != nil {
				ipxeTemplateID, serr := uuid.Parse(reportedOS.IpxeTemplateId.GetValue())
				if serr != nil {
					slogger.Error().Err(serr).Str("IpxeTemplateID", reportedOS.IpxeTemplateId.GetValue()).Msg("Invalid iPXE template UUID in Operating System, skipping")
					continue
				}

				_, serr = itsaDAO.GetByIpxeTemplateIDAndSiteID(ctx, nil, ipxeTemplateID, siteID, nil)
				if serr != nil {
					if errors.Is(serr, cdb.ErrDoesNotExist) {
						slogger.Warn().Str("IpxeTemplateID", ipxeTemplateID.String()).Msg("iPXE Template Association does not exist for Site, skipping")
						continue
					}
					slogger.Error().Err(serr).Msg("Failed to retrieve IpxeTemplateSiteAssociation, DB error")
					continue
				}
			}

			// New OS from Site: Create it with Site's InfrastructureProviderID.
			// OSes originating in Site are provider-owned (not tenant-owned)
			// ProviderAdmin can update them and all Tenants of the Provider can retrieve them
			// Scope is Local: the definition lives at a single site with bidirectional sync

			status := cdbm.OperatingSystemStatusFromProtoMap[reportedOS.Status]
			if status == "" {
				slogger.Warn().Str("Status", reportedOS.Status.String()).Msg("Received unknown status from Site, using `Syncing` as default")
				status = cdbm.OperatingSystemStatusSyncing
			}

			_, serr := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
				ID:                       reportedOSID,
				Name:                     reportedOS.Name,
				Org:                      site.Org,
				TenantID:                 nil,
				InfrastructureProviderID: &site.InfrastructureProviderID,
				OsType:                   osType,
				Description:              reportedOS.Description,
				UserData:                 reportedOS.UserData,
				IpxeScript:               reportedOS.IpxeScript,
				AllowOverride:            reportedOS.AllowOverride,
				PhoneHomeEnabled:         reportedOS.PhoneHomeEnabled,
				IpxeTemplateId:           cutil.GetPtr(reportedOS.IpxeTemplateId.GetValue()),
				IpxeTemplateParameters:   ipxeTemplateParams,
				IpxeTemplateArtifacts:    ipxeTemplateArtifacts,
				IpxeOSHash:               reportedOS.IpxeTemplateDefinitionHash,
				IpxeOsScope:              cutil.GetPtr(cdbm.OperatingSystemScopeLocal),
				Status:                   status,
			})
			if serr != nil {
				slogger.Error().Err(serr).Msg("Failed to create Operating System, DB error")
				continue
			}

			if !reportedOS.IsActive {
				// TODO: Allow creation of inactive OSes
				_, serr := osDAO.Update(ctx, nil, cdbm.OperatingSystemUpdateInput{
					OperatingSystemId: reportedOSID,
					IsActive:          cutil.GetPtr(false),
				})
				if serr != nil {
					slogger.Error().Err(serr).Msg("Failed to set Operating System to inactive on creation")
					continue
				}
			}

			// Create site association linking the OS to the reporting site.
			ossaStatus := cdbm.OperatingSystemSiteAssociationStatusFromProtoMap[reportedOS.Status]
			if ossaStatus == "" {
				slogger.Warn().Str("Status", reportedOS.Status.String()).Msg("Received unknown status from Site, using `Syncing` as default")
				ossaStatus = cdbm.OperatingSystemSiteAssociationStatusSyncing
			}

			_, ossaErr := ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
				OperatingSystemID: reportedOSID,
				SiteID:            siteID,
				Status:            ossaStatus,
			})
			if ossaErr != nil {
				slogger.Error().Err(ossaErr).Msg("Failed to create site association for new OS")
				continue
			}

			// Newly-created OS: definition and per-site association have just been
			// written with the reported state. Skip the existing-OS update path
			// below (it dereferences existingOS which is nil here) and do not add
			// to globalOrLimitedOSIDs because new records are always Local scope.
			continue
		}

		// REST layer has already soft-deleted this OS (user-initiated)
		// Do not restore it even if Site still reports it as active (the delete push to Site may be in-flight)
		if existingOS.Deleted != nil {
			continue
		}

		// Update or create the per-site association for every OS type. For
		// Global/Limited, REST is the source of truth for the definition so we
		// only record the Site's controller state and skip the definition update.
		// For Local (provider-owned, from Site) we also fall through to update
		// the definition below. nil scope is treated as Local for safety
		// (legacy records before the backfill migration)
		isLocalScope := existingOS.IpxeOsScope == nil || *existingOS.IpxeOsScope == cdbm.OperatingSystemScopeLocal
		controllerState := cdbm.OperatingSystemStatusFromProtoMap[reportedOS.Status]
		if controllerState == "" {
			slogger.Warn().Str("Status", reportedOS.Status.String()).Msg("Received unknown status from Site, using `Syncing` as default")
			controllerState = cdbm.OperatingSystemStatusSyncing
		}

		ossaStatus := cdbm.OperatingSystemSiteAssociationStatusFromProtoMap[reportedOS.Status]
		if ossaStatus == "" {
			slogger.Warn().Str("Status", reportedOS.Status.String()).Msg("Received unknown status from Site, using `Syncing` as default")
			ossaStatus = cdbm.OperatingSystemSiteAssociationStatusSyncing
		}

		ossa, serr := ossaDAO.GetByOperatingSystemIDAndSiteID(ctx, nil, reportedOSID, siteID, nil)
		if serr != nil {
			if !errors.Is(serr, cdb.ErrDoesNotExist) {
				slogger.Error().Err(serr).Msg("Failed to retrieve Operating System Site Association, DB error")
				continue
			}

			// Operating System Site Association is missing, create it
			_, serr := ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
				OperatingSystemID: reportedOSID,
				SiteID:            siteID,
				Status:            ossaStatus,
				ControllerState:   &controllerState,
			})
			if serr != nil {
				slogger.Error().Err(serr).Msg("Failed to create Operating System Site Association")
				continue
			}
		} else {
			// Update existing Operating System Site Association
			_, uerr := ossaDAO.Update(ctx, nil, cdbm.OperatingSystemSiteAssociationUpdateInput{
				OperatingSystemSiteAssociationID: ossa.ID,
				Status:                           &ossaStatus,
				ControllerState:                  &controllerState,
			})
			if uerr != nil {
				slogger.Error().Err(uerr).Msg("Failed to update Operating System Site Association")
				continue
			}
		}

		// TODO: Is this correct?
		if !isLocalScope {
			globalOrLimitedOSIDs[reportedOSID] = struct{}{}
		}

		// Operating System exists in both REST and Site; update the REST record only for
		// Local-scoped OSes (Site is the source of truth for the definition).
		// Global/Limited OSes are REST-owned: skip the definition update and rely solely on
		// the aggregate status recomputation that runs at the end of this function.
		// Backfill: older records may have been created with tenant_id set and no
		// infrastructure_provider_id (before this ownership model was established).
		needsProviderBackfill := isLocalScope && existingOS.InfrastructureProviderID == nil
		needsOrgBackfill := isLocalScope && existingOS.Org == "" && site.Org != ""
		needsIsActiveCorrection := isLocalScope && existingOS.IsActive != reportedOS.IsActive
		needsTenantClear := isLocalScope && existingOS.TenantID != nil

		if isLocalScope && (coreUpdated.After(existingOS.Updated) || needsProviderBackfill || needsOrgBackfill || needsIsActiveCorrection || needsTenantClear) {
			controllerState := cdbm.OperatingSystemStatusFromProtoMap[reportedOS.Status]
			if controllerState == "" {
				slogger.Warn().Str("Status", reportedOS.Status.String()).Msg("Received unknown status from Site, using `Syncing` as default")
				controllerState = cdbm.OperatingSystemStatusSyncing
			}

			var ipxeTemplateID *string
			if reportedOS.IpxeTemplateId != nil {
				ipxeTemplateID = cutil.GetPtr(reportedOS.IpxeTemplateId.GetValue())
			}

			updateInput := cdbm.OperatingSystemUpdateInput{
				OperatingSystemId:        existingOS.ID,
				Name:                     &reportedOS.Name,
				Org:                      &site.Org,
				TenantID:                 nil,
				InfrastructureProviderID: &site.InfrastructureProviderID,
				OsType:                   &osType,
				Description:              reportedOS.Description,
				UserData:                 reportedOS.UserData,
				IpxeScript:               reportedOS.IpxeScript,
				AllowOverride:            &reportedOS.AllowOverride,
				PhoneHomeEnabled:         &reportedOS.PhoneHomeEnabled,
				IsActive:                 &reportedOS.IsActive,
				IpxeTemplateId:           ipxeTemplateID,
				IpxeTemplateParameters:   &ipxeTemplateParams,
				IpxeTemplateArtifacts:    &ipxeTemplateArtifacts,
				IpxeOSHash:               reportedOS.IpxeTemplateDefinitionHash,
				Status:                   &controllerState,
			}
			if _, uerr := osDAO.Update(ctx, nil, updateInput); uerr != nil {
				slogger.Error().Err(uerr).Msg("Failed to update Operating System, DB error")
				continue
			}
			// Backfill: if the record previously had a tenant_id (old ownership model), clear it.
			// Provider-owned OSes must not have tenant_id set.
			if existingOS.TenantID != nil {
				_, cerr := osDAO.Clear(ctx, nil, cdbm.OperatingSystemClearInput{
					OperatingSystemId: existingOS.ID,
					TenantID:          true,
				})
				if cerr != nil {
					slogger.Error().Err(cerr).Msg("Failed to clear Tenant ID from Provider owned Operating System, DB error")
					continue
				}
			}
		}
	}

	// Deletion propagation: Site's Find APIs return only active records, so any iPXE OS
	// in our DB that is NOT in this inventory was deleted in nico-core. Soft-delete it here.
	// Image-based OSes are not managed by this inventory, so we restrict to iPXE types only.
	// Exception: global- and limited-scoped OSes are owned by REST and must not be
	// deleted based on Site's inventory (Site is not their source of truth)
	allIpxeOSes, _, err := osDAO.GetAll(ctx, nil, cdbm.OperatingSystemFilterInput{
		OsTypes:                  []string{cdbm.OperatingSystemTypeIPXE, cdbm.OperatingSystemTypeTemplatedIPXE},
		InfrastructureProviderID: &site.InfrastructureProviderID,
	}, cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to fetch iPXE Operating Systems from DB for deletion reconciliation")
		return err
	}

	for _, ipxeOS := range allIpxeOSes {
		if ipxeOS.IpxeOsScope != nil && *ipxeOS.IpxeOsScope != cdbm.OperatingSystemScopeLocal {
			continue
		}

		slogger := logger.With().Str("OperatingSystemID", ipxeOS.ID.String()).Logger()

		if !reportedOSIDs.Contains(ipxeOS.ID) {
			slogger.Info().Msg("Soft-deleting iPXE OS absent from Site inventory")
			serr := osDAO.Delete(ctx, nil, ipxeOS.ID)
			if serr != nil {
				slogger.Error().Err(serr).Msg("Failed to soft-delete OS, DB error")
				continue
			}
		}
	}

	// Aggregate status for global/limited OSes from their per-site core statuses.
	// Rule: If all Site Associations have `Ready` status then the Operating System is `Ready`. Otherwise, it is `Syncing`.
	if len(globalOrLimitedOSIDs) > 0 {
		ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mos.dbSession)
		for osID := range globalOrLimitedOSIDs {
			slogger := logger.With().Str("OperatingSystemID", osID.String()).Logger()

			ossas, _, serr := ossaDAO.GetAll(ctx, nil, cdbm.OperatingSystemSiteAssociationFilterInput{
				OperatingSystemIDs: []uuid.UUID{osID},
			}, cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)}, nil)

			if serr != nil {
				slogger.Error().Err(serr).Msg("Failed to fetch Site Associations to determine Operating System status, DB error")
				continue
			}

			allReady := true
			for _, ossa := range ossas {
				if ossa.Status != cdbm.OperatingSystemSiteAssociationStatusSynced {
					allReady = false
					break
				}
			}

			aggregatedStatus := cdbm.OperatingSystemStatusSyncing
			if allReady && len(ossas) > 0 {
				aggregatedStatus = cdbm.OperatingSystemStatusReady
			}

			_, serr = osDAO.Update(ctx, nil, cdbm.OperatingSystemUpdateInput{
				OperatingSystemId: osID,
				Status:            &aggregatedStatus,
			})
			if serr != nil {
				slogger.Error().Err(serr).Msg("Failed to update aggregate OS status, DB error")
			}
		}
	}

	logger.Info().Msg("Completed activity")

	return nil
}

// CreateOrUpdateOperatingSystemViaSiteAgent is Temporal activity to create or update an Operating System via Site Agent
func (mos ManageOperatingSystem) CreateOrUpdateOperatingSystemViaSiteAgent(ctx context.Context, siteID uuid.UUID, operatingSystemID uuid.UUID) error {
	logger := log.With().Str("Activity", "CreateOrUpdateOperatingSystemViaSiteAgent").Str("OperatingSystemID", operatingSystemID.String()).Logger()
	logger.Info().Msg("Starting activity")

	osDAO := cdbm.NewOperatingSystemDAO(mos.dbSession)
	os, err := osDAO.GetByID(ctx, nil, operatingSystemID, nil)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			logger.Warn().Err(err).Msg("Received create/update request for unknown or deleted Operating System")
			return nil
		}
		logger.Error().Err(err).Msg("Failed to retrieve Operating System, DB error")
		return err
	}

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mos.dbSession)

	ossa, err := ossaDAO.GetByOperatingSystemIDAndSiteID(ctx, nil, operatingSystemID, siteID, nil)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			logger.Warn().Err(err).Msg("Operating System Site Association does not exist")
			return nil
		}
		logger.Error().Err(err).Msg("Failed to retrieve Operating System Site Association, DB error")
		return err
	}

	if ossa.Status == cdbm.OperatingSystemSiteAssociationStatusDeleting {
		logger.Warn().Msg("Operating System is being deleted, skipping create/update")
		return nil
	}

	isOperatingSystemCreated := cutil.GetPtr(false)
	if !ossa.IsMissingOnSite {
		isOperatingSystemCreated, err = mos.IsOperatingSystemCreatedOnSite(ctx, nil, ossa.ID)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to determine if Operating System has already been created on Site")
			return err
		}
	}

	stc, err := mos.siteClientPool.GetClientByID(ossa.SiteID)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to retrieve Temporal client for Site")
		return err
	}

	var wr client.WorkflowRun
	var workflowMethod string

	workflowOptions := client.StartWorkflowOptions{
		TaskQueue: queue.SiteTaskQueue,
	}

	newCtxWithTimeout, cancel := context.WithTimeout(context.Background(), cutil.WorkflowContextTimeout)
	defer cancel()

	if *isOperatingSystemCreated {
		workflowMethod = "update"
		workflowOptions.ID = "operating-system-update-" + os.ID.String()

		updateRequest := &cwssaws.UpdateOperatingSystemRequest{
			Id:                         &cwssaws.OperatingSystemId{Value: os.ID.String()},
			Name:                       &os.Name,
			Description:                os.Description,
			IsActive:                   &os.IsActive,
			AllowOverride:              &os.AllowOverride,
			PhoneHomeEnabled:           &os.PhoneHomeEnabled,
			UserData:                   os.UserData,
			IpxeScript:                 os.IpxeScript,
			IpxeTemplateDefinitionHash: os.IpxeTemplateDefinitionHash,
		}

		if os.IpxeTemplateId != nil {
			updateRequest.IpxeTemplateId = &cwssaws.IpxeTemplateId{
				Value: *os.IpxeTemplateId,
			}
		}

		if len(os.IpxeTemplateParameters) > 0 {
			updateRequest.IpxeTemplateParameters = &cwssaws.IpxeTemplateParameters{
				Items: []*cwssaws.IpxeTemplateParameter{},
			}

			for _, ipxeTemplateParameter := range os.IpxeTemplateParameters {
				updateRequest.IpxeTemplateParameters.Items = append(updateRequest.IpxeTemplateParameters.Items, ipxeTemplateParameter.ToProto())
			}
		}

		if len(os.IpxeTemplateArtifacts) > 0 {
			updateRequest.IpxeTemplateArtifacts = &cwssaws.IpxeTemplateArtifacts{
				Items: []*cwssaws.IpxeTemplateArtifact{},
			}

			for _, ipxeTemplateArtifact := range os.IpxeTemplateArtifacts {
				updateRequest.IpxeTemplateArtifacts.Items = append(updateRequest.IpxeTemplateArtifacts.Items, ipxeTemplateArtifact.ToProto())
			}
		}

		logger.Info().Msg("Triggering synchronous UpdateOperatingSystem workflow")

		wr, err = stc.ExecuteWorkflow(newCtxWithTimeout, workflowOptions, "UpdateOperatingSystem", updateRequest)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to schedule synchronous UpdateOperatingSystem workflow")
			return err
		}
	} else {
		workflowMethod = "create"
		workflowOptions.ID = "operating-system-create-" + os.ID.String()

		createRequest := &cwssaws.CreateOperatingSystemRequest{
			Id:                   &cwssaws.OperatingSystemId{Value: os.ID.String()},
			Name:                 os.Name,
			Description:          os.Description,
			TenantOrganizationId: os.Org,
			IsActive:             os.IsActive,
			AllowOverride:        os.AllowOverride,
			PhoneHomeEnabled:     os.PhoneHomeEnabled,
			UserData:             os.UserData,
			IpxeScript:           os.IpxeScript,
		}

		if os.IpxeTemplateId != nil {
			createRequest.IpxeTemplateId = &cwssaws.IpxeTemplateId{
				Value: *os.IpxeTemplateId,
			}
		}

		if len(os.IpxeTemplateParameters) > 0 {
			createRequest.IpxeTemplateParameters = []*cwssaws.IpxeTemplateParameter{}

			for _, ipxeTemplateParameter := range os.IpxeTemplateParameters {
				createRequest.IpxeTemplateParameters = append(createRequest.IpxeTemplateParameters, ipxeTemplateParameter.ToProto())
			}
		}

		if len(os.IpxeTemplateArtifacts) > 0 {
			createRequest.IpxeTemplateArtifacts = []*cwssaws.IpxeTemplateArtifact{}

			for _, ipxeTemplateArtifact := range os.IpxeTemplateArtifacts {
				createRequest.IpxeTemplateArtifacts = append(createRequest.IpxeTemplateArtifacts, ipxeTemplateArtifact.ToProto())
			}
		}

		logger.Info().Msg("Triggering synchronous CreateOperatingSystem workflow")

		wr, err = stc.ExecuteWorkflow(newCtxWithTimeout, workflowOptions, "CreateOperatingSystem", createRequest)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to schedule synchronous CreateOperatingSystem workflow")
			return err
		}
	}

	wid := wr.GetID()

	var status, statusMessage string

	err = wr.Get(ctx, nil)
	if err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded {
			logger.Error().Err(err).Msgf("failed to %s Operating System, timeout occurred executing workflow on Site.", workflowMethod)

			// Create a new context deadlines
			newctx, newcancel := context.WithTimeout(context.Background(), cutil.WorkflowContextNewAfterTimeout)
			defer newcancel()

			// Initiate termination workflow
			serr := stc.TerminateWorkflow(newctx, wid, "", fmt.Sprintf("Timeout occurred executing %s Operating System workflow", workflowMethod))
			if serr != nil {
				logger.Error().Err(serr).Msgf("Failed to execute terminate Temporal workflow for %s Operating System", workflowMethod)
			}
			logger.Info().Str("Workflow ID", wid).Msgf("Initiated terminate synchronous %s Operating System workflow", workflowMethod)

			status = cdbm.OperatingSystemSiteAssociationStatusError
			statusMessage = fmt.Sprintf("Failed to %s Operating System, timeout occurred executing workflow on Site.", workflowMethod)

			// Clear error so function returns nil after updating status
			err = nil
		} else if strings.Contains(err.Error(), util.ErrMsgSiteControllerDuplicateEntryFound) {
			// Handle duplicate key error - record error and fail workflow for retry, IsOperatingSystemCreatedOnSite relies on this error
			logger.Warn().Err(err).Msg("Operating System already exists on Site, recording error and failing workflow to retry")

			status = cdbm.OperatingSystemSiteAssociationStatusError
			statusMessage = fmt.Sprintf("Operating System already exists on Site: %s", util.ErrMsgSiteControllerDuplicateEntryFound)

			_ = mos.updateOperatingSystemSiteAssociationStatusInDB(ctx, nil, ossa.ID, &status, &statusMessage)

			return fmt.Errorf("Operating System creation failed, already present on Site, workflow will be retried as update: %w", err)
		} else {
			// Other errors
			status = cdbm.OperatingSystemSiteAssociationStatusError
			statusMessage = fmt.Sprintf("Failed to execute %s Operating System workflow via Site Agent", workflowMethod)
		}
	}

	// Log status detail regardless of success or failure
	_ = mos.updateOperatingSystemSiteAssociationStatusInDB(ctx, nil, ossa.ID, &status, &statusMessage)

	// If workflow wasn't successful, return error to retry workflow
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to execute synchronous %s Operating System workflow on Site", workflowMethod)
		return err
	}

	// Create/update was successful
	if wr != nil {
		logger.Info().Str("Workflow ID", wr.GetID()).Msgf("Successfully executed %s Operating System workflow on Site", workflowMethod)
	}

	logger.Info().Msg("completed activity")

	return nil
}

// DeleteOperatingSystemViaSiteAgent is Temporal activity to delete an Operating System via Site Agent
func (mos ManageOperatingSystem) DeleteOperatingSystemViaSiteAgent(ctx context.Context, siteID uuid.UUID, operatingSystemID uuid.UUID) error {
	logger := log.With().Str("Activity", "DeleteOperatingSystemViaSiteAgent").Str("OperatingSystemID", operatingSystemID.String()).Logger()
	logger.Info().Msg("Starting activity")

	osDAO := cdbm.NewOperatingSystemDAO(mos.dbSession)
	os, err := osDAO.GetByID(ctx, nil, operatingSystemID, nil)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			logger.Warn().Err(err).Msg("Received deletion request for unknown or deleted Operating System")
			return nil
		}
		logger.Error().Err(err).Msg("Failed to retrieve Operating System, DB error")
		return err
	}

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mos.dbSession)

	ossa, err := ossaDAO.GetByOperatingSystemIDAndSiteID(ctx, nil, operatingSystemID, siteID, nil)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			logger.Warn().Err(err).Msg("Operating System Site Association does not exist")
			return nil
		}
		logger.Error().Err(err).Msg("Failed to retrieve Operating System Site Association, DB error")
		return err
	}

	// Start a transaction
	tx, err := cdb.BeginTx(ctx, mos.dbSession, &sql.TxOptions{})
	if err != nil {
		logger.Error().Err(err).Msg("Failed to begin transaction")
		return err
	}
	defer tx.Rollback()

	// Delete the Operating System Site Association
	err = ossaDAO.Delete(ctx, tx, ossa.ID)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to delete Operating System Site Association, DB error")
		return err
	}

	deleteRequest := &cwssaws.DeleteOperatingSystemRequest{
		Id: &cwssaws.OperatingSystemId{Value: os.ID.String()},
	}

	stc, err := mos.siteClientPool.GetClientByID(ossa.SiteID)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to retrieve Temporal client for Site")
		return err
	}

	workflowOptions := client.StartWorkflowOptions{
		ID:        "operating-system-delete-" + os.ID.String(),
		TaskQueue: queue.SiteTaskQueue,
	}

	logger.Info().Msg("Triggering synchronous DeleteOperatingSystem workflow")

	we, werr := stc.ExecuteWorkflow(ctx, workflowOptions, "DeleteOperatingSystem", deleteRequest)
	if werr != nil {
		logger.Error().Err(werr).Msg("Failed to trigger synchronous DeleteOperatingSystem workflow")
		return err
	}

	werr = we.Get(ctx, nil)
	if werr != nil {
		var applicationErr *tp.ApplicationError
		if errors.As(werr, &applicationErr) && applicationErr.Type() == swe.ErrTypeCarbideObjectNotFound {
			logger.Warn().Msg("Opearting System was not found on Site, treating as success")
			werr = nil
		}
	}
	if werr != nil {
		logger.Error().Err(werr).Msg("Failed to execute synchronous DeleteOperatingSystem workflow")
		return err
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to commit transaction after synchronous DeleteOperatingSystem workflow on site")
		return err
	}

	return nil
}

// IsOperatingSystemCreatedOnSite is helper function to get if operating system created or not
func (mos ManageOperatingSystem) IsOperatingSystemCreatedOnSite(ctx context.Context, tx *cdb.Tx, operatingSystemSiteAssociationID uuid.UUID) (*bool, error) {
	ossaDAO := cdbm.NewStatusDetailDAO(mos.dbSession)

	ossasds, _, err := ossaDAO.GetAllByEntityID(ctx, tx, operatingSystemSiteAssociationID.String(), nil, cutil.GetPtr(cdbp.TotalLimit), nil)
	if err != nil {
		return nil, err
	}

	for _, ossad := range ossasds {
		// If it was synced at some point, then it should exist on Site
		if ossad.Status == cdbm.OperatingSystemSiteAssociationStatusSynced {
			return cutil.GetPtr(true), nil
		}

		// If we have an error suggesting violation of unique constraint, then it should exist on Site
		if ossad.Status == cdbm.OperatingSystemSiteAssociationStatusError && strings.Contains(*ossad.Message, util.ErrMsgSiteControllerDuplicateEntryFound) {
			return cutil.GetPtr(true), nil
		}
	}

	// If we have not seen it Synced or with the integrity error, then it does not exist on Site
	return cutil.GetPtr(false), nil
}

// NewManageOperatingSystem returns a new ManageOperatingSystem activity
func NewManageOperatingSystem(dbSession *cdb.Session, siteClientPool *sc.ClientPool) ManageOperatingSystem {
	return ManageOperatingSystem{
		dbSession:      dbSession,
		siteClientPool: siteClientPool,
	}
}
