// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sku

import (
	"context"
	"errors"
	"reflect"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	sc "github.com/NVIDIA/infra-controller-rest/workflow/pkg/client/site"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

// ManageSku is an activity wrapper for managing SKU inventory that allows injecting DB access
type ManageSku struct {
	dbSession      *cdb.Session
	siteClientPool *sc.ClientPool
}

func getAssociatedMachineIDsFromProto(sku *cwssaws.Sku) []string {
	if sku == nil || sku.AssociatedMachineIds == nil {
		return nil
	}
	result := []string{}
	for _, amid := range sku.AssociatedMachineIds {
		if strId := amid.GetId(); strId != "" {
			result = append(result, strId)
		}
	}
	return result
}

// UpdateSkusInDB is a Temporal activity that takes a collection of SKU data pushed by Site Agent and updates the DB
// NOTE: Initial implementation validates inputs and site existence; DB synchronization will be added iteratively.
func (ms ManageSku) UpdateSkusInDB(ctx context.Context, siteID uuid.UUID, skuInventory *cwssaws.SkuInventory) error {
	logger := log.With().Str("Activity", "UpdateSkusInDB").Str("Site ID", siteID.String()).Logger()

	logger.Info().Msg("starting activity")

	if skuInventory == nil {
		logger.Error().Msg("UpdateSkusInDB called with nil inventory")
		return errors.New("UpdateSkusInDB called with nil inventory")
	}

	if skuInventory.InventoryStatus == cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED {
		logger.Warn().Msg("received failed inventory status from Site Agent, skipping inventory processing")
		return nil
	}

	// Ensure Site exists
	stDAO := cdbm.NewSiteDAO(ms.dbSession)
	_, err := stDAO.GetByID(ctx, nil, siteID, nil, false)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			logger.Warn().Err(err).Msg("received inventory for unknown or deleted Site")
		} else {
			logger.Error().Err(err).Msg("failed to retrieve Site from DB")
		}
		return err
	}

	// Initialize DAO
	skuDAO := cdbm.NewSkuDAO(ms.dbSession)

	// Fetch ALL existing SKUs for site
	filterInput := cdbm.SkuFilterInput{SiteIDs: []uuid.UUID{siteID}}
	existingSkus, _, err := skuDAO.GetAll(ctx, nil, filterInput, cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)})
	if err != nil {
		logger.Error().Err(err).Msg("failed to get SKUs for Site from DB")
		return err
	}

	// Build a map of all existing SKUs by ID (unique identifier)
	existingByID := map[string]*cdbm.SKU{}
	for _, sku := range existingSkus {
		existingByID[sku.ID] = &sku
	}

	// Track all IDs reported by this inventory payload (either from full list in pagination or iteration on current load)
	reportedIDs := map[string]bool{}

	// Track all IDs reported by the inventory page (if present) for use in deletion logic
	if skuInventory.InventoryPage != nil {
		logger.Info().Msgf("Received SKU inventory page: %d of %d, page size: %d, total count: %d",
			skuInventory.InventoryPage.CurrentPage, skuInventory.InventoryPage.TotalPages,
			skuInventory.InventoryPage.PageSize, skuInventory.InventoryPage.TotalItems)

		for _, strId := range skuInventory.InventoryPage.ItemIds {
			reportedIDs[strId] = true
		}
	}

	// iterate over current page or all (single load) if paging disabled
	for _, reportedSku := range skuInventory.GetSkus() {
		if reportedSku == nil {
			logger.Error().Msg("received nil SKU entry, skipping processing")
			continue
		} else if reportedSku.Id == "" {
			logger.Error().Msg("received SKU entry from Site with empty ID, skipping processing")
			continue
		}
		reportedIDs[reportedSku.Id] = true
		reportedAssociatedMachineIDs := getAssociatedMachineIDsFromProto(reportedSku)

		// Create a new SKU if it doesn't already exist in DB
		cur, found := existingByID[reportedSku.Id]
		if !found {
			// Create new SKU with SiteID
			sku := cdbm.SkuCreateInput{
				SkuID:      reportedSku.Id,
				SiteID:     siteID,
				DeviceType: reportedSku.DeviceType,
				Components: &cdbm.SkuComponents{
					SkuComponents: reportedSku.Components,
				},
				AssociatedMachineIds: reportedAssociatedMachineIDs,
			}
			_, cerr := skuDAO.Create(ctx, nil, sku)
			if cerr != nil {
				logger.Error().Err(cerr).Str("SkuID", reportedSku.Id).Msg("failed to create SKU in DB")
			}
			continue
		}

		// Update existing SKU data in DB
		if !reflect.DeepEqual(cur.Components.SkuComponents, reportedSku.Components) || cur.DeviceType != reportedSku.DeviceType ||
			!reflect.DeepEqual(cur.AssociatedMachineIds, reportedAssociatedMachineIDs) {
			// nil AssociatedMachineIds in nico can mean we need to clear out existing AssociatedMachineIds in DB
			// but a nil value will not trigger an update in the DAO layer. We could use `Clear` but an empty map
			// will save a call to the DB.
			if cur.AssociatedMachineIds != nil && reportedAssociatedMachineIDs == nil {
				reportedAssociatedMachineIDs = []string{}
			}
			sku := cdbm.SkuUpdateInput{
				SkuID:                reportedSku.Id,
				Components:           &cdbm.SkuComponents{SkuComponents: reportedSku.Components},
				DeviceType:           reportedSku.DeviceType,
				AssociatedMachineIds: reportedAssociatedMachineIDs,
			}
			_, uerr := skuDAO.Update(ctx, nil, sku)
			if uerr != nil {
				logger.Error().Err(uerr).Str("SkuID", reportedSku.Id).Msg("failed to update SKU in DB")
			}
		}
	}

	// Delete any SKU present in DB not present in NICo.
	// We only act if this is the last page (or paging disabled) and outside race window.
	// The source of truth for NICo is reportedIDs.
	if skuInventory.InventoryPage == nil || skuInventory.InventoryPage.TotalPages == 0 || (skuInventory.InventoryPage.CurrentPage == skuInventory.InventoryPage.TotalPages) {
		for _, sk := range existingSkus {
			if _, keep := reportedIDs[sk.ID]; keep {
				continue
			}
			logger.Info().Str("SkuId", sk.ID).Msg("deleting SKU from DB since it was no longer reported in inventory from Site")
			if derr := skuDAO.Delete(ctx, nil, sk.ID); derr != nil {
				logger.Error().Err(derr).Str("SkuID", sk.ID).Msg("failed to delete SKU from DB")
			}
		}
	}

	logger.Info().Msg("completed activity")
	return nil
}

// NewManageSku returns a new ManageSku activity
func NewManageSku(dbSession *cdb.Session, siteClientPool *sc.ClientPool) ManageSku {
	return ManageSku{
		dbSession:      dbSession,
		siteClientPool: siteClientPool,
	}
}
