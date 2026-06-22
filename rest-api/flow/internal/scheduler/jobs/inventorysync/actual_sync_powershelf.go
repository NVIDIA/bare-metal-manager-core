// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"net"
	"time"

	"github.com/rs/zerolog/log"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/common/utils"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
	pb "github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi/gen"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
)

// ---------------------------------------------------------------------------
// syncPowershelvesNICo: sync PowerShelf components via Core (NICo)
// ---------------------------------------------------------------------------
//
// Uses Core's NICo API. Core's PSM backend auto-registers power shelves, so no
// registration step is needed.
//
// NICo API calls (2 round-trips):
//   - GetAllExpectedPowerShelvesLinked: discover Core power shelf IDs by PMC MAC
//   - GetComponentInventory: get firmware, power state from site explorer
//
// Flow:
//  1. DB: get all PowerShelf components with PMCs
//  2. NICo GetAllExpectedPowerShelvesLinked: map PMC MAC → Core PowerShelfId
//  3. Direct-write external_id (Core's PowerShelfId) for matched components
//  4. NICo GetComponentInventory: extract firmware_version, power_state
//  5. Direct-write inventory fields to DB
//  6. Return drifts (missing_in_actual for components without a Core PowerShelfId)
func syncPowershelvesNICo(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) (received int, drifts []model.ComponentDrift, rpcOK bool) {
	log.Debug().Msg("Syncing powershelves via NICo...")

	expectedPowershelves, err := model.GetComponentsByType(ctx, pool.DB, devicetypes.ComponentTypePowerShelf)
	if err != nil {
		log.Error().Msgf("Unable to retrieve powershelf components from db: %v", err)
		return 0, nil, false
	}

	if len(expectedPowershelves) == 0 {
		return 0, nil, true
	}

	expectedByPmcMac := make(map[string]*model.Component)
	for i := range expectedPowershelves {
		ps := &expectedPowershelves[i]
		if len(ps.BMCs) != 1 {
			log.Error().Msgf("Powershelf %s has %d BMCs, expected exactly 1; skipping", ps.SerialNumber, len(ps.BMCs))
			continue
		}
		pmcMacAddr, err := net.ParseMAC(ps.BMCs[0].MacAddress)
		if err != nil || pmcMacAddr == nil {
			log.Error().Msgf("Powershelf %s has invalid BMC MAC address %s; skipping", ps.SerialNumber, ps.BMCs[0].MacAddress)
			continue
		}
		expectedByPmcMac[pmcMacAddr.String()] = ps
	}

	// ID discovery: map PMC MAC → Core PowerShelfId
	linked, err := nicoClient.GetAllExpectedPowerShelvesLinked(ctx)
	if err != nil {
		log.Error().Msgf("Unable to retrieve linked expected power shelves from NICo: %v", err)
		return 0, nil, false
	}
	received = len(linked)

	linkedByMac := make(map[string]nicoapi.LinkedExpectedPowerShelf)
	for _, leps := range linked {
		if leps.BMCMACAddress != "" {
			linkedByMac[utils.NormalizeMAC(leps.BMCMACAddress)] = leps
		}
	}

	// Direct-write external_id for matched components
	var shelfIDs []*pb.PowerShelfId
	componentsByShelfID := make(map[string]*model.Component)

	for pmcMac, ps := range expectedByPmcMac {
		leps, found := linkedByMac[pmcMac]
		if !found || leps.PowerShelfID == "" {
			continue
		}

		if ps.ComponentID == nil || *ps.ComponentID != leps.PowerShelfID {
			shelfID := leps.PowerShelfID
			ps.ComponentID = &shelfID
			if err := ps.Patch(ctx, pool.DB); err != nil {
				log.Error().Msgf("Powershelf %s (PMC %s): unable to update external_id: %v", ps.ID, pmcMac, err)
				continue
			}
			log.Info().Msgf("Powershelf %s (PMC %s): set external_id to Core PowerShelfId %s", ps.ID, pmcMac, shelfID)
		}

		shelfIDs = append(shelfIDs, &pb.PowerShelfId{Id: leps.PowerShelfID})
		componentsByShelfID[leps.PowerShelfID] = ps
	}

	// Fetch inventory from Core for all matched power shelves. A failure here
	// leaves the serial-mismatch drifts incomplete, so flag the type
	// not-OK: the caller then preserves the existing drift table this cycle
	// rather than overwriting it with a partial view.
	now := time.Now()
	inventoryOK := true
	if len(shelfIDs) > 0 {
		invResp, err := nicoClient.GetComponentInventory(ctx, &pb.GetComponentInventoryRequest{
			Target: &pb.GetComponentInventoryRequest_PowerShelfIds{
				PowerShelfIds: &pb.PowerShelfIdList{Ids: shelfIDs},
			},
		})
		if err != nil {
			log.Error().Msgf("Unable to retrieve powershelf inventory from NICo: %v", err)
			inventoryOK = false
		} else {
			drifts = append(drifts, applyInventoryToComponents(ctx, pool, invResp, componentsByShelfID)...)
		}
	}

	syncPowershelfStatuses(ctx, pool, nicoClient, componentsByShelfID)

	// Build drifts for components that don't have a Core PowerShelfId yet
	for _, ps := range expectedByPmcMac {
		if ps.ComponentID == nil || *ps.ComponentID == "" {
			compID := ps.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  nil,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
		}
	}

	log.Info().Msgf("Powershelf NICo sync: %d drift(s) out of %d expected", len(drifts), len(expectedPowershelves))
	return received, drifts, inventoryOK
}

// syncPowershelfStatuses is the power-shelf equivalent of syncSwitchStatuses.
func syncPowershelfStatuses(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
	componentsByShelfID map[string]*model.Component,
) {
	ids := mapKeys(componentsByShelfID)
	if len(ids) == 0 {
		return
	}
	statesByID, err := nicoClient.FindPowerShelfControllerStates(ctx, ids)
	if err != nil {
		log.Error().Msgf("Unable to retrieve power-shelf controller_states from NICo: %v", err)
		return
	}
	persistComponentOperationStatuses(ctx, pool, types.ComponentTypePowerShelf, statesByID, componentsByShelfID)
}
