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
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

// nvosIPDescriptionKey is the component.description key under which the
// switch's resolved NVOS host IP is recorded. Core owns the resolution; Flow
// only mirrors it so the IP is queryable alongside the component.
const nvosIPDescriptionKey = "nvos_ip"

// ---------------------------------------------------------------------------
// syncNVSwitchesNICo: sync NVSwitch components via Core (NICo)
// ---------------------------------------------------------------------------
//
// Uses Core's NICo API. Core's NSM backend auto-registers switches, so no
// registration step is needed.
//
// NICo API calls (2 round-trips):
//   - GetAllExpectedSwitchesLinked: discover Core switch IDs by BMC MAC
//   - GetComponentInventory: get firmware, serial, power state from site explorer
//
// Flow:
//  1. DB: get all NVSwitch components with BMCs
//  2. NICo GetAllExpectedSwitchesLinked: map BMC MAC → Core SwitchId
//  3. Direct-write external_id (Core's SwitchId) for matched components
//  4. NICo GetComponentInventory: extract firmware_version, serial_number, power_state
//  5. Direct-write inventory fields to DB
//  6. Return drifts (missing_in_actual for components without a Core SwitchId)
func syncNVSwitchesNICo(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) (received int, drifts []model.ComponentDrift, rpcOK bool) {
	log.Debug().Msg("Syncing NV switches via NICo...")

	expectedSwitches, err := model.GetComponentsByType(ctx, pool.DB, devicetypes.ComponentTypeNVSwitch)
	if err != nil {
		log.Error().Msgf("Unable to retrieve NVSwitch components from db: %v", err)
		return 0, nil, false
	}

	if len(expectedSwitches) == 0 {
		return 0, nil, true
	}

	expectedByBmcMac := make(map[string]*model.Component)
	for i := range expectedSwitches {
		sw := &expectedSwitches[i]
		if len(sw.BMCs) != 1 {
			log.Error().Msgf("NVSwitch %s has %d BMCs, expected exactly 1; skipping", sw.SerialNumber, len(sw.BMCs))
			continue
		}
		bmcMacAddr, err := net.ParseMAC(sw.BMCs[0].MacAddress)
		if err != nil || bmcMacAddr == nil {
			log.Error().Msgf("NVSwitch %s has invalid BMC MAC address %s; skipping", sw.SerialNumber, sw.BMCs[0].MacAddress)
			continue
		}
		expectedByBmcMac[bmcMacAddr.String()] = sw
	}

	// ID discovery: map BMC MAC → Core SwitchId
	linked, err := nicoClient.GetAllExpectedSwitchesLinked(ctx)
	if err != nil {
		log.Error().Msgf("Unable to retrieve linked expected switches from NICo: %v", err)
		return 0, nil, false
	}
	received = len(linked)

	linkedByMac := make(map[string]nicoapi.LinkedExpectedSwitch)
	for _, les := range linked {
		if les.BMCMACAddress != "" {
			linkedByMac[utils.NormalizeMAC(les.BMCMACAddress)] = les
		}
	}

	// Direct-write external_id for matched components
	var switchIDs []*corev1.SwitchId
	componentsBySwitchID := make(map[string]*model.Component)

	for bmcMac, sw := range expectedByBmcMac {
		les, found := linkedByMac[bmcMac]
		if !found || les.SwitchID == "" {
			continue
		}

		if sw.ComponentID == nil || *sw.ComponentID != les.SwitchID {
			switchID := les.SwitchID
			sw.ComponentID = &switchID
			if err := sw.Patch(ctx, pool.DB); err != nil {
				log.Error().Msgf("NVSwitch %s (BMC %s): unable to update external_id: %v", sw.ID, bmcMac, err)
				continue
			}
			log.Info().Msgf("NVSwitch %s (BMC %s): set external_id to Core SwitchId %s", sw.ID, bmcMac, switchID)
		}

		switchIDs = append(switchIDs, &corev1.SwitchId{Id: les.SwitchID})
		componentsBySwitchID[les.SwitchID] = sw
	}

	// Fetch inventory from Core for all matched switches. Inventory only feeds
	// the firmware_version / power_state direct-writes now — drift is keyed on
	// BMC MAC via the linked RPC above — so a failure here is best-effort and
	// just leaves those fields stale this cycle; it does not make the drift
	// table partial.
	if len(switchIDs) > 0 {
		invResp, err := nicoClient.GetComponentInventory(ctx, &corev1.GetComponentInventoryRequest{
			Target: &corev1.GetComponentInventoryRequest_SwitchIds{
				SwitchIds: &corev1.SwitchIdList{Ids: switchIDs},
			},
		})
		if err != nil {
			log.Error().Msgf("Unable to retrieve switch inventory from NICo: %v", err)
		} else {
			applyInventoryToComponents(ctx, pool, invResp, componentsBySwitchID)
		}
	}

	syncSwitchStatuses(ctx, pool, nicoClient, componentsBySwitchID)

	syncSwitchNvosIPs(ctx, pool, nicoClient, componentsBySwitchID)

	// Build drifts for components that don't have a Core SwitchId yet
	now := time.Now()
	for _, sw := range expectedByBmcMac {
		if sw.ComponentID == nil || *sw.ComponentID == "" {
			compID := sw.ID
			drifts = append(drifts, model.ComponentDrift{
				ComponentID: &compID,
				ExternalID:  nil,
				DriftType:   model.DriftTypeMissingInActual,
				Diffs:       []model.FieldDiff{},
				CheckedAt:   now,
			})
		}
	}

	log.Info().Msgf("NVSwitch NICo sync: %d drift(s) out of %d expected", len(drifts), len(expectedSwitches))
	return received, drifts, true
}

// syncSwitchStatuses fetches controller_state for the matched switches and
// persists the derived ComponentOperationStatus per DB row.
func syncSwitchStatuses(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
	componentsBySwitchID map[string]*model.Component,
) {
	ids := mapKeys(componentsBySwitchID)
	if len(ids) == 0 {
		return
	}
	statesByID, err := nicoClient.FindSwitchControllerStates(ctx, ids)
	if err != nil {
		log.Error().Msgf("Unable to retrieve switch controller_states from NICo: %v", err)
		return
	}
	persistComponentOperationStatuses(ctx, pool, types.ComponentTypeNVSwitch, statesByID, componentsBySwitchID)
}

// syncSwitchNvosIPs records Core's resolved NVOS host IP for each matched
// switch in the component's description. Core only reports an NVOS IP once both
// the NVOS MAC and its assigned address resolve, so switches without one are
// left untouched rather than having the key cleared. The description merge
// preserves any other keys (operator-managed metadata, etc.).
func syncSwitchNvosIPs(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
	componentsBySwitchID map[string]*model.Component,
) {
	ids := mapKeys(componentsBySwitchID)
	if len(ids) == 0 {
		return
	}
	ipsByID, err := nicoClient.FindSwitchNvosIPs(ctx, ids)
	if err != nil {
		log.Error().Msgf("Unable to retrieve switch NVOS IPs from NICo: %v", err)
		return
	}
	for switchID, ip := range ipsByID {
		comp, ok := componentsBySwitchID[switchID]
		if !ok || ip == "" {
			continue
		}
		if existing, ok := comp.Description[nvosIPDescriptionKey].(string); ok && existing == ip {
			continue
		}
		if comp.Description == nil {
			comp.Description = map[string]any{}
		}
		comp.Description[nvosIPDescriptionKey] = ip
		if err := comp.Patch(ctx, pool.DB); err != nil {
			log.Error().Msgf("NVSwitch %s: unable to persist NVOS IP %s: %v", comp.ID, ip, err)
			continue
		}
		log.Info().Msgf("NVSwitch %s: recorded NVOS IP %s", comp.ID, ip)
	}
}
