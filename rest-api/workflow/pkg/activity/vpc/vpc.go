// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package vpc

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"

	"go.temporal.io/sdk/client"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"

	cwm "github.com/NVIDIA/infra-controller/rest-api/workflow/internal/metrics"
	sc "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/client/site"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/util"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"

	cwutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
)

// ManageVpc is an activity wrapper for managing VPC lifecycle that allows
// injecting DB access
type ManageVpc struct {
	dbSession      *cdb.Session
	siteClientPool *sc.ClientPool
	tc             client.Client
}

// Activity functions

// UpdateVpcsInDB is a Temporal activity that takes a collection of VPC data pushed by Site Agent and updates the DB
func (mv ManageVpc) UpdateVpcsInDB(ctx context.Context, siteID uuid.UUID, vpcInventory *corev1.VPCInventory) ([]cwm.InventoryObjectLifecycleEvent, error) {
	logger := log.With().Str("Activity", "UpdateVpcsInDB").Str("Site ID", siteID.String()).Logger()

	logger.Info().Msg("starting activity")

	// Initialize metrics tracking variables
	vpcLifecycleEvents := []cwm.InventoryObjectLifecycleEvent{}

	stDAO := cdbm.NewSiteDAO(mv.dbSession)

	site, err := stDAO.GetByID(ctx, nil, siteID, nil, false)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			logger.Warn().Err(err).Msg("received VPC inventory for unknown or deleted Site")
		} else {
			logger.Error().Err(err).Msg("failed to retrieve Site from DB")
		}
		return nil, err
	}

	// Get temporal client for specified Site
	tc, err := mv.siteClientPool.GetClientByID(siteID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve Temporal client for Site")
		return nil, err
	}

	if vpcInventory.InventoryStatus == corev1.InventoryStatus_INVENTORY_STATUS_FAILED {
		logger.Warn().Msg("received failed inventory status from Site Agent, skipping inventory processing")
		return nil, errors.New(vpcInventory.StatusMsg)
	}

	vpcDAO := cdbm.NewVpcDAO(mv.dbSession)
	sdDAO := cdbm.NewStatusDetailDAO(mv.dbSession)

	existingVpcs, _, err := vpcDAO.GetAll(ctx, nil, cdbm.VpcFilterInput{
		SiteIDs: []uuid.UUID{site.ID},
	}, cdbp.PageInput{Limit: cwutil.GetPtr(cdbp.TotalLimit)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get VPCs for Site from DB")
		return nil, err
	}

	existingVpcIDMap := make(map[string]*cdbm.Vpc)
	existingVpcCtrlIDMap := make(map[string]*cdbm.Vpc)

	for i := range existingVpcs {
		vpc := &existingVpcs[i]
		existingVpcIDMap[vpc.ID.String()] = vpc
		if vpc.ControllerVpcID != nil {
			existingVpcCtrlIDMap[vpc.ControllerVpcID.String()] = vpc
		}
	}

	reportedVpcIDMap := map[uuid.UUID]bool{}

	if vpcInventory.InventoryPage != nil {
		logger.Info().Msgf("Received VPC inventory page: %d of %d, page size: %d, total count: %d",
			vpcInventory.InventoryPage.CurrentPage, vpcInventory.InventoryPage.TotalPages,
			vpcInventory.InventoryPage.PageSize, vpcInventory.InventoryPage.TotalItems)

		for _, strId := range vpcInventory.InventoryPage.ItemIds {
			id, serr := uuid.Parse(strId)
			if serr != nil {
				logger.Error().Err(serr).Str("ID", strId).Msg("failed to parse VPC ID from inventory page")
				continue
			}
			reportedVpcIDMap[id] = true
		}
	}

	// Prepare a map of ID -> propagation status
	// so we can quickly attach it to the object
	// when need to perform the update query.
	vpcPropagationStatus := map[string]*cdbm.NetworkSecurityGroupPropagationDetails{}
	for _, propStatus := range vpcInventory.NetworkSecurityGroupPropagations {
		vpcPropagationStatus[propStatus.Id] = &cdbm.NetworkSecurityGroupPropagationDetails{NetworkSecurityGroupPropagationObjectStatus: propStatus}
		logger.Debug().Str("Controller VPC ID", propStatus.Id).Msg("propagation details cached for VPC")
	}

	// Iterate through VPC Inventory and update DB
	for _, controllerVpc := range vpcInventory.Vpcs {
		if controllerVpc == nil || controllerVpc.GetId().GetValue() == "" {
			logger.Error().Msg("received VPC inventory entry with missing controller ID, skipping")
			continue
		}
		controllerVpcIDStr := controllerVpc.GetId().GetValue()
		slogger := logger.With().Str("VPC Controller ID", controllerVpcIDStr).Logger()

		sitePropagationStatus := vpcPropagationStatus[controllerVpcIDStr]
		slogger.Debug().Msgf("cached propagation status for VPC %+v", sitePropagationStatus)

		vpc := existingVpcCtrlIDMap[controllerVpcIDStr]
		if vpc == nil {
			vpc = existingVpcIDMap[controllerVpcIDStr]
		}

		// No active REST row for this inventory VPC: create one or undelete a soft-deleted match.
		if vpc == nil {
			vpc = mv.createOrUpdateVpcFromSite(ctx, site, controllerVpc, sitePropagationStatus)
			if vpc == nil {
				continue
			}

			// Keep in-memory maps in sync so later inventory entries and missing-on-Site detection see this VPC.
			existingVpcIDMap[vpc.ID.String()] = vpc
			if vpc.ControllerVpcID != nil {
				existingVpcCtrlIDMap[vpc.ControllerVpcID.String()] = vpc
			}
			reportedVpcIDMap[vpc.ID] = true
			slogger.Info().Str("VPC ID", vpc.ID.String()).Msg("created or updated VPC from Site inventory")
			continue
		}

		reportedVpcIDMap[vpc.ID] = true

		// Reset missing flag if necessary
		var isMissingOnSite *bool
		if vpc.IsMissingOnSite {
			isMissingOnSite = cwutil.GetPtr(false)
		}

		// Populate controller VPC ID if necessary
		var controllerVpcID *uuid.UUID
		if vpc.ControllerVpcID == nil {
			ctrlID, serr := uuid.Parse(controllerVpc.Id.Value)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to parse VPC Controller ID, not a valid UUID")
				continue
			}
			controllerVpcID = &ctrlID
		}

		reportedVpc := &cdbm.Vpc{}
		reportedVpc.FromProto(controllerVpc)

		// Initialized Network virtualization type
		var networkVirtualizationType *string
		// If the VPC in the DB has Network Virtualization Type, but Site reported different one then update it
		reportedVirtType := reportedVpc.NetworkVirtualizationType
		if reportedVirtType != nil && !util.PtrsEqual(vpc.NetworkVirtualizationType, reportedVirtType) {
			networkVirtualizationType = reportedVirtType
		}

		controllerActiveVni := reportedVpc.ActiveVni
		reportedRoutingProfile := reportedVpc.RoutingProfile
		reportedRoutingProfileOverrides := reportedVpc.RoutingProfileOverrides
		reportedEffectiveRoutingProfile := reportedVpc.EffectiveRoutingProfile
		reportedNSGID := reportedVpc.NetworkSecurityGroupID

		needsUpdate := isMissingOnSite != nil ||
			controllerVpcID != nil ||
			networkVirtualizationType != nil ||
			!util.PtrsEqual(vpc.RoutingProfile, reportedRoutingProfile) ||
			!reflect.DeepEqual(vpc.RoutingProfileOverrides, reportedRoutingProfileOverrides) ||
			!reflect.DeepEqual(vpc.EffectiveRoutingProfile, reportedEffectiveRoutingProfile) ||
			!util.PtrsEqual(vpc.NetworkSecurityGroupID, reportedNSGID) ||
			!vpc.NetworkSecurityGroupPropagationDetails.Equal(sitePropagationStatus) ||
			// Changing VNI isn't allowed after creation, and it should never go back to nil - that would be a bug.
			// We should assume status _could start_ as null and then update to the active VPC VNI.
			// Status should never go back to nil - that would be a bug.
			(controllerActiveVni != nil && !util.PtrsEqual(vpc.ActiveVni, controllerActiveVni))

		if needsUpdate {
			// A nil Update field is ignored, so explicitly clear a stale NSG association.
			if vpc.NetworkSecurityGroupID != nil && reportedNSGID == nil {
				vpc, err = vpcDAO.Clear(ctx, nil, cdbm.VpcClearInput{
					VpcID:                  vpc.ID,
					NetworkSecurityGroupID: true,
				})
				if err != nil {
					slogger.Error().Err(err).Msg("failed to clear NetworkSecurityGroupID for VPC in DB")
					continue
				}
			}

			// If the VPC in the DB has propagation details but the site reported no propagation details
			// then we should clear it in the DB.  Passing along the nil to the Update call would
			// just ignore the field.
			if vpc.NetworkSecurityGroupPropagationDetails != nil && sitePropagationStatus == nil {
				vpc, err = vpcDAO.Clear(ctx, nil, cdbm.VpcClearInput{
					VpcID:                                  vpc.ID,
					NetworkSecurityGroupPropagationDetails: true,
				})
				if err != nil {
					slogger.Error().Err(err).Msg("failed to clear NetworkSecurityGroupPropagationDetails for VPC in DB")
					continue
				}
			}

			// Controller omission clears cached routing-profile state. Update treats nil
			// as leave-unchanged, so explicitly clear each stale field first.
			if vpc.RoutingProfile != nil && reportedRoutingProfile == nil {
				vpc, err = vpcDAO.Clear(ctx, nil, cdbm.VpcClearInput{
					VpcID:          vpc.ID,
					RoutingProfile: true,
				})
				if err != nil {
					slogger.Error().Err(err).Msg("failed to clear RoutingProfile for VPC in DB")
					continue
				}
			}

			if vpc.RoutingProfileOverrides != nil && reportedRoutingProfileOverrides == nil {
				vpc, err = vpcDAO.Clear(ctx, nil, cdbm.VpcClearInput{
					VpcID:                   vpc.ID,
					RoutingProfileOverrides: true,
				})
				if err != nil {
					slogger.Error().Err(err).Msg("failed to clear RoutingProfileOverrides for VPC in DB")
					continue
				}
			}

			if vpc.EffectiveRoutingProfile != nil && reportedEffectiveRoutingProfile == nil {
				vpc, err = vpcDAO.Clear(ctx, nil, cdbm.VpcClearInput{
					VpcID:                   vpc.ID,
					EffectiveRoutingProfile: true,
				})
				if err != nil {
					slogger.Error().Err(err).Msg("failed to clear EffectiveRoutingProfile for VPC in DB")
					continue
				}
			}

			// Persist remaining non-nil controller-reported differences after explicit clears.
			_, serr := vpcDAO.Update(ctx, nil, cdbm.VpcUpdateInput{
				VpcID:                                  vpc.ID,
				NetworkSecurityGroupID:                 reportedNSGID,
				NetworkSecurityGroupPropagationDetails: sitePropagationStatus,
				NetworkVirtualizationType:              networkVirtualizationType,
				RoutingProfile:                         reportedRoutingProfile,
				RoutingProfileOverrides:                reportedRoutingProfileOverrides,
				EffectiveRoutingProfile:                reportedEffectiveRoutingProfile,
				ControllerVpcID:                        controllerVpcID,
				IsMissingOnSite:                        isMissingOnSite,
				ActiveVni:                              controllerActiveVni,
			})
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to update missing on Site flag/controller VPC ID in DB")
				continue
			}
		}

		// If VPC is not in Deleting state, then update status to Ready
		if vpc.Status != cdbm.VpcStatusDeleting && vpc.Status != cdbm.VpcStatusReady {
			err = mv.updateVpcStatusInDB(ctx, nil, vpc.ID, cwutil.GetPtr(cdbm.VpcStatusReady), cwutil.GetPtr("VPC is ready for use"))
			if err != nil {
				slogger.Error().Err(err).Msg("failed to update VPC status detail in DB")
			}
		}

		// Verify if VPC's metadata update required, if yes trigger `UpdateVPC` workflow
		if controllerVpc.Metadata != nil {
			triggerVpcMetadataUpdate := false

			if vpc.Name != controllerVpc.Metadata.Name {
				triggerVpcMetadataUpdate = true
			}

			if vpc.Description != nil && *vpc.Description != controllerVpc.Metadata.Description {
				triggerVpcMetadataUpdate = true
			}

			if controllerVpc.Metadata.Labels != nil && vpc.Labels != nil {
				if len(vpc.Labels) != len(controllerVpc.Metadata.Labels) {
					triggerVpcMetadataUpdate = true
				} else {
					// Verify if each label matches with Vpc in cloud
					for _, label := range controllerVpc.Metadata.Labels {
						if label != nil {
							// case1: Key not found
							_, ok := vpc.Labels[label.Key]
							if !ok {
								triggerVpcMetadataUpdate = true
								break
							}

							// case2: Value isn't matching
							if label.Value != nil {
								if vpc.Labels[label.Key] != *label.Value {
									triggerVpcMetadataUpdate = true
									break
								}
							}
						}
					}
				}
			}

			// Trigger update Vpc metadata workflow
			if triggerVpcMetadataUpdate {
				_ = mv.UpdateVpcMetadata(ctx, siteID, tc, vpc.ID, controllerVpc)
			}
		}
	}

	// Populate list of VPCs that were not found
	vpcsToDelete := []*cdbm.Vpc{}

	// If inventory paging is enabled, we only need to do this once and we do it on the last page
	if vpcInventory.InventoryPage == nil || vpcInventory.InventoryPage.TotalPages == 0 || (vpcInventory.InventoryPage.CurrentPage == vpcInventory.InventoryPage.TotalPages) {
		for _, vpc := range existingVpcIDMap {
			found := false

			_, found = reportedVpcIDMap[vpc.ID]
			if !found && vpc.ControllerVpcID != nil {
				// Additional check if controller VPC ID != VPC ID
				_, found = reportedVpcIDMap[*vpc.ControllerVpcID]
			}

			if !found {
				// The VPC was not found in the VPC Inventory, so add it to list of VPCs to potentially terminate
				vpcsToDelete = append(vpcsToDelete, vpc)
			}
		}
	}

	// Loop through VPCs for deletion
	for _, vpc := range vpcsToDelete {
		slogger := logger.With().Str("VPC ID", vpc.ID.String()).Logger()

		// If the VPC was already being deleted, we can proceed with removing it from the DB
		if vpc.Status == cdbm.VpcStatusDeleting {
			serr := vpcDAO.DeleteByID(ctx, nil, vpc.ID)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to delete VPC from DB")
			} else {
				// Add VPC ID to deletedVpcIDs list
				vpcLifecycleEvents = append(vpcLifecycleEvents, cwm.InventoryObjectLifecycleEvent{
					ObjectID: vpc.ID,
					Deleted:  cwutil.GetPtr(time.Now()),
				})
			}
		} else if vpc.ControllerVpcID != nil {
			// Was this created within inventory receipt interval? If so, we may be processing an older inventory
			if time.Since(vpc.Created) < cwutil.InventoryReceiptInterval {
				continue
			}

			status := cdbm.VpcStatusError
			statusMessage := "VPC is missing on Site"

			// Leave orderBy as nil as the result is sorted by created timestamp by default
			if status == vpc.Status {
				latestsd, _, serr := sdDAO.GetAll(ctx, nil, cdbm.StatusDetailFilterInput{EntityIDs: []string{vpc.ID.String()}}, cdbp.PageInput{Limit: cwutil.GetPtr(1)})
				if serr != nil {
					slogger.Error().Err(serr).Msg("failed to retrieve latest Status Detail for VPC")
					continue
				}

				if len(latestsd) > 0 && latestsd[0].Message != nil && *latestsd[0].Message == statusMessage {
					continue
				}
			}

			// Set isMissingOnSite flag to true and update status, user can decide on deletion
			_, serr := vpcDAO.Update(ctx, nil, cdbm.VpcUpdateInput{VpcID: vpc.ID, IsMissingOnSite: cwutil.GetPtr(true)})
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to set missing on Site flag in DB")
				continue
			}

			serr = mv.updateVpcStatusInDB(ctx, nil, vpc.ID, &status, &statusMessage)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to update status and/or create Status Detail in DB")
			}
		}
	}

	return vpcLifecycleEvents, nil
}

// createOrUpdateVpcFromSite creates a REST VPC from Site inventory, or undeletes
// a matching soft-deleted row. Returns nil when skipped or on failure.
func (mv ManageVpc) createOrUpdateVpcFromSite(
	ctx context.Context,
	site *cdbm.Site,
	siteInventoryVpc *corev1.Vpc,
	propagationDetails *cdbm.NetworkSecurityGroupPropagationDetails,
) *cdbm.Vpc {
	logger := log.With().
		Str("Activity", "UpdateVpcsInDB").
		Str("Site ID", site.ID.String()).
		Str("VPC Controller ID", siteInventoryVpc.GetId().GetValue()).
		Logger()

	vpcID, err := uuid.Parse(siteInventoryVpc.GetId().GetValue())
	if err != nil {
		logger.Warn().Err(err).Msg("skipping VPC from Site: controller VPC ID is not a valid UUID")
		return nil
	}

	fromSite := new(cdbm.Vpc)
	fromSite.FromProto(siteInventoryVpc)
	if fromSite.Name == "" {
		logger.Warn().Msg("skipping VPC from Site: VPC metadata does not contain a name")
		return nil
	}
	if fromSite.Org == "" {
		logger.Warn().Msg("skipping VPC from Site: VPC does not report a tenant organization")
		return nil
	}

	// Create/restore under one transaction so concurrent inventory pages cannot insert duplicates.
	vpc, err := cdb.WithTxResult(ctx, mv.dbSession, func(tx *cdb.Tx) (*cdbm.Vpc, error) {
		vpcDAO := cdbm.NewVpcDAO(mv.dbSession)

		// Match by primary key first; DAO ANDs VpcIDs with ControllerVpcIDs, so fall back separately.
		matches, _, reloadErr := vpcDAO.GetAll(ctx, tx, cdbm.VpcFilterInput{
			VpcIDs: []uuid.UUID{vpcID}, SiteIDs: []uuid.UUID{site.ID}, IncludeDeleted: true,
		}, cdbp.PageInput{Limit: cwutil.GetPtr(cdbp.TotalLimit)}, []string{cdbm.TenantRelationName})
		if reloadErr != nil {
			return nil, fmt.Errorf("reload VPC by inventory ID: %w", reloadErr)
		}
		if len(matches) == 0 {
			matches, _, reloadErr = vpcDAO.GetAll(ctx, tx, cdbm.VpcFilterInput{
				ControllerVpcIDs: []uuid.UUID{vpcID}, SiteIDs: []uuid.UUID{site.ID}, IncludeDeleted: true,
			}, cdbp.PageInput{Limit: cwutil.GetPtr(cdbp.TotalLimit)}, []string{cdbm.TenantRelationName})
			if reloadErr != nil {
				return nil, fmt.Errorf("reload VPC by controller ID: %w", reloadErr)
			}
		}

		// Split matches into at most one active and one soft-deleted row for this identity.
		var activeVpc, softDeletedVpc *cdbm.Vpc
		for i := range matches {
			row := &matches[i]
			if row.Deleted == nil {
				if activeVpc != nil {
					logger.Warn().Msg("skipping VPC from Site: inventory identity matches multiple active VPCs")
					return nil, nil
				}
				activeVpc = row
				continue
			}
			if softDeletedVpc != nil {
				logger.Warn().Msg("skipping VPC from Site: inventory identity matches multiple soft-deleted VPCs")
				return nil, nil
			}
			softDeletedVpc = row
		}
		if activeVpc != nil {
			return activeVpc, nil
		}

		// Restore keeps the soft-deleted row's tenant; create resolves tenant from the Site org.
		var tenant *cdbm.Tenant
		if softDeletedVpc != nil {
			if softDeletedVpc.Org != fromSite.Org {
				logger.Warn().Msg("skipping VPC from Site: soft-deleted VPC tenant organization differs from Site inventory")
				return nil, nil
			}
			if softDeletedVpc.Tenant == nil {
				logger.Warn().Msg("skipping VPC from Site: soft-deleted VPC tenant does not exist")
				return nil, nil
			}
			tenant = softDeletedVpc.Tenant
		} else {
			tenants, _, tenantErr := cdbm.NewTenantDAO(mv.dbSession).GetAll(
				ctx, tx, cdbm.TenantFilterInput{Orgs: []string{fromSite.Org}}, cdbp.PageInput{Limit: cwutil.GetPtr(cdbp.TotalLimit)}, nil,
			)
			if tenantErr != nil {
				return nil, fmt.Errorf("get VPC tenant by organization: %w", tenantErr)
			}
			if len(tenants) == 0 {
				logger.Warn().Msg("skipping VPC from Site: tenant organization does not have a REST Tenant")
				return nil, nil
			}
			tenant = &tenants[0]
		}

		nsgID := fromSite.NetworkSecurityGroupID
		nvLinkID := fromSite.NVLinkLogicalPartitionID
		if softDeletedVpc != nil {
			if nsgID == nil {
				nsgID = softDeletedVpc.NetworkSecurityGroupID
			}
			// Existing REST NVLink assignment stays authoritative on restore.
			nvLinkID = softDeletedVpc.NVLinkLogicalPartitionID
		}

		// Skip when referenced NSG/NVLink is missing or not owned by this tenant/site.
		if nsgID != nil {
			_, nsgErr := cdbm.NewNetworkSecurityGroupDAO(mv.dbSession).GetByID(ctx, tx, *nsgID, nil)
			if errors.Is(nsgErr, cdb.ErrDoesNotExist) {
				logger.Warn().Msg("skipping VPC from Site: referenced Network Security Group does not exist in REST")
				return nil, nil
			}
			if nsgErr != nil {
				return nil, fmt.Errorf("get inventory VPC Network Security Group: %w", nsgErr)
			}
		}

		if nvLinkID != nil {
			nvLink, nvLinkErr := cdbm.NewNVLinkLogicalPartitionDAO(mv.dbSession).GetByID(ctx, tx, *nvLinkID, nil)
			if errors.Is(nvLinkErr, cdb.ErrDoesNotExist) {
				logger.Warn().Msg("skipping VPC from Site: referenced NVLink Logical Partition does not exist in REST")
				return nil, nil
			}
			if nvLinkErr != nil {
				return nil, fmt.Errorf("get inventory VPC NVLink Logical Partition: %w", nvLinkErr)
			}
			if nvLink.SiteID != site.ID || nvLink.TenantID != tenant.ID {
				logger.Warn().Msg("skipping VPC from Site: referenced NVLink Logical Partition belongs to a different Tenant or Site")
				return nil, nil
			}
			// Restore may keep a non-Ready NVLink; new creates require Ready.
			if softDeletedVpc == nil && nvLink.Status != cdbm.NVLinkLogicalPartitionStatusReady {
				logger.Warn().Msg("skipping VPC from Site: referenced NVLink Logical Partition is not Ready")
				return nil, nil
			}
		}

		// Reject inventoring a VPC whose name is already taken by another active row.
		vpcName := fromSite.Name
		if softDeletedVpc != nil {
			vpcName = softDeletedVpc.Name
		}
		nameConflictVpcs, _, nameErr := vpcDAO.GetAll(ctx, tx, cdbm.VpcFilterInput{
			Name: &vpcName, TenantIDs: []uuid.UUID{tenant.ID}, SiteIDs: []uuid.UUID{site.ID},
		}, cdbp.PageInput{Limit: cwutil.GetPtr(cdbp.TotalLimit)}, nil)
		if nameErr != nil {
			return nil, fmt.Errorf("check inventory VPC name conflict: %w", nameErr)
		}
		for i := range nameConflictVpcs {
			if softDeletedVpc == nil || nameConflictVpcs[i].ID != softDeletedVpc.ID {
				logger.Warn().Msg("skipping VPC from Site: an active VPC with the same name already exists for the Tenant and Site")
				return nil, nil
			}
		}

		statusDetailDAO := cdbm.NewStatusDetailDAO(mv.dbSession)
		readyMsg := "VPC was found on Site, Ready for use"

		if softDeletedVpc != nil {
			// Bun soft-delete requires the deleted timestamp to already be in the past.
			if softDeletedVpc.Deleted != nil && !time.Now().After(*softDeletedVpc.Deleted) {
				logger.Warn().Msg("skipping VPC from Site: soft-delete marker is not in the past")
				return nil, nil
			}

			// Prefer Site inventory values; fall back to the soft-deleted row.
			nvt := softDeletedVpc.NetworkVirtualizationType
			if fromSite.NetworkVirtualizationType != nil {
				nvt = fromSite.NetworkVirtualizationType
			}
			activeVni := softDeletedVpc.ActiveVni
			if fromSite.ActiveVni != nil {
				activeVni = fromSite.ActiveVni
			}
			requestedVni := softDeletedVpc.Vni
			if fromSite.Vni != nil {
				requestedVni = fromSite.Vni
			}
			routingProfile := softDeletedVpc.RoutingProfile
			if fromSite.RoutingProfile != nil {
				routingProfile = fromSite.RoutingProfile
			}
			routingOverrides := softDeletedVpc.RoutingProfileOverrides
			if fromSite.RoutingProfileOverrides != nil {
				routingOverrides = fromSite.RoutingProfileOverrides
			}
			effectiveRouting := softDeletedVpc.EffectiveRoutingProfile
			if fromSite.EffectiveRoutingProfile != nil {
				effectiveRouting = fromSite.EffectiveRoutingProfile
			}

			// Clear(Deleted) undeletes the row; Update then refreshes inventory fields to Ready.
			if _, clearErr := vpcDAO.Clear(ctx, tx, cdbm.VpcClearInput{VpcID: softDeletedVpc.ID, Deleted: true}); clearErr != nil {
				return nil, fmt.Errorf("clear soft-deleted VPC: %w", clearErr)
			}
			restored, updateErr := vpcDAO.Update(ctx, tx, cdbm.VpcUpdateInput{
				VpcID:                                  softDeletedVpc.ID,
				ControllerVpcID:                        &vpcID,
				NetworkVirtualizationType:              nvt,
				RoutingProfile:                         routingProfile,
				RoutingProfileOverrides:                routingOverrides,
				EffectiveRoutingProfile:                effectiveRouting,
				ActiveVni:                              activeVni,
				NetworkSecurityGroupID:                 nsgID,
				NetworkSecurityGroupPropagationDetails: propagationDetails,
				Status:                                 cwutil.GetPtr(cdbm.VpcStatusReady),
				IsMissingOnSite:                        cwutil.GetPtr(false),
				Vni:                                    requestedVni,
			})
			if updateErr != nil {
				return nil, fmt.Errorf("update restored VPC from Site: %w", updateErr)
			}
			if _, statusErr := statusDetailDAO.Create(ctx, tx, cdbm.StatusDetailCreateInput{
				EntityID: restored.ID.String(), Status: cdbm.VpcStatusReady, Message: &readyMsg,
			}); statusErr != nil {
				return nil, fmt.Errorf("create restored VPC status detail: %w", statusErr)
			}
			return restored, nil
		}

		// No soft-deleted match: insert a new Ready VPC keyed by the Site inventory ID.
		createdBy := cdbm.User{}
		createdBy.ID = site.ID
		created, createErr := vpcDAO.Create(ctx, tx, cdbm.VpcCreateInput{
			ID:                                     &vpcID,
			Name:                                   fromSite.Name,
			Description:                            fromSite.Description,
			Org:                                    fromSite.Org,
			InfrastructureProviderID:               site.InfrastructureProviderID,
			TenantID:                               tenant.ID,
			SiteID:                                 site.ID,
			NVLinkLogicalPartitionID:               nvLinkID,
			NetworkVirtualizationType:              fromSite.NetworkVirtualizationType,
			RoutingProfile:                         fromSite.RoutingProfile,
			RoutingProfileOverrides:                fromSite.RoutingProfileOverrides,
			ControllerVpcID:                        &vpcID,
			ActiveVni:                              fromSite.ActiveVni,
			NetworkSecurityGroupID:                 nsgID,
			NetworkSecurityGroupPropagationDetails: propagationDetails,
			Labels:                                 fromSite.Labels,
			Status:                                 cdbm.VpcStatusReady,
			CreatedBy:                              createdBy,
			Vni:                                    fromSite.Vni,
		})
		if createErr != nil {
			return nil, fmt.Errorf("create VPC from Site: %w", createErr)
		}
		// EffectiveRoutingProfile is not part of CreateInput, so set it in a follow-up Update.
		if fromSite.EffectiveRoutingProfile != nil {
			created, createErr = vpcDAO.Update(ctx, tx, cdbm.VpcUpdateInput{
				VpcID: created.ID, EffectiveRoutingProfile: fromSite.EffectiveRoutingProfile,
			})
			if createErr != nil {
				return nil, fmt.Errorf("update created VPC effective routing profile: %w", createErr)
			}
		}
		if _, statusErr := statusDetailDAO.Create(ctx, tx, cdbm.StatusDetailCreateInput{
			EntityID: created.ID.String(), Status: cdbm.VpcStatusReady, Message: &readyMsg,
		}); statusErr != nil {
			return nil, fmt.Errorf("create inventory VPC status detail: %w", statusErr)
		}
		return created, nil
	})
	if err != nil {
		logger.Warn().Err(err).Msg("failed to create or update VPC from Site")
		return nil
	}
	return vpc
}

// updateVpcStatusInDB is helper function to write VPC updates to DB
func (mv ManageVpc) updateVpcStatusInDB(ctx context.Context, tx *cdb.Tx, vpcID uuid.UUID, status *string, statusMessage *string) error {
	if status != nil {
		vpcDAO := cdbm.NewVpcDAO(mv.dbSession)

		_, err := vpcDAO.Update(ctx, tx, cdbm.VpcUpdateInput{VpcID: vpcID, Status: status})
		if err != nil {
			return err
		}

		statusDetailDAO := cdbm.NewStatusDetailDAO(mv.dbSession)
		_, err = statusDetailDAO.Create(ctx, tx, cdbm.StatusDetailCreateInput{EntityID: vpcID.String(), Status: *status, Message: statusMessage})
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateVpcMetadata is a Temporal activity that will trigger an update of an vpc's metadata
// if they are found out of sync with the cloud.
func (mv ManageVpc) UpdateVpcMetadata(ctx context.Context, siteID uuid.UUID, tc client.Client, vpcID uuid.UUID, controllerVpc *corev1.Vpc) error {
	logger := log.With().Str("Activity", "UpdateVpcMetadata").Str("Site ID", siteID.String()).Str("VPC ID", vpcID.String()).Logger()

	logger.Info().Msg("starting activity")

	vpcDAO := cdbm.NewVpcDAO(mv.dbSession)
	vpc, err := vpcDAO.GetByID(ctx, nil, vpcID, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve VPC from DB by ID")
		return err
	}

	logger.Info().Msg("retrieved VPC from DB")

	description := ""
	if vpc.Description != nil {
		description = *vpc.Description
	}

	// Prepare the labels for the metadata of the nico call.
	labels := []*corev1.Label{}
	for k, v := range vpc.Labels {
		labels = append(labels, &corev1.Label{
			Key:   k,
			Value: &v,
		})
	}

	// Build an update request for vpc that needs a sync metadata and call UpdateVpc.
	workflowOptions := client.StartWorkflowOptions{
		ID:        "site-vpc-update-metadata-" + vpcID.String(),
		TaskQueue: queue.SiteTaskQueue,
	}

	// Prepare the config update request workflow object. NetworkSecurityGroupId is
	// intentionally omitted: this activity only syncs metadata fields.
	updateVpcRequest := &corev1.VpcUpdateRequest{
		Id: &corev1.VpcId{Value: vpc.ID.String()},
		Metadata: &corev1.Metadata{
			Name:        vpc.Name,
			Description: description,
			Labels:      labels,
		},
	}

	we, err := tc.ExecuteWorkflow(ctx, workflowOptions, "UpdateVPC", updateVpcRequest)
	if err != nil {
		logger.Error().Err(err).Str("VPC ID", vpc.ID.String()).Msg("failed to trigger workflow to update VPC Metadata")
	} else {
		logger.Info().Str("Workflow ID", we.GetID()).Msg("triggered workflow to update VPC Metadata")
	}

	logger.Info().Msg("completed activity")

	return nil
}

// NewManageVpc returns a new ManageVpc activity
func NewManageVpc(dbSession *cdb.Session, siteClientPool *sc.ClientPool, tc client.Client) ManageVpc {
	return ManageVpc{
		dbSession:      dbSession,
		siteClientPool: siteClientPool,
		tc:             tc,
	}
}

// ManageVpcLifecycleMetrics is an activity wrapper for managing VPC lifecycle metrics
type ManageVpcLifecycleMetrics struct {
	dbSession            *cdb.Session
	statusTransitionTime *prometheus.GaugeVec
	siteIDNameMap        map[uuid.UUID]string
}

// RecordVpcStatusTransitionMetrics is a Temporal activity that records duration of important status transitions for VPCs
func (mvlm ManageVpcLifecycleMetrics) RecordVpcStatusTransitionMetrics(ctx context.Context, siteID uuid.UUID, vpcLifecycleEvents []cwm.InventoryObjectLifecycleEvent) error {
	logger := log.With().Str("Activity", "RecordVpcStatusTransitionMetrics").Str("Site ID", siteID.String()).Logger()

	logger.Info().Msg("starting activity")

	// Cache site name to avoid repeated DB call
	siteName, ok := mvlm.siteIDNameMap[siteID]
	if !ok {
		siteDAO := cdbm.NewSiteDAO(mvlm.dbSession)
		site, err := siteDAO.GetByID(context.Background(), nil, siteID, nil, false)
		if err != nil {
			logger.Error().Err(err).Str("Site ID", siteID.String()).Msg("failed to retrieve Site from DB")
			return err
		}
		siteName = site.Name
		mvlm.siteIDNameMap[siteID] = siteName
	}

	logger.Info().Int("EventCount", len(vpcLifecycleEvents)).Str("Site Name", siteName).Msg("processing vpc lifecycle events")

	// Get status details for each VPC
	sdDAO := cdbm.NewStatusDetailDAO(mvlm.dbSession)
	metricsRecorded := 0

	for _, event := range vpcLifecycleEvents {
		statusDetails, _, err := sdDAO.GetAll(ctx, nil, cdbm.StatusDetailFilterInput{EntityIDs: []string{event.ObjectID.String()}}, cdbp.PageInput{Limit: cwutil.GetPtr(cdbp.TotalLimit)})
		if err != nil {
			logger.Error().Err(err).Str("VPC ID", event.ObjectID.String()).Msg("failed to retrieve Status Details for VPC")
			return err
		}

		if event.Created != nil {
			// NOTE: VPC create operation is not tracked in this activity since it is created in synchronous manner and it should never arrive here
			logger.Warn().Str("VPC ID", event.ObjectID.String()).Msg("VPC create operation is not tracked in this activity since it is created in synchronous manner and it should never arrive here")
		} else if event.Deleted != nil {
			// DELETE event: Measure time from Deleting to actual deletion
			// Find the earliest Deleting status (iterate backwards since sorted DESC)
			var deletingStatusDetail *cdbm.StatusDetail
			for i := range slices.Backward(statusDetails) {
				sd := &statusDetails[i]
				if sd.Status == cdbm.VpcStatusDeleting {
					deletingStatusDetail = sd
					break
				}
			}

			if deletingStatusDetail != nil {
				// Calculate duration from Deleting status to deletion time
				duration := event.Deleted.Sub(deletingStatusDetail.Created)
				// Note: VPC doesn't have VpcStatusDeleted constant, so we use string "Deleted"
				mvlm.statusTransitionTime.WithLabelValues(siteName, cwm.InventoryOperationTypeDelete, cdbm.VpcStatusDeleting, "Deleted").Set(duration.Seconds())
				metricsRecorded++
				logger.Info().
					Str("VPC ID", event.ObjectID.String()).
					Str("Operation", "DELETE").
					Float64("Duration Seconds", duration.Seconds()).
					Msg("recorded vpc lifecycle metric")
			} else {
				logger.Debug().
					Str("VPC ID", event.ObjectID.String()).
					Msg("skipped vpc DELETE metric")
			}
		}
	}

	logger.Info().Int("MetricsRecorded", metricsRecorded).Msg("completed activity")

	return nil
}

// NewManageVpcLifecycleMetrics returns a new ManageVpcLifecycleMetrics activity
func NewManageVpcLifecycleMetrics(reg prometheus.Registerer, dbSession *cdb.Session) ManageVpcLifecycleMetrics {
	lifecycleMetrics := ManageVpcLifecycleMetrics{
		dbSession: dbSession,
		statusTransitionTime: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: cwm.MetricsNamespace,
				Name:      "vpc_operation_latency_seconds",
				Help:      "Current latency of vpc operations",
			},
			[]string{"site", "operation_type", "from_status", "to_status"}),

		siteIDNameMap: map[uuid.UUID]string{},
	}
	reg.MustRegister(lifecycleMetrics.statusTransitionTime)

	return lifecycleMetrics
}
