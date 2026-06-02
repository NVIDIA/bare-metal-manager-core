// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package subnet

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"go.temporal.io/sdk/client"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/ipam"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"

	cwm "github.com/NVIDIA/infra-controller-rest/workflow/internal/metrics"
	sc "github.com/NVIDIA/infra-controller-rest/workflow/pkg/client/site"

	cwsv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"

	"github.com/prometheus/client_golang/prometheus"

	cwutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
)

const (
	// DefaultReservedIPCount is the number of IP addresses to reserve in the subnet (usually the first and the last)
	DefaultReservedIPCount = 2
)

// ManageSubnet is an activity wrapper for managing Subnet lifecycle that allows
// injecting DB access
type ManageSubnet struct {
	dbSession      *cdb.Session
	siteClientPool *sc.ClientPool
	tc             client.Client
}

// Activity functions

// UpdateSubnetsInDB is a Temporal activity that takes a collection of Subnet/Network Segment data pushed by Site Agent and updates the DB
func (ms ManageSubnet) UpdateSubnetsInDB(ctx context.Context, siteID uuid.UUID, subnetInventory *cwsv1.SubnetInventory) ([]cwm.InventoryObjectLifecycleEvent, error) {
	logger := log.With().Str("Activity", "UpdateSubnetsInDB").Str("Site ID", siteID.String()).Logger()

	logger.Info().Msg("starting activity")

	// Initialize lifecycle events collector for metrics
	subnetLifecycleEvents := []cwm.InventoryObjectLifecycleEvent{}

	stDAO := cdbm.NewSiteDAO(ms.dbSession)

	site, err := stDAO.GetByID(ctx, nil, siteID, nil, false)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			logger.Warn().Err(err).Msg("received Subnet inventory for unknown or deleted Site")
		} else {
			logger.Error().Err(err).Msg("failed to retrieve Site from DB")
		}
		return nil, err
	}

	if subnetInventory.InventoryStatus == cwsv1.InventoryStatus_INVENTORY_STATUS_FAILED {
		logger.Warn().Msg("received failed inventory status from Site Agent, skipping inventory processing")
		return nil, nil
	}

	subnetDAO := cdbm.NewSubnetDAO(ms.dbSession)
	sdDAO := cdbm.NewStatusDetailDAO(ms.dbSession)

	subnets, total, err := subnetDAO.GetAll(ctx, nil, cdbm.SubnetFilterInput{SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)}, []string{})
	if err != nil {
		logger.Error().Err(err).Msg("failed to get Subnets for Site from DB")
		return nil, err
	}

	if total == 0 {
		logger.Info().Msg("No Subnets found for Site")
		return nil, nil
	}

	// Construct a map of Controller Segment ID to Subnet
	existingSubnetIDMap := make(map[string]*cdbm.Subnet)
	existingSubnetCtrlIDMap := make(map[string]*cdbm.Subnet)

	for _, subnet := range subnets {
		foundSubnet := subnet
		existingSubnetIDMap[subnet.ID.String()] = &foundSubnet
		if subnet.ControllerNetworkSegmentID != nil {
			existingSubnetCtrlIDMap[subnet.ControllerNetworkSegmentID.String()] = &foundSubnet
		}
	}

	reportedSubnetIDMap := map[uuid.UUID]bool{}

	if subnetInventory.InventoryPage != nil {
		logger.Info().Msgf("Received Subnet inventory page: %d of %d, page size: %d, total count: %d",
			subnetInventory.InventoryPage.CurrentPage, subnetInventory.InventoryPage.TotalPages,
			subnetInventory.InventoryPage.PageSize, subnetInventory.InventoryPage.TotalItems)

		for _, strId := range subnetInventory.InventoryPage.ItemIds {
			id, serr := uuid.Parse(strId)
			if serr != nil {
				logger.Error().Err(serr).Str("ID", strId).Msg("failed to parse Subnet ID from inventory page")
				continue
			}
			reportedSubnetIDMap[id] = true
		}
	}

	// Iterate through Subnet Inventory and update DB
	for _, controllerSegment := range subnetInventory.Segments {
		slogger := logger.With().Str("Controller Segment ID", controllerSegment.Id.Value).Logger()

		subnet, ok := existingSubnetCtrlIDMap[controllerSegment.Id.Value]
		if !ok {
			// Check if the Subnet is found by ID (controllerSegment.Name == cloudSubnet.ID)
			subnet, ok = existingSubnetIDMap[controllerSegment.Name]
			if ok {
				existingSubnetCtrlIDMap[controllerSegment.Id.Value] = subnet
			}
		}

		if subnet == nil {
			if controllerSegment.SegmentType == cwsv1.NetworkSegmentType_TENANT {
				logger.Error().Str("Controller Segment ID", controllerSegment.Id.Value).Msg("Network Segment does not have a Subnet record in DB, possibly created directly on Site")
			}
			continue
		}

		reportedSubnetIDMap[subnet.ID] = true

		// Reset missing flag if necessary
		var isMissingOnSite *bool
		if subnet.IsMissingOnSite {
			isMissingOnSite = cdb.GetBoolPtr(false)
		}

		// Populate controller Subnet ID if necessary
		var controllerSegmentID *uuid.UUID
		if subnet.ControllerNetworkSegmentID == nil {
			ctrlID, serr := uuid.Parse(controllerSegment.Id.Value)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to parse Subnet Controller ID, not a valid UUID")
				continue
			}
			controllerSegmentID = &ctrlID
		}

		var mtu *int
		if controllerSegment.Mtu != nil {
			mtuVal := int(*controllerSegment.Mtu)
			mtu = &mtuVal
		}

		if mtu != nil || isMissingOnSite != nil || controllerSegmentID != nil {
			_, serr := subnetDAO.Update(ctx, nil, cdbm.SubnetUpdateInput{SubnetId: subnet.ID, ControllerNetworkSegmentID: controllerSegmentID, Mtu: mtu, IsMissingOnSite: cdb.GetBoolPtr(false)})
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to update MTU/missing on Site flag/controller Segment ID in DB")
				continue
			}
		}

		// Update Subnet in DB
		status, statusMessage := getNICoSubnetStatus(controllerSegment.State)

		// If Subnet is already in Deleting state then no need to update status
		if subnet.Status == cdbm.SubnetStatusDeleting {
			continue
		}

		// Check if most recent status detail is the same as the current status, otherwise create a new one
		updateStatusInDB := false
		if subnet.Status != status {
			// Status is different, create a new status detail
			updateStatusInDB = true
		} else {
			// Check if the latest status detail message is different from the current status message
			// Leave orderBy nil since the result is sorted by create timestamp by default
			latestsd, _, serr := sdDAO.GetAllByEntityID(ctx, nil, subnet.ID.String(), nil, cdb.GetIntPtr(1), nil)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to retrieve latest Status Detail for Subnet")
			} else if len(latestsd) == 0 || (latestsd[0].Message != nil && *latestsd[0].Message != statusMessage) {
				updateStatusInDB = true
			}
		}

		if updateStatusInDB {
			serr := ms.updateSubnetStatusInDB(ctx, nil, subnet.ID, &status, &statusMessage)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to update status and/or create Status Detail in DB")
			} else {
				// When subnet becomes Ready, record a creation lifecycle event; actual duration will be computed from StatusDetails
				if status == cdbm.SubnetStatusReady {
					slogger.Info().Str("To Status", status).Msg("recording subnet create lifecycle event")
					subnetLifecycleEvents = append(subnetLifecycleEvents, cwm.InventoryObjectLifecycleEvent{ObjectID: subnet.ID, Created: cdb.GetTimePtr(time.Now())})
				}
			}
		}
	}

	// Process Subnets that were not found
	subnetsToDelete := []*cdbm.Subnet{}

	// If inventory paging is enabled, we only need to do this once and we do it on the last page
	if subnetInventory.InventoryPage == nil || subnetInventory.InventoryPage.TotalPages == 0 || (subnetInventory.InventoryPage.CurrentPage == subnetInventory.InventoryPage.TotalPages) {
		for _, subnet := range existingSubnetIDMap {
			found := false

			_, found = reportedSubnetIDMap[subnet.ID]
			if !found && subnet.ControllerNetworkSegmentID != nil {
				// Additional check if controller Segment ID != Subnet ID
				_, found = reportedSubnetIDMap[*subnet.ControllerNetworkSegmentID]
			}

			if !found {
				// The Subnet was not found in the Subnet Inventory, so add it to list of Subnets to potentially terminate
				subnetsToDelete = append(subnetsToDelete, subnet)
			}
		}
	}

	// Loop through and remove controller Network Segment ID from Subnets that were not found
	for _, subnet := range subnetsToDelete {
		slogger := logger.With().Str("Subnet ID", subnet.ID.String()).Logger()

		// If the Subnet was already being deleted, we can proceed with removing it from the DB
		if subnet.Status == cdbm.SubnetStatusDeleting {
			// Retrieve Subnet with IPBlock
			curSubnet, serr := subnetDAO.GetByID(ctx, nil, subnet.ID, []string{cdbm.IPv4BlockRelationName})
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to get Subnet from DB")
				continue
			}

			// The Subnet was being deleted, so delete it from DB
			tx, terr := cdb.BeginTx(ctx, ms.dbSession, &sql.TxOptions{})
			if terr != nil {
				slogger.Error().Err(terr).Msg("failed to start transaction")
				return subnetLifecycleEvents, terr
			}

			serr = ms.deleteSubnetFromDB(ctx, tx, curSubnet, logger)
			if serr != nil {
				slogger.Error().Err(serr).Msg("failed to delete Subnet from DB")
				terr := tx.Rollback()
				if terr != nil {
					slogger.Error().Err(terr).Msg("failed to rollback transaction")
				}
			} else {
				err = tx.Commit()
				if err != nil {
					slogger.Error().Err(err).Msg("error committing Subnet delete transaction to DB")
				} else {
					// Add delete lifecycle event for metrics
					slogger.Info().Str("Subnet ID", curSubnet.ID.String()).Msg("recording subnet delete lifecycle event")
					subnetLifecycleEvents = append(subnetLifecycleEvents, cwm.InventoryObjectLifecycleEvent{ObjectID: curSubnet.ID, Deleted: cdb.GetTimePtr(time.Now())})
				}
			}
		} else if subnet.ControllerNetworkSegmentID != nil {
			// Was this created within inventory receipt interval? If so, we may be processing an older inventory
			if time.Since(subnet.Created) < cwutil.InventoryReceiptInterval {
				continue
			}

			status := cdbm.SubnetStatusError
			statusMessage := "Subnet is missing on Site"

			// Leave orderBy as nil as the result is sorted by created timestamp by default
			if status == subnet.Status {
				latestsd, _, serr := sdDAO.GetAllByEntityID(ctx, nil, subnet.ID.String(), nil, cdb.GetIntPtr(1), nil)
				if serr != nil {
					slogger.Error().Err(serr).Msg("failed to retrieve latest Status Detail for Subnet")
					continue
				}

				if len(latestsd) > 0 && latestsd[0].Message != nil && *latestsd[0].Message == statusMessage {
					continue
				}
			}

			// Set isMissingOnSite flag to true and update status, user can decide on deletion
			_, serr := subnetDAO.Update(ctx, nil, cdbm.SubnetUpdateInput{SubnetId: subnet.ID, IsMissingOnSite: cdb.GetBoolPtr(true)})
			if serr != nil {
				// Log error and continue
				slogger.Error().Err(serr).Msg("failed to set missing on Site flag in DB")
			}

			err = ms.updateSubnetStatusInDB(ctx, nil, subnet.ID, &status, &statusMessage)
			if err != nil {
				// Log error and continue
				slogger.Error().Err(serr).Msg("failed to update status and/or create Status Detail in DB")
			}
		}
	}

	return subnetLifecycleEvents, nil
}

// updateSubnetStatusInDB is helper function to write Subnet status updates to DB
func (ms ManageSubnet) updateSubnetStatusInDB(ctx context.Context, tx *cdb.Tx, subnetID uuid.UUID, status *string, statusMessage *string) error {
	if status != nil {
		subnetDAO := cdbm.NewSubnetDAO(ms.dbSession)

		_, err := subnetDAO.Update(ctx, tx, cdbm.SubnetUpdateInput{SubnetId: subnetID, Status: status})
		if err != nil {
			return err
		}

		statusDetailDAO := cdbm.NewStatusDetailDAO(ms.dbSession)
		_, err = statusDetailDAO.CreateFromParams(ctx, tx, subnetID.String(), *status, statusMessage)
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteSubnetFromDB is helper function to delete Subnet from DB
func (ms ManageSubnet) deleteSubnetFromDB(ctx context.Context, tx *cdb.Tx, subnet *cdbm.Subnet, logger zerolog.Logger) error {
	// Acquire an advisory lock on the parent IP block ID on which there could be contention
	// this lock is released when the transaction commits or rollsback
	err := tx.AcquireAdvisoryLock(ctx, cdb.GetAdvisoryLockIDFromString(subnet.IPv4BlockID.String()), false)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to acquire advisory lock on IP Block")
		terr := tx.Rollback()
		if terr != nil {
			logger.Error().Err(terr).Msg("failed to rollback transaction")
		}
		return err
	}
	logger.Info().Msg("acquired advisory lock on Subnet's IP Block")

	// Delete IPAM entry for this subnet
	ipamStorage := ipam.NewIpamStorage(ms.dbSession.DB, tx.GetBunTx())
	childCidr := ipam.GetCidrForIPBlock(ctx, *subnet.IPv4Prefix, subnet.PrefixLength)
	err = ipam.DeleteChildIpamEntryFromCidr(ctx, tx, ms.dbSession, ipamStorage, subnet.IPv4Block, childCidr)
	if err != nil {
		logger.Error().Err(err).Msg("failed to delete ipam record for Subnet")
		terr := tx.Rollback()
		if terr != nil {
			logger.Error().Err(terr).Msg("failed to rollback transaction")
		}
		return err
	}
	logger.Info().Msg("delete Subnet IPAM entry")

	// Soft-delete subnet
	subnetDAO := cdbm.NewSubnetDAO(ms.dbSession)

	err = subnetDAO.Delete(ctx, tx, subnet.ID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to delete Subnet from DB")
		terr := tx.Rollback()
		if terr != nil {
			logger.Error().Err(terr).Msg("failed to rollback transaction")
		}
		return err
	}

	return nil
}

// Utility function to get NICo Subent status from Controller Segment state
func getNICoSubnetStatus(controllerNetworkSegmentTenantState cwsv1.TenantState) (string, string) {
	switch controllerNetworkSegmentTenantState {
	case cwsv1.TenantState_PROVISIONING:
		return cdbm.SubnetStatusProvisioning, "Subnet is being provisioned on Site"
	case cwsv1.TenantState_READY:
		return cdbm.SubnetStatusReady, "Subnet is ready for use"
	case cwsv1.TenantState_CONFIGURING:
		return cdbm.SubnetStatusProvisioning, "Subnet is being configured on Site"
	case cwsv1.TenantState_TERMINATING:
		return cdbm.SubnetStatusDeleting, "Subnet is being deleted on Site"
	case cwsv1.TenantState_TERMINATED:
		return cdbm.SubnetStatusDeleted, "Subnet has been deleted on Site"
	case cwsv1.TenantState_FAILED:
		return cdbm.SubnetStatusError, "Subnet is in error state"
	default:
		return cdbm.SubnetStatusError, "Subnet status is unknown"
	}
}

// NewManageSubnet returns a new ManageSubnet activity
func NewManageSubnet(dbSession *cdb.Session, siteClientPool *sc.ClientPool, tc client.Client) ManageSubnet {
	return ManageSubnet{
		dbSession:      dbSession,
		siteClientPool: siteClientPool,
		tc:             tc,
	}
}

// ManageSubnetLifecycleMetrics is an activity wrapper for managing Subnet lifecycle metrics
type ManageSubnetLifecycleMetrics struct {
	dbSession            *cdb.Session
	statusTransitionTime *prometheus.GaugeVec
	siteIDNameMap        map[uuid.UUID]string
}

// RecordSubnetStatusTransitionMetrics is a Temporal activity that records duration of important status transitions for Subnets
func (mslm ManageSubnetLifecycleMetrics) RecordSubnetStatusTransitionMetrics(ctx context.Context, siteID uuid.UUID, subnetLifecycleEvents []cwm.InventoryObjectLifecycleEvent) error {
	logger := log.With().Str("Activity", "RecordSubnetStatusTransitionMetrics").Str("Site ID", siteID.String()).Logger()

	logger.Info().Msg("starting activity")

	// Cache site name to avoid repeated DB call
	siteName, ok := mslm.siteIDNameMap[siteID]
	if !ok {
		siteDAO := cdbm.NewSiteDAO(mslm.dbSession)
		site, err := siteDAO.GetByID(context.Background(), nil, siteID, nil, false)
		if err != nil {
			logger.Error().Err(err).Str("Site ID", siteID.String()).Msg("failed to retrieve Site from DB")
			return err
		}
		siteName = site.Name
		mslm.siteIDNameMap[siteID] = siteName
	}

	logger.Info().Int("EventCount", len(subnetLifecycleEvents)).Str("Site Name", siteName).Msg("processing subnet lifecycle events")

	// Get status details for each Subnet in events
	sdDAO := cdbm.NewStatusDetailDAO(mslm.dbSession)
	metricsRecorded := 0

	for _, event := range subnetLifecycleEvents {
		statusDetails, _, err := sdDAO.GetAllByEntityID(ctx, nil, event.ObjectID.String(), nil, cdb.GetIntPtr(cdbp.TotalLimit), nil)
		if err != nil {
			logger.Error().Err(err).Str("Subnet ID", event.ObjectID.String()).Msg("failed to retrieve Status Details for Subnet")
			return err
		}

		if event.Created != nil {
			// CREATE event: Measure time from earliest Pending to Ready
			// Requirements:
			// 1. Must have exactly one Ready status (ensures clean transition)
			// 2. Find the earliest Pending status to calculate duration from
			var readySD *cdbm.StatusDetail
			var pendingSD *cdbm.StatusDetail
			readyStatusCount := 0

			for i := range statusDetails {
				if statusDetails[i].Status == cdbm.SubnetStatusReady {
					readyStatusCount++
					// Early exit if multiple Ready statuses found - indicates abnormal state
					if readyStatusCount > 1 {
						break
					}
					readySD = &statusDetails[i]
				} else if statusDetails[i].Status == cdbm.SubnetStatusPending {
					// Find the earliest Pending status (statusDetails sorted by Created DESC)
					pendingSD = &statusDetails[i]
				}
			}

			// Only emit metric if we have exactly 1 Ready and at least 1 Pending
			if readySD != nil && pendingSD != nil && readyStatusCount == 1 {
				dur := readySD.Created.Sub(pendingSD.Created)
				mslm.statusTransitionTime.WithLabelValues(siteName, cwm.InventoryOperationTypeCreate, cdbm.SubnetStatusPending, cdbm.SubnetStatusReady).Set(dur.Seconds())
				metricsRecorded++
				logger.Info().
					Str("Subnet ID", event.ObjectID.String()).
					Str("Operation", "CREATE").
					Float64("Duration Seconds", dur.Seconds()).
					Msg("recorded subnet lifecycle metric")
			} else {
				logger.Debug().
					Str("Subnet ID", event.ObjectID.String()).
					Msg("skipped subnet CREATE metric")
			}
		} else if event.Deleted != nil {
			// DELETE event: Measure time from Deleting to actual deletion
			// Find the earliest Deleting status (iterate backwards since sorted DESC)
			var deletingSD *cdbm.StatusDetail
			for i := range slices.Backward(statusDetails) {
				if statusDetails[i].Status == cdbm.SubnetStatusDeleting {
					deletingSD = &statusDetails[i]
					break
				}
			}

			if deletingSD != nil {
				// Calculate duration from Deleting status to deletion time
				dur := event.Deleted.Sub(deletingSD.Created)
				mslm.statusTransitionTime.WithLabelValues(siteName, cwm.InventoryOperationTypeDelete, cdbm.SubnetStatusDeleting, cdbm.SubnetStatusDeleted).Set(dur.Seconds())
				metricsRecorded++
				logger.Info().
					Str("Subnet ID", event.ObjectID.String()).
					Str("Operation", "DELETE").
					Float64("Duration Seconds", dur.Seconds()).
					Msg("recorded subnet lifecycle metric")
			} else {
				logger.Debug().
					Str("Subnet ID", event.ObjectID.String()).
					Msg("skipped subnet DELETE metric")
			}
		}
	}

	logger.Info().Int("MetricsRecorded", metricsRecorded).Msg("completed activity")
	return nil
}

// NewManageSubnetLifecycleMetrics returns a new ManageSubnetLifecycleMetrics activity
func NewManageSubnetLifecycleMetrics(reg prometheus.Registerer, dbSession *cdb.Session) ManageSubnetLifecycleMetrics {
	lifecycleMetrics := ManageSubnetLifecycleMetrics{
		dbSession: dbSession,
		statusTransitionTime: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: cwm.MetricsNamespace,
				Name:      "subnet_operation_latency_seconds",
				Help:      "Current latency of subnet operations",
			},
			[]string{"site", "operation_type", "from_status", "to_status"}),

		siteIDNameMap: map[uuid.UUID]string{},
	}
	reg.MustRegister(lifecycleMetrics.statusTransitionTime)

	return lifecycleMetrics
}
