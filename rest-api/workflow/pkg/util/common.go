// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"context"
	"slices"
	"time"

	cwutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/google/uuid"
)

var (
	// ErrMsgSiteControllerRowNotFound is returned when an entity is not found in Site Controller
	ErrMsgSiteControllerRowNotFound = "row not found"
	// ErrMsgSiteControllerNoRowsReturned is returned when lookup for entity returns nothing in Site Controller
	ErrMsgSiteControllerNoRowsReturned = "no rows returned"
	// ErrMsgSiteControllerMarkedForDeletion is returned when an entity is marked for deletion in Site Controller
	ErrMsgSiteControllerMarkedForDeletion = "marked for deletion"
	// ErrMsgSiteControllerCouldNotFind is returned when an entity is not found in Site Controller
	ErrMsgSiteControllerCouldNotFind = "could not find"
	// ErrMsgSiteControllerDuplicateEntryFound is returned when an entity is found in Site Controller
	ErrMsgSiteControllerDuplicateEntryFound = "duplicate key value violates unique constraint"
)

func PtrsEqual[T comparable](i1 *T, i2 *T) bool {
	// They're either both nil or both non-nil
	// Otherwise, they certainly don't match.
	if (i1 == nil) != (i2 == nil) {
		return false
	}

	// We know their nil-ness is the same,
	// so if one is non-nil, then we can
	// compare the actual values being pointed
	// to by both.
	if i1 != nil && *i1 != *i2 {
		return false
	}

	return true
}

func NetworkSecurityGroupPropagationDetailsEqual(pd1, pd2 *cdbm.NetworkSecurityGroupPropagationDetails) bool {
	if (pd1 == nil) != (pd2 == nil) {
		return false
	}

	// If pd1 was nil but we made it here, then
	// both were nil, so we can return true.
	if pd1 == nil {
		return true
	}

	return pd1.Status.Number() == pd2.Status.Number() &&
		PtrsEqual(pd1.Details, pd2.Details) &&
		slices.Equal(pd1.UnpropagatedInstanceIds, pd2.UnpropagatedInstanceIds) &&
		slices.Equal(pd1.RelatedInstanceIds, pd2.RelatedInstanceIds)

}

func MachineCapabilitiesEqual(cap1 *cdbm.MachineCapability, cap2 *cdbm.MachineCapability) bool {

	return PtrsEqual(cap1.Cores, cap2.Cores) &&
		PtrsEqual(cap1.Threads, cap2.Threads) &&
		PtrsEqual(cap1.Count, cap2.Count) &&
		PtrsEqual(cap1.DeviceType, cap2.DeviceType) &&
		cap1.Name == cap2.Name &&
		cap1.Type == cap2.Type &&
		PtrsEqual(cap1.Capacity, cap2.Capacity) &&
		PtrsEqual(cap1.Frequency, cap2.Frequency) &&
		PtrsEqual(cap1.HardwareRevision, cap2.HardwareRevision) &&
		PtrsEqual(cap1.Vendor, cap2.Vendor) &&
		slices.Equal(cap1.InactiveDevices, cap2.InactiveDevices) &&
		cap1.Index == cap2.Index
}

// IsTimeWithinStaleInventoryThreshold checks if the action time is within the threshold where we could be processing an older inventory
func IsTimeWithinStaleInventoryThreshold(actionTime time.Time) bool {
	return time.Since(actionTime) < cwutil.InventoryReceiptInterval+(time.Second*10)
}

// UpdateNVLinkLogicalPartitionStatusInDB updates the NVLinkLogicalPartition status in the DB and creates a new StatusDetail
func UpdateNVLinkLogicalPartitionStatusInDB(ctx context.Context, tx *cdb.Tx, dbSession *cdb.Session, nvlinklogicalpartitionID uuid.UUID, status *cdbm.NVLinkLogicalPartitionStatus, statusMessage *string) (*cdbm.NVLinkLogicalPartition, *cdbm.StatusDetail, error) {
	var updatedNVLinkLogicalPartition *cdbm.NVLinkLogicalPartition
	var err error
	var newSSD *cdbm.StatusDetail
	if status != nil {
		nvlinklogicalpartitionDAO := cdbm.NewNVLinkLogicalPartitionDAO(dbSession)
		updatedNVLinkLogicalPartition, err = nvlinklogicalpartitionDAO.Update(
			ctx,
			tx,
			cdbm.NVLinkLogicalPartitionUpdateInput{
				NVLinkLogicalPartitionID: nvlinklogicalpartitionID,
				Status:                   status,
			},
		)
		if err != nil {
			return updatedNVLinkLogicalPartition, newSSD, err
		}

		statusDetailDAO := cdbm.NewStatusDetailDAO(dbSession)
		newSSD, err = statusDetailDAO.CreateFromParams(ctx, tx, nvlinklogicalpartitionID.String(), string(*status), statusMessage)
		if err != nil {
			return updatedNVLinkLogicalPartition, newSSD, err
		}
	}
	return updatedNVLinkLogicalPartition, newSSD, err
}
