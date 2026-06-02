// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"testing"
	"time"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAPIInfiniBandPartitionCreateRequest_Validate(t *testing.T) {
	tests := []struct {
		desc      string
		obj       APIInfiniBandPartitionCreateRequest
		expectErr bool
	}{
		{
			desc:      "ok when only required fields are provided",
			obj:       APIInfiniBandPartitionCreateRequest{Name: "test", SiteID: uuid.New().String()},
			expectErr: false,
		},
		{
			desc:      "ok when all fields are provided",
			obj:       APIInfiniBandPartitionCreateRequest{Name: "test", Description: cdb.GetStrPtr("test"), SiteID: uuid.New().String()},
			expectErr: false,
		},
		{
			desc:      "error when required fields are not provided",
			obj:       APIInfiniBandPartitionCreateRequest{Name: "test"},
			expectErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.obj.Validate()
			assert.Equal(t, tc.expectErr, err != nil)
			if err != nil {
				fmt.Println(err.Error())
			}
		})
	}
}

func TestAPIInfiniBandPartitionUpdateRequest_Validate(t *testing.T) {
	tests := []struct {
		desc      string
		obj       APIInfiniBandPartitionUpdateRequest
		expectErr bool
	}{
		{
			desc:      "ok when only some fields are provided",
			obj:       APIInfiniBandPartitionUpdateRequest{Name: cdb.GetStrPtr("updatedname")},
			expectErr: false,
		},
		{
			desc:      "ok when all fields are provided",
			obj:       APIInfiniBandPartitionUpdateRequest{Name: cdb.GetStrPtr("updatedname"), Description: cdb.GetStrPtr("updated")},
			expectErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.obj.Validate()
			assert.Equal(t, tc.expectErr, err != nil)
			if err != nil {
				fmt.Println(err.Error())
			}
		})
	}
}

func TestAPIInfiniBandPartitionNew(t *testing.T) {
	dbIBP := &cdbm.InfiniBandPartition{
		ID:          uuid.New(),
		Name:        "test-ib-partition",
		Description: cdb.GetStrPtr("test"),
		SiteID:      uuid.New(),
		TenantID:    uuid.New(),
		Status:      cdbm.InfiniBandInterfaceStatusPending,
		Created:     cdb.GetCurTime(),
		Updated:     cdb.GetCurTime(),
	}
	dbsds := []cdbm.StatusDetail{
		{
			ID:       uuid.New(),
			EntityID: dbIBP.ID.String(),
			Status:   cdbm.InfiniBandInterfaceStatusPending,
			Created:  time.Now(),
			Updated:  time.Now(),
		},
	}
	tests := []struct {
		desc  string
		dbObj *cdbm.InfiniBandPartition
		dbSds []cdbm.StatusDetail
	}{
		{
			desc:  "test creating API IB Partition",
			dbObj: dbIBP,
			dbSds: dbsds,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPIInfiniBandPartition(tc.dbObj, tc.dbSds)
			assert.Equal(t, tc.dbObj.ID.String(), got.ID)
		})
	}
}

func TestNewAPIInfiniBandPartitionSummary(t *testing.T) {
	dbIBP := &cdbm.InfiniBandPartition{
		ID:          uuid.New(),
		Name:        "test-ib-partition",
		Description: cdb.GetStrPtr("test"),
		SiteID:      uuid.New(),
		TenantID:    uuid.New(),
		Status:      cdbm.InfiniBandInterfaceStatusPending,
		Created:     cdb.GetCurTime(),
		Updated:     cdb.GetCurTime(),
	}
	tests := []struct {
		desc  string
		dbObj *cdbm.InfiniBandPartition
	}{
		{
			desc:  "test creating API IB Partition Summary",
			dbObj: dbIBP,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPIInfiniBandPartitionSummary(tc.dbObj)
			assert.Equal(t, tc.dbObj.Name, got.Name)
			assert.Equal(t, tc.dbObj.SiteID.String(), got.SiteID)
		})
	}
}
