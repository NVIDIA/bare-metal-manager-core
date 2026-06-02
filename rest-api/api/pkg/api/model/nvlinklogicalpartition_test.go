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

func TestAPINVLinkLogicalPartitionCreateRequest_Validate(t *testing.T) {
	tests := []struct {
		desc      string
		obj       APINVLinkLogicalPartitionCreateRequest
		expectErr bool
	}{
		{
			desc:      "ok when only required fields are provided",
			obj:       APINVLinkLogicalPartitionCreateRequest{Name: "test", SiteID: uuid.New().String()},
			expectErr: false,
		},
		{
			desc:      "ok when all fields are provided",
			obj:       APINVLinkLogicalPartitionCreateRequest{Name: "test", Description: cdb.GetStrPtr("test"), SiteID: uuid.New().String()},
			expectErr: false,
		},
		{
			desc:      "error when required fields are not provided",
			obj:       APINVLinkLogicalPartitionCreateRequest{Name: "test"},
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

func TestAPINVLinkLogicalPartitionUpdateRequest_Validate(t *testing.T) {
	tests := []struct {
		desc      string
		obj       APINVLinkLogicalPartitionUpdateRequest
		expectErr bool
	}{
		{
			desc:      "ok when only some fields are provided",
			obj:       APINVLinkLogicalPartitionUpdateRequest{Name: cdb.GetStrPtr("updatedname")},
			expectErr: false,
		},
		{
			desc:      "ok when all fields are provided",
			obj:       APINVLinkLogicalPartitionUpdateRequest{Name: cdb.GetStrPtr("updatedname"), Description: cdb.GetStrPtr("updated")},
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

func TestAPINVLinkLogicalPartitionNew(t *testing.T) {
	dbVpcs := []cdbm.Vpc{
		{
			ID:          uuid.New(),
			Name:        "test-vpc",
			Description: cdb.GetStrPtr("test"),
			SiteID:      uuid.New(),
			TenantID:    uuid.New(),
		},
	}

	dbNLPInterfaces := []cdbm.NVLinkInterface{
		{
			ID:                       uuid.New(),
			NVLinkLogicalPartitionID: uuid.New(),
			InstanceID:               uuid.New(),
			DeviceInstance:           0,
			Status:                   cdbm.NVLinkInterfaceStatusPending,
			Created:                  cdb.GetCurTime(),
			Updated:                  cdb.GetCurTime(),
		},
	}

	dbNLP := &cdbm.NVLinkLogicalPartition{
		ID:          uuid.New(),
		Name:        "test-nvl-partition",
		Description: cdb.GetStrPtr("test"),
		SiteID:      uuid.New(),
		TenantID:    uuid.New(),
		Status:      cdbm.NVLinkLogicalPartitionStatusPending,
		Created:     cdb.GetCurTime(),
		Updated:     cdb.GetCurTime(),
	}
	dbsds := []cdbm.StatusDetail{
		{
			ID:       uuid.New(),
			EntityID: dbNLP.ID.String(),
			Status:   cdbm.NVLinkLogicalPartitionStatusPending,
			Created:  time.Now(),
			Updated:  time.Now(),
		},
	}
	tests := []struct {
		desc            string
		dbVpcs          []cdbm.Vpc
		dbNLPInterfaces []cdbm.NVLinkInterface
		dbNLP           *cdbm.NVLinkLogicalPartition
		dbSds           []cdbm.StatusDetail
	}{
		{
			desc:            "test creating API IB Partition",
			dbVpcs:          dbVpcs,
			dbNLPInterfaces: dbNLPInterfaces,
			dbNLP:           dbNLP,
			dbSds:           dbsds,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPINVLinkLogicalPartition(tc.dbNLP, tc.dbVpcs, tc.dbNLPInterfaces, tc.dbSds)
			assert.Equal(t, tc.dbNLP.ID.String(), got.ID)
			assert.Equal(t, tc.dbVpcs[0].Name, got.Vpcs[0].Name)
		})
	}
}

func TestNewAPINVLinkLogicalPartitionSummary(t *testing.T) {
	dbNLP := &cdbm.NVLinkLogicalPartition{
		ID:          uuid.New(),
		Name:        "test-nvl-partition",
		Description: cdb.GetStrPtr("test"),
		SiteID:      uuid.New(),
		TenantID:    uuid.New(),
		Status:      cdbm.InfiniBandInterfaceStatusPending,
		Created:     cdb.GetCurTime(),
		Updated:     cdb.GetCurTime(),
	}
	tests := []struct {
		desc  string
		dbObj *cdbm.NVLinkLogicalPartition
	}{
		{
			desc:  "test creating API IB Partition Summary",
			dbObj: dbNLP,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPINVLinkLogicalPartitionSummary(tc.dbObj)
			assert.Equal(t, tc.dbObj.Name, got.Name)
			assert.Equal(t, tc.dbObj.SiteID.String(), got.SiteID)
		})
	}
}
