// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"testing"
	"time"

	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAPIVpcPeeringCreateRequest_Validate(t *testing.T) {
	vpc1ID := uuid.New().String()
	vpc2ID := uuid.New().String()
	siteID := uuid.New().String()

	tests := []struct {
		desc      string
		obj       APIVpcPeeringCreateRequest
		expectErr bool
	}{
		{
			desc: "ok when all required fields are provided",
			obj: APIVpcPeeringCreateRequest{
				Vpc1ID: vpc1ID,
				Vpc2ID: vpc2ID,
				SiteID: siteID,
			},
			expectErr: false,
		},
		{
			desc: "error when VPC1 is not a valid UUID",
			obj: APIVpcPeeringCreateRequest{
				Vpc1ID: "invalid-uuid",
				Vpc2ID: vpc2ID,
				SiteID: siteID,
			},
			expectErr: true,
		},
		{
			desc: "error when VPC1 is missing",
			obj: APIVpcPeeringCreateRequest{
				Vpc1ID: "",
				Vpc2ID: vpc2ID,
				SiteID: siteID,
			},
			expectErr: true,
		},
		{
			desc: "error when VPC2 is not a valid UUID",
			obj: APIVpcPeeringCreateRequest{
				Vpc1ID: vpc1ID,
				Vpc2ID: "invalid-uuid",
				SiteID: siteID,
			},
			expectErr: true,
		},
		{
			desc: "error when VPC2 is missing",
			obj: APIVpcPeeringCreateRequest{
				Vpc1ID: vpc1ID,
				Vpc2ID: "",
				SiteID: siteID,
			},
			expectErr: true,
		},
		{
			desc: "error when siteId is not a valid UUID",
			obj: APIVpcPeeringCreateRequest{
				Vpc1ID: vpc1ID,
				Vpc2ID: vpc2ID,
				SiteID: "not-a-uuid",
			},
			expectErr: true,
		},
		{
			desc: "error when siteId is missing",
			obj: APIVpcPeeringCreateRequest{
				Vpc1ID: vpc1ID,
				Vpc2ID: vpc2ID,
				SiteID: "",
			},
			expectErr: true,
		},
		{
			desc: "error when VPC1 and VPC2 are the same",
			obj: APIVpcPeeringCreateRequest{
				Vpc1ID: vpc1ID,
				Vpc2ID: vpc1ID,
				SiteID: siteID,
			},
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

func TestNewAPIVpcPeering(t *testing.T) {
	now := time.Now()
	dbVpcPeering := cdbm.VpcPeering{
		ID:            uuid.New(),
		Vpc1ID:        uuid.New(),
		Vpc2ID:        uuid.New(),
		SiteID:        uuid.New(),
		IsMultiTenant: true,
		Status:        cdbm.VpcPeeringStatusReady,
		Created:       now,
		Updated:       now,
	}

	api := NewAPIVpcPeering(dbVpcPeering)

	assert.Equal(t, dbVpcPeering.ID.String(), api.ID)
	assert.Equal(t, dbVpcPeering.Vpc1ID.String(), api.Vpc1ID)
	assert.Equal(t, dbVpcPeering.Vpc2ID.String(), api.Vpc2ID)
	assert.Equal(t, dbVpcPeering.SiteID.String(), api.SiteID)
	assert.Equal(t, dbVpcPeering.IsMultiTenant, api.IsMultiTenant)
	assert.Equal(t, dbVpcPeering.Status, api.Status)
	assert.Equal(t, dbVpcPeering.Created, api.Created)
	assert.Equal(t, dbVpcPeering.Updated, api.Updated)

}

func TestNewAPIVpcPeeringSummary(t *testing.T) {
	now := time.Now()
	dbVpcPeering := &cdbm.VpcPeering{
		ID:            uuid.New(),
		Vpc1ID:        uuid.New(),
		Vpc2ID:        uuid.New(),
		SiteID:        uuid.New(),
		IsMultiTenant: false,
		Status:        cdbm.VpcPeeringStatusPending,
		Created:       now,
		Updated:       now,
	}

	t.Run("ok when db model is provided", func(t *testing.T) {
		summary := NewAPIVpcPeeringSummary(dbVpcPeering)
		assert.NotNil(t, summary)
		assert.Equal(t, dbVpcPeering.ID.String(), summary.ID)
		assert.Equal(t, dbVpcPeering.Vpc1ID.String(), summary.Vpc1ID)
		assert.Equal(t, dbVpcPeering.Vpc2ID.String(), summary.Vpc2ID)
		assert.Equal(t, dbVpcPeering.Status, summary.Status)
		assert.Equal(t, dbVpcPeering.IsMultiTenant, summary.IsMultiTenant)
	})

	t.Run("returns nil when db model is nil", func(t *testing.T) {
		summary := NewAPIVpcPeeringSummary(nil)
		assert.Nil(t, summary)
	})
}
