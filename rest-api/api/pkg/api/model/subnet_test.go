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

func TestAPISubnetCreateRequest_Validate(t *testing.T) {
	prefix7 := 7
	prefix24 := 24
	prefix32 := 32
	prefix31 := 31
	tests := []struct {
		desc      string
		obj       APISubnetCreateRequest
		expectErr bool
	}{
		{
			desc:      "error when Name is not provided",
			obj:       APISubnetCreateRequest{Description: cdb.GetStrPtr("ab"), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "error when Name is no valid string",
			obj:       APISubnetCreateRequest{Name: "a", Description: cdb.GetStrPtr("ab"), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "ok when description is empty",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr(""), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: false,
		},
		{
			desc:      "error when VpcID is not valid uuid",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: "baduuid", IPv4BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "error when IPv4Block is not valid uuid",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr("bad"), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "error when IPv6Block is specified",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: uuid.New().String(), IPv6BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "error when neither IPv6Block nor IPv6Block are specified",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: uuid.New().String(), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "error when prefixLength is not valid < min",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix7},
			expectErr: true,
		},
		{
			desc:      "error when prefixLength is not valid > max",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix31},
			expectErr: true,
		},
		{
			desc:      "ok when all fields are specified",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: false,
		},
		{
			desc:      "ok when only IPv4BlockID is specified",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: false,
		},
		{
			desc:      "error when /32 subnet is created",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix32},
			expectErr: true,
		},
		{
			desc:      "error when prefixLength is not specified",
			obj:       APISubnetCreateRequest{Name: "ab", Description: cdb.GetStrPtr("abc"), VpcID: uuid.New().String(), IPv4BlockID: cdb.GetStrPtr(uuid.New().String())},
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

func TestAPISubnetUpdateRequest_Validate(t *testing.T) {
	tests := []struct {
		desc      string
		obj       APISubnetUpdateRequest
		expectErr bool
	}{
		{
			desc:      "ok when Name is not provided",
			obj:       APISubnetUpdateRequest{Description: cdb.GetStrPtr("ab")},
			expectErr: false,
		},
		{
			desc:      "ok when Description is not provided",
			obj:       APISubnetUpdateRequest{Name: cdb.GetStrPtr("ab")},
			expectErr: false,
		},
		{
			desc:      "error when Name is provided but is empty",
			obj:       APISubnetUpdateRequest{Name: cdb.GetStrPtr(""), Description: cdb.GetStrPtr("ab")},
			expectErr: true,
		},
		{
			desc:      "error when Name is no valid string",
			obj:       APISubnetUpdateRequest{Name: cdb.GetStrPtr("a"), Description: cdb.GetStrPtr("ab")},
			expectErr: true,
		},
		{
			desc:      "ok when description is not valid with empty",
			obj:       APISubnetUpdateRequest{Name: cdb.GetStrPtr("ab"), Description: cdb.GetStrPtr("")},
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

func TestAPISubnetNew(t *testing.T) {
	ipv4Block := &cdbm.IPBlock{
		ID:                       uuid.New(),
		Name:                     "test",
		SiteID:                   uuid.New(),
		InfrastructureProviderID: uuid.New(),
		TenantID:                 cdb.GetUUIDPtr(uuid.New()),
		RoutingType:              cdbm.IPBlockRoutingTypePublic,
		Prefix:                   "192.168.0.0",
		PrefixLength:             16,
		ProtocolVersion:          "IPv4",
		Status:                   cdbm.IPBlockStatusPending,
		Created:                  cdb.GetCurTime(),
		Updated:                  cdb.GetCurTime(),
	}
	ipv6Block := &cdbm.IPBlock{
		ID:                       uuid.New(),
		Name:                     "test",
		SiteID:                   uuid.New(),
		InfrastructureProviderID: uuid.New(),
		TenantID:                 cdb.GetUUIDPtr(uuid.New()),
		RoutingType:              cdbm.IPBlockRoutingTypePublic,
		Prefix:                   "2001:aabb::",
		PrefixLength:             16,
		ProtocolVersion:          "IPv6",
		Status:                   cdbm.IPBlockStatusPending,
		Created:                  cdb.GetCurTime(),
		Updated:                  cdb.GetCurTime(),
	}
	dbObj := &cdbm.Subnet{
		ID:                         uuid.New(),
		Name:                       "test",
		Description:                cdb.GetStrPtr("test"),
		SiteID:                     uuid.New(),
		VpcID:                      uuid.New(),
		TenantID:                   uuid.New(),
		ControllerNetworkSegmentID: cdb.GetUUIDPtr(uuid.New()),
		IPv4BlockID:                &ipv4Block.ID,
		IPv4Prefix:                 &ipv4Block.Prefix,
		IPv6BlockID:                &ipv6Block.ID,
		IPv6Prefix:                 &ipv6Block.Prefix,
		Status:                     cdbm.SubnetStatusPending,
		Created:                    cdb.GetCurTime(),
		Updated:                    cdb.GetCurTime(),
	}
	dbObj1 := &cdbm.Subnet{
		ID:          uuid.New(),
		Name:        "test",
		Description: cdb.GetStrPtr("test"),
		SiteID:      uuid.New(),
		VpcID:       uuid.New(),
		TenantID:    uuid.New(),
		IPv4BlockID: &ipv4Block.ID,
		IPv4Prefix:  &ipv4Block.Prefix,
		Status:      cdbm.SubnetStatusPending,
		Created:     cdb.GetCurTime(),
		Updated:     cdb.GetCurTime(),
	}
	dbsds := []cdbm.StatusDetail{
		{
			ID:       uuid.New(),
			EntityID: dbObj.ID.String(),
			Status:   cdbm.TenantAccountStatusPending,
			Created:  time.Now(),
			Updated:  time.Now(),
		},
	}
	tests := []struct {
		desc        string
		dbObj       *cdbm.Subnet
		ipbv4Prefix *string
		ipbv6Prefix *string
		gwv4        *string
		gwv6        *string
		sdObj       []cdbm.StatusDetail
	}{
		{
			desc:        "test creating API Subnet both IPv4 and IPv6",
			dbObj:       dbObj,
			ipbv4Prefix: cdb.GetStrPtr("192.168.0.0"),
			ipbv6Prefix: cdb.GetStrPtr("2001:aabb::"),
			gwv4:        cdb.GetStrPtr("192.168.0.1"),
			gwv6:        cdb.GetStrPtr("2001:aabb::0::1"),
			sdObj:       dbsds,
		},
		{
			desc:        "test creating API Subnet only IPv4",
			dbObj:       dbObj1,
			ipbv4Prefix: cdb.GetStrPtr("192.168.0.0"),
			gwv4:        cdb.GetStrPtr("192.168.0.1"),
			sdObj:       dbsds,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPISubnet(tc.dbObj, tc.sdObj, nil)
			assert.Equal(t, tc.dbObj.ID.String(), got.ID)
			assert.NotNil(t, tc.dbObj.SiteID)
			if tc.dbObj.ControllerNetworkSegmentID != nil {
				assert.Equal(t, tc.dbObj.ControllerNetworkSegmentID.String(), *got.ControllerNetworkSegmentID)
			}
			assert.Equal(t, *tc.dbObj.Description, *got.Description)
			assert.Equal(t, *tc.dbObj.IPv4Prefix, *got.IPv4Prefix)
			if tc.dbObj.IPv6Prefix != nil {
				assert.Equal(t, *tc.dbObj.IPv6Prefix, *got.IPv6Prefix)
			}

			assert.Equal(t, tc.dbObj.PrefixLength, got.PrefixLength)
		})
	}
}
