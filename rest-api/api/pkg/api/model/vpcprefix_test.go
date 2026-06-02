// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"testing"
	"time"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	ipam "github.com/NVIDIA/infra-controller-rest/ipam"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAPIVpcPrefixCreateRequest_Validate(t *testing.T) {
	prefix7 := VpcPrefixBlockSizeMin - 1
	prefix24 := 24
	prefix32 := 32
	prefix31 := VpcPrefixBlockSizeMax + 1
	tests := []struct {
		desc      string
		obj       APIVpcPrefixCreateRequest
		expectErr bool
	}{
		{
			desc:      "error when Name is not provided",
			obj:       APIVpcPrefixCreateRequest{VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "error when Name is no valid string",
			obj:       APIVpcPrefixCreateRequest{Name: "a", VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "ok when description is empty",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: false,
		},
		{
			desc:      "error when VpcID is not valid uuid",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: "baduuid", IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "error when IPv4Block is not valid uuid",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr("bad"), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "error when IPBlockID is not provided",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: uuid.New().String(), PrefixLength: prefix24},
			expectErr: true,
		},
		{
			desc:      "error when prefixLength is not valid < min",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix7},
			expectErr: true,
		},
		{
			desc:      "error when prefixLength is not valid > max",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix31},
			expectErr: true,
		},
		{
			desc:      "ok when all fields are specified",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: false,
		},
		{
			desc:      "ok when only IPBlockID is specified",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix24},
			expectErr: false,
		},
		{
			desc:      "error when /32 VpcPrefix is created",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: prefix32},
			expectErr: true,
		},
		{
			desc:      "error when prefixLength is not specified",
			obj:       APIVpcPrefixCreateRequest{Name: "ab", VpcID: uuid.New().String(), IPBlockID: cdb.GetStrPtr(uuid.New().String())},
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

func TestAPIVpcPrefixUpdateRequest_Validate(t *testing.T) {
	prefix24 := 24
	tests := []struct {
		desc      string
		obj       APIVpcPrefixUpdateRequest
		expectErr bool
	}{
		{
			desc:      "ok when Name is not provided",
			obj:       APIVpcPrefixUpdateRequest{IPBlockID: cdb.GetStrPtr(uuid.New().String()), PrefixLength: cdb.GetIntPtr(prefix24)},
			expectErr: true,
		},
		{
			desc:      "ok when ipbock is not provided",
			obj:       APIVpcPrefixUpdateRequest{Name: cdb.GetStrPtr("ab")},
			expectErr: false,
		},
		{
			desc:      "error when Name is provided but is empty",
			obj:       APIVpcPrefixUpdateRequest{Name: cdb.GetStrPtr("")},
			expectErr: true,
		},
		{
			desc:      "error when Name is no valid string",
			obj:       APIVpcPrefixUpdateRequest{Name: cdb.GetStrPtr("a")},
			expectErr: true,
		},
		{
			desc:      "ok when ipblock provided but not prefix length",
			obj:       APIVpcPrefixUpdateRequest{IPBlockID: cdb.GetStrPtr(uuid.New().String())},
			expectErr: true,
		},
		{
			desc:      "ok when prefix length provided but not ipblock",
			obj:       APIVpcPrefixUpdateRequest{PrefixLength: cdb.GetIntPtr(prefix24)},
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

func TestAPIVpcPrefixNew(t *testing.T) {
	ipBlock := &cdbm.IPBlock{
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
	dbObj1 := &cdbm.VpcPrefix{
		ID:           uuid.New(),
		Name:         "test",
		SiteID:       uuid.New(),
		VpcID:        uuid.New(),
		IPBlockID:    &ipBlock.ID,
		Prefix:       ipBlock.Prefix,
		PrefixLength: 24,
		Created:      cdb.GetCurTime(),
		Updated:      cdb.GetCurTime(),
	}
	dbsds := []cdbm.StatusDetail{
		{
			ID:       uuid.New(),
			EntityID: dbObj1.ID.String(),
			Status:   cdbm.VpcPrefixStatusReady,
			Created:  time.Now(),
			Updated:  time.Now(),
		},
	}
	tests := []struct {
		desc   string
		dbObj  *cdbm.VpcPrefix
		prefix *string
		sdObj  []cdbm.StatusDetail
	}{
		{
			desc:   "test creating API VpcPrefix only IPv4",
			dbObj:  dbObj1,
			prefix: cdb.GetStrPtr("192.168.0.0"),
			sdObj:  dbsds,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPIVpcPrefix(tc.dbObj, tc.sdObj, nil)
			assert.Equal(t, tc.dbObj.ID.String(), got.ID)
			assert.NotNil(t, tc.dbObj.SiteID)
			assert.NotNil(t, tc.dbObj.VpcID)
			assert.Equal(t, tc.dbObj.Prefix, *got.Prefix)
			assert.Equal(t, tc.dbObj.PrefixLength, got.PrefixLength)
			assert.Nil(t, got.UsageStats)
		})
	}
}

func TestNewAPIVpcPrefix_UsageStats(t *testing.T) {
	dbObj := &cdbm.VpcPrefix{
		ID:           uuid.New(),
		Name:         "vpc-prefix-stats",
		SiteID:       uuid.New(),
		VpcID:        uuid.New(),
		IPBlockID:    cdb.GetUUIDPtr(uuid.New()),
		Prefix:       "10.1.0.0",
		PrefixLength: 24,
		Created:      cdb.GetCurTime(),
		Updated:      cdb.GetCurTime(),
	}
	tests := []struct {
		desc  string
		usage *ipam.Usage
		want  *APIIPBlockUsageStats
	}{
		{
			desc:  "non-nil empty usage yields zero-valued UsageStats",
			usage: &ipam.Usage{},
			want: &APIIPBlockUsageStats{
				AvailablePrefixes: []string(nil),
			},
		},
		{
			desc: "partial usage copies only populated fields",
			usage: &ipam.Usage{
				AvailableIPs:      100,
				AvailablePrefixes: []string{"10.1.1.0/26"},
			},
			want: &APIIPBlockUsageStats{
				AvailableIPs:      100,
				AvailablePrefixes: []string{"10.1.1.0/26"},
			},
		},
		{
			desc: "full usage maps all fields",
			usage: &ipam.Usage{
				AvailableIPs:              50,
				AcquiredIPs:               14,
				AvailableSmallestPrefixes: 200,
				AvailablePrefixes:         []string{"10.2.0.0/26", "10.2.0.64/26"},
				AcquiredPrefixes:          8,
			},
			want: &APIIPBlockUsageStats{
				AvailableIPs:              50,
				AcquiredIPs:               14,
				AvailableSmallestPrefixes: 200,
				AvailablePrefixes:         []string{"10.2.0.0/26", "10.2.0.64/26"},
				AcquiredPrefixes:          8,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPIVpcPrefix(dbObj, nil, tc.usage)
			req := assert.New(t)
			req.NotNil(got.UsageStats)
			req.Equal(tc.want.AvailableIPs, got.UsageStats.AvailableIPs)
			req.Equal(tc.want.AcquiredIPs, got.UsageStats.AcquiredIPs)
			req.Equal(tc.want.AvailablePrefixes, got.UsageStats.AvailablePrefixes)
			req.Equal(tc.want.AvailableSmallestPrefixes, got.UsageStats.AvailableSmallestPrefixes)
			req.Equal(tc.want.AcquiredPrefixes, got.UsageStats.AcquiredPrefixes)
		})
	}
}
