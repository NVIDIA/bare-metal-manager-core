// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewAPITenant(t *testing.T) {
	type args struct {
		dbtn *cdbm.Tenant
	}

	tncfg := &cdbm.TenantConfig{
		EnableSSHAccess: true,
	}

	dbtn := &cdbm.Tenant{
		ID:             uuid.New(),
		Org:            "test-org",
		OrgDisplayName: cdb.GetStrPtr("Org Display name"),
		Config:         tncfg,
		Created:        time.Now(),
		Updated:        time.Now(),
	}

	tnAPITenant := APITenant{
		ID:             dbtn.ID.String(),
		Org:            dbtn.Org,
		OrgDisplayName: dbtn.OrgDisplayName,
		Capabilities:   tenantToAPITenantCapabilities(dbtn),
		Created:        dbtn.Created,
		Updated:        dbtn.Updated,
	}

	tests := []struct {
		name string
		args args
		want *APITenant
	}{
		{
			name: "test initializing API model for Tenant",
			args: args{
				dbtn: dbtn,
			},
			want: &tnAPITenant,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NewAPITenant(tt.args.dbtn))
		})
	}
}

func TestNewAPITenantSummary(t *testing.T) {
	dbtn := &cdbm.Tenant{
		ID:             uuid.New(),
		Org:            "test-org",
		OrgDisplayName: cdb.GetStrPtr("Org Display name"),
		Created:        time.Now(),
		Updated:        time.Now(),
	}

	type args struct {
		dbtn *cdbm.Tenant
	}
	tests := []struct {
		name string
		args args
		want *APITenantSummary
	}{
		{
			name: "test init API summary model for Tenant",
			args: args{
				dbtn: dbtn,
			},
			want: &APITenantSummary{
				Org:            dbtn.Org,
				OrgDisplayName: dbtn.OrgDisplayName,
				Capabilities:   tenantToAPITenantCapabilities(dbtn),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NewAPITenantSummary(tt.args.dbtn))
		})
	}
}
