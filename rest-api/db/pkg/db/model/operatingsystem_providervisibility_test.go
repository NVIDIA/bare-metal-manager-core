// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
)

// TestOperatingSystemSQLDAO_GetAll_ProviderVisibility exercises the ownership
// visibility switch in GetAll: provider-only, tenant-only, dual-role, and the
// tenant-admin view that surfaces provider-owned OSes only when they are
// associated with one of the tenant's accessible sites
// (ProviderOSVisibleAtSiteIDs).
func TestOperatingSystemSQLDAO_GetAll_ProviderVisibility(t *testing.T) {
	ctx := context.Background()
	dbSession := testOperatingSystemInitDB(t)
	defer dbSession.Close()
	testOperatingSystemSetupSchema(t, dbSession)

	ip := testOperatingSystemBuildInfrastructureProvider(t, dbSession, "testIP")
	tenant := testOperatingSystemBuildTenant(t, dbSession, "testTenant")
	user := testOperatingSystemBuildUser(t, dbSession, "testUser")
	siteX := TestBuildSite(t, dbSession, ip, "siteX", user)
	siteY := TestBuildSite(t, dbSession, ip, "siteY", user)

	ossd := NewOperatingSystemDAO(dbSession)
	ossaDAO := NewOperatingSystemSiteAssociationDAO(dbSession)
	dummyUUID := uuid.New()

	buildOS := func(name string, providerID, tenantID *uuid.UUID) *OperatingSystem {
		os, err := ossd.Create(ctx, nil, OperatingSystemCreateInput{
			Name:                        name,
			Description:                 cutil.GetPtr("description"),
			Org:                         "testOrg",
			InfrastructureProviderID:    providerID,
			TenantID:                    tenantID,
			ControllerOperatingSystemID: &dummyUUID,
			Version:                     cutil.GetPtr("version"),
			OsType:                      OperatingSystemTypeIPXE,
			ImageURL:                    cutil.GetPtr("iPXE"),
			IpxeScript:                  cutil.GetPtr("ipxeScript"),
			UserData:                    cutil.GetPtr("userData"),
			AllowOverride:               true,
			EnableBlockStorage:          true,
			PhoneHomeEnabled:            false,
			Status:                      OperatingSystemStatusPending,
			CreatedBy:                   user.ID,
		})
		require.NoError(t, err)
		require.NotNil(t, os)
		return os
	}

	associate := func(osID, siteID uuid.UUID) {
		ossa, err := ossaDAO.Create(ctx, nil, OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: osID,
			SiteID:            siteID,
			Status:            OperatingSystemSiteAssociationStatusSyncing,
			CreatedBy:         user.ID,
		})
		require.NoError(t, err)
		require.NotNil(t, ossa)
	}

	// Provider-owned OSes.
	provAtX := buildOS("prov-at-x", &ip.ID, nil)
	associate(provAtX.ID, siteX.ID)
	provAtY := buildOS("prov-at-y", &ip.ID, nil)
	associate(provAtY.ID, siteY.ID)
	buildOS("prov-no-site", &ip.ID, nil)

	// Tenant-owned OSes.
	buildOS("tenant-1", nil, &tenant.ID)
	buildOS("tenant-2", nil, &tenant.ID)

	tests := []struct {
		desc          string
		providerID    *uuid.UUID
		tenantIDs     []uuid.UUID
		visibleSites  *[]uuid.UUID
		expectedNames []string
	}{
		{
			desc:          "provider-only view returns all provider OSes",
			providerID:    &ip.ID,
			expectedNames: []string{"prov-at-x", "prov-at-y", "prov-no-site"},
		},
		{
			desc:          "tenant-only view returns only tenant OSes",
			tenantIDs:     []uuid.UUID{tenant.ID},
			expectedNames: []string{"tenant-1", "tenant-2"},
		},
		{
			desc:          "dual-role view returns tenant and provider OSes",
			providerID:    &ip.ID,
			tenantIDs:     []uuid.UUID{tenant.ID},
			expectedNames: []string{"prov-at-x", "prov-at-y", "prov-no-site", "tenant-1", "tenant-2"},
		},
		{
			desc:          "tenant-admin view surfaces provider OS at accessible site",
			providerID:    &ip.ID,
			tenantIDs:     []uuid.UUID{tenant.ID},
			visibleSites:  &[]uuid.UUID{siteX.ID},
			expectedNames: []string{"prov-at-x", "tenant-1", "tenant-2"},
		},
		{
			desc:          "tenant-admin view surfaces provider OSes across multiple accessible sites",
			providerID:    &ip.ID,
			tenantIDs:     []uuid.UUID{tenant.ID},
			visibleSites:  &[]uuid.UUID{siteX.ID, siteY.ID},
			expectedNames: []string{"prov-at-x", "prov-at-y", "tenant-1", "tenant-2"},
		},
		{
			desc:          "tenant-admin view with empty accessible sites hides provider OSes",
			providerID:    &ip.ID,
			tenantIDs:     []uuid.UUID{tenant.ID},
			visibleSites:  &[]uuid.UUID{},
			expectedNames: []string{"tenant-1", "tenant-2"},
		},
		{
			desc:          "tenant-admin view excludes provider OS not associated with accessible site",
			providerID:    &ip.ID,
			tenantIDs:     []uuid.UUID{tenant.ID},
			visibleSites:  &[]uuid.UUID{siteY.ID},
			expectedNames: []string{"prov-at-y", "tenant-1", "tenant-2"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			filter := OperatingSystemFilterInput{
				InfrastructureProviderID:   tc.providerID,
				TenantIDs:                  tc.tenantIDs,
				ProviderOSVisibleAtSiteIDs: tc.visibleSites,
			}
			page := paginator.PageInput{Limit: cutil.GetPtr(paginator.TotalLimit)}
			got, total, err := ossd.GetAll(ctx, nil, filter, page, nil)
			require.NoError(t, err)
			gotNames := make([]string, len(got))
			for i, os := range got {
				gotNames[i] = os.Name
			}
			assert.ElementsMatch(t, tc.expectedNames, gotNames)
			assert.Equal(t, len(tc.expectedNames), total)
		})
	}
}
