// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestEnsureTenantSitesForInfrastructureProvider(t *testing.T) {
	ctx := context.Background()

	dbSession := common.TestInitDB(t)
	defer dbSession.Close()

	common.TestSetupSchema(t, dbSession)

	org := "test-org-ensure-sites"
	user := common.TestBuildUser(t, dbSession, uuid.NewString(), org, []string{authz.ProviderAdminRole, authz.TenantAdminRole})
	ip := common.TestBuildInfrastructureProvider(t, dbSession, "test-provider-ensure-sites", org, user)
	tn := common.TestBuildTenant(t, dbSession, "test-tenant-ensure-sites", org, user)

	site1 := common.TestBuildSite(t, dbSession, ip, "site-1", user)
	site2 := common.TestBuildSite(t, dbSession, ip, "site-2", user)

	tsDAO := cdbm.NewTenantSiteDAO(dbSession)

	// Sanity check: no TenantSite records exist yet.
	_, count, err := tsDAO.GetAll(ctx, nil, cdbm.TenantSiteFilterInput{TenantIDs: []uuid.UUID{tn.ID}}, cdbp.PageInput{}, nil)
	require.NoError(t, err)
	require.Equal(t, 0, count)

	// First call should create one TenantSite record per site.
	err = cdb.WithTx(ctx, dbSession, func(tx *cdb.Tx) error {
		return EnsureTenantSitesForInfrastructureProvider(ctx, tx, dbSession, tn, ip.ID, user.ID)
	})
	require.NoError(t, err)

	sites, count, err := tsDAO.GetAll(ctx, nil, cdbm.TenantSiteFilterInput{TenantIDs: []uuid.UUID{tn.ID}}, cdbp.PageInput{}, nil)
	require.NoError(t, err)
	require.Equal(t, 2, count)

	siteIDs := map[uuid.UUID]bool{}
	for _, s := range sites {
		siteIDs[s.SiteID] = true
	}
	require.True(t, siteIDs[site1.ID])
	require.True(t, siteIDs[site2.ID])

	// Calling it again should be idempotent -- no duplicate TenantSite rows.
	err = cdb.WithTx(ctx, dbSession, func(tx *cdb.Tx) error {
		return EnsureTenantSitesForInfrastructureProvider(ctx, tx, dbSession, tn, ip.ID, user.ID)
	})
	require.NoError(t, err)

	_, count, err = tsDAO.GetAll(ctx, nil, cdbm.TenantSiteFilterInput{TenantIDs: []uuid.UUID{tn.ID}}, cdbp.PageInput{}, nil)
	require.NoError(t, err)
	require.Equal(t, 2, count, "second call should not create duplicate TenantSite records")
}