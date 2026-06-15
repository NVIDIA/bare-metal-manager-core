// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/ipam"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	cipam "github.com/NVIDIA/infra-controller/rest-api/ipam"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/util"
)

type siteFabricIPBlockTestResources struct {
	dbSession *cdb.Session
	user      *cdbm.User
	provider  *cdbm.InfrastructureProvider
	site      *cdbm.Site
}

func setupSiteFabricIPBlockTest(t *testing.T) siteFabricIPBlockTestResources {
	t.Helper()

	dbSession := testSiteInitDB(t)
	t.Cleanup(dbSession.Close)

	util.TestSetupSchema(t, dbSession)

	ipamStorage := cipam.NewBunStorage(dbSession.DB, nil)
	require.NoError(t, ipamStorage.ApplyDbSchema())
	require.NoError(t, ipamStorage.DeleteAllPrefixesFromAllNamespaces(context.Background()))

	ipOrg := "test-provider-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}
	user := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)
	provider := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, user)
	site := util.TestBuildSite(t, dbSession, provider, "test-site", cdbm.SiteStatusRegistered, nil, user)

	return siteFabricIPBlockTestResources{
		dbSession: dbSession,
		user:      user,
		provider:  provider,
		site:      site,
	}
}

func TestManageSite_UpdateSiteIPBlocksInDB_CreatesMissingBlocks(t *testing.T) {
	ctx := context.Background()
	resources := setupSiteFabricIPBlockTest(t)
	mst := NewManageSite(resources.dbSession, nil, nil, nil)

	err := mst.UpdateSiteIPBlocksInDB(ctx, resources.site.ID, []string{
		"10.0.1.12/16",
		"2001:db8:1::1/64",
		"10.0.0.0/16",
	})
	require.NoError(t, err)

	ipBlocks := getSiteFabricIPBlocks(t, ctx, resources)
	require.Len(t, ipBlocks, 2)

	ipBlocksByPrefix := map[string]cdbm.IPBlock{}
	for _, ipBlock := range ipBlocks {
		ipBlocksByPrefix[ipam.GetCidrForIPBlock(ctx, ipBlock.Prefix, ipBlock.PrefixLength)] = ipBlock
	}

	assertSiteFabricIPBlock(t, ipBlocksByPrefix["10.0.0.0/16"], "site-fabric-ipv4-10-0-0-0-16", cdbm.IPBlockProtocolVersionV4)
	assertSiteFabricIPBlock(t, ipBlocksByPrefix["2001:db8:1::/64"], "site-fabric-ipv6-20010db8000100000000000000000000-64", cdbm.IPBlockProtocolVersionV6)

	namespace := ipam.GetIpamNamespaceForIPBlock(ctx, cdbm.IPBlockRoutingTypeDatacenterOnly, resources.provider.ID.String(), resources.site.ID.String())
	ipamStorage := ipam.NewIpamStorage(resources.dbSession.DB, nil)
	for cidr := range ipBlocksByPrefix {
		_, err = ipamStorage.ReadPrefix(ctx, cidr, namespace)
		require.NoError(t, err)
	}

	statusDetailDAO := cdbm.NewStatusDetailDAO(resources.dbSession)
	for _, ipBlock := range ipBlocks {
		statusDetails, total, err := statusDetailDAO.GetAllByEntityID(ctx, nil, ipBlock.ID.String(), nil, nil, nil)
		require.NoError(t, err)
		require.Equal(t, 1, total)
		require.Len(t, statusDetails, 1)
		assert.Equal(t, cdbm.IPBlockStatusReady, statusDetails[0].Status)
		require.NotNil(t, statusDetails[0].Message)
		assert.Equal(t, siteFabricIPBlockReadyMsg, *statusDetails[0].Message)
	}
}

func TestManageSite_UpdateSiteIPBlocksInDB_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	resources := setupSiteFabricIPBlockTest(t)
	mst := NewManageSite(resources.dbSession, nil, nil, nil)

	prefixes := []string{"10.42.0.0/16", "2001:db8:42::/64"}
	require.NoError(t, mst.UpdateSiteIPBlocksInDB(ctx, resources.site.ID, prefixes))
	require.NoError(t, mst.UpdateSiteIPBlocksInDB(ctx, resources.site.ID, prefixes))

	ipBlocks := getSiteFabricIPBlocks(t, ctx, resources)
	require.Len(t, ipBlocks, 2)

	statusDetailDAO := cdbm.NewStatusDetailDAO(resources.dbSession)
	for _, ipBlock := range ipBlocks {
		_, total, err := statusDetailDAO.GetAllByEntityID(ctx, nil, ipBlock.ID.String(), nil, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, total)
	}
}

func TestManageSite_UpdateSiteIPBlocksInDB_LeavesExistingManualBlock(t *testing.T) {
	ctx := context.Background()
	resources := setupSiteFabricIPBlockTest(t)
	mst := NewManageSite(resources.dbSession, nil, nil, nil)

	existing := util.TestBuildBuildIPBlock(
		t,
		resources.dbSession,
		"manual-site-block",
		resources.site,
		resources.provider,
		nil,
		cdbm.IPBlockRoutingTypeDatacenterOnly,
		"172.16.0.0",
		12,
		cdbm.IPBlockProtocolVersionV4,
		false,
		cdbm.IPBlockStatusReady,
		resources.user,
	)

	require.NoError(t, mst.UpdateSiteIPBlocksInDB(ctx, resources.site.ID, []string{"172.16.0.0/12"}))

	ipBlocks := getSiteFabricIPBlocks(t, ctx, resources)
	require.Len(t, ipBlocks, 1)
	assert.Equal(t, existing.ID, ipBlocks[0].ID)
	assert.Equal(t, "manual-site-block", ipBlocks[0].Name)
}

func TestManageSite_UpdateSiteIPBlocksInDB_CreatesDatacenterOnlyBlockWhenOtherRoutingTypeExists(t *testing.T) {
	ctx := context.Background()
	resources := setupSiteFabricIPBlockTest(t)
	mst := NewManageSite(resources.dbSession, nil, nil, nil)

	existing := util.TestBuildBuildIPBlock(
		t,
		resources.dbSession,
		"public-site-block",
		resources.site,
		resources.provider,
		nil,
		cdbm.IPBlockRoutingTypePublic,
		"172.16.0.0",
		12,
		cdbm.IPBlockProtocolVersionV4,
		false,
		cdbm.IPBlockStatusReady,
		resources.user,
	)

	require.NoError(t, mst.UpdateSiteIPBlocksInDB(ctx, resources.site.ID, []string{"172.16.0.0/12"}))

	ipBlocks := getSiteFabricIPBlocks(t, ctx, resources)
	require.Len(t, ipBlocks, 2)

	ipBlocksByRoutingType := map[string]cdbm.IPBlock{}
	for _, ipBlock := range ipBlocks {
		ipBlocksByRoutingType[ipBlock.RoutingType] = ipBlock
	}

	require.Contains(t, ipBlocksByRoutingType, cdbm.IPBlockRoutingTypePublic)
	require.Contains(t, ipBlocksByRoutingType, cdbm.IPBlockRoutingTypeDatacenterOnly)
	assert.Equal(t, existing.ID, ipBlocksByRoutingType[cdbm.IPBlockRoutingTypePublic].ID)
	assertSiteFabricIPBlock(
		t,
		ipBlocksByRoutingType[cdbm.IPBlockRoutingTypeDatacenterOnly],
		"site-fabric-ipv4-172-16-0-0-12",
		cdbm.IPBlockProtocolVersionV4,
	)
}

func TestManageSite_UpdateSiteIPBlocksInDB_ReturnsErrorWhenFabricBlockLockHeld(t *testing.T) {
	ctx := context.Background()
	resources := setupSiteFabricIPBlockTest(t)
	mst := NewManageSite(resources.dbSession, nil, nil, nil)

	err := cdb.WithTx(ctx, resources.dbSession, func(tx *cdb.Tx) error {
		require.NoError(t, tx.AcquireAdvisoryLock(ctx, siteFabricIPBlocksLockID(resources.site), false))

		derr := mst.UpdateSiteIPBlocksInDB(ctx, resources.site.ID, []string{"10.0.0.0/16"})
		assert.ErrorIs(t, derr, cdb.ErrXactAdvisoryLockFailed)

		return nil
	})
	require.NoError(t, err)

	ipBlocks := getSiteFabricIPBlocks(t, ctx, resources)
	assert.Empty(t, ipBlocks)
}

func TestManageSite_UpdateSiteIPBlocksInDB_InvalidPrefixDoesNotCreateBlocks(t *testing.T) {
	ctx := context.Background()
	resources := setupSiteFabricIPBlockTest(t)
	mst := NewManageSite(resources.dbSession, nil, nil, nil)

	err := mst.UpdateSiteIPBlocksInDB(ctx, resources.site.ID, []string{"not-a-cidr"})
	require.Error(t, err)

	ipBlocks := getSiteFabricIPBlocks(t, ctx, resources)
	assert.Empty(t, ipBlocks)
}

func getSiteFabricIPBlocks(t *testing.T, ctx context.Context, resources siteFabricIPBlockTestResources) []cdbm.IPBlock {
	t.Helper()

	ipBlockDAO := cdbm.NewIPBlockDAO(resources.dbSession)
	ipBlocks, _, err := ipBlockDAO.GetAll(
		ctx,
		nil,
		cdbm.IPBlockFilterInput{
			SiteIDs:                   []uuid.UUID{resources.site.ID},
			InfrastructureProviderIDs: []uuid.UUID{resources.provider.ID},
			ExcludeDerived:            true,
		},
		cdbp.PageInput{},
		nil,
	)
	require.NoError(t, err)

	return ipBlocks
}

func assertSiteFabricIPBlock(t *testing.T, ipBlock cdbm.IPBlock, name string, protocolVersion string) {
	t.Helper()

	assert.Equal(t, name, ipBlock.Name)
	require.NotNil(t, ipBlock.Description)
	assert.Equal(t, siteFabricIPBlockDescription, *ipBlock.Description)
	assert.Equal(t, cdbm.IPBlockRoutingTypeDatacenterOnly, ipBlock.RoutingType)
	assert.Equal(t, protocolVersion, ipBlock.ProtocolVersion)
	assert.Equal(t, cdbm.IPBlockStatusReady, ipBlock.Status)
	assert.False(t, ipBlock.FullGrant)
	assert.Nil(t, ipBlock.TenantID)
}
