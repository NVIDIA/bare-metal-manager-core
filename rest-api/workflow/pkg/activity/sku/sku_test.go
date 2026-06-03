// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sku

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"

	"github.com/NVIDIA/infra-controller-rest/workflow/internal/config"
	cwu "github.com/NVIDIA/infra-controller-rest/workflow/pkg/util"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

func TestManageSku_Reconcile_CreateUpdateDelete(t *testing.T) {
	ctx := context.Background()
	_ = config.GetTestConfig()

	dbSession := cwu.TestInitDB(t)
	defer dbSession.Close()
	cwu.TestSetupSchema(t, dbSession)

	// Build basic graph: provider, tenant, site
	ipOrg := "test-ip-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}
	ipu := cwu.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)
	ip := cwu.TestBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)
	site := cwu.TestBuildSite(t, dbSession, ip, "test-site", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, site)

	ms := NewManageSku(dbSession, cwu.TestTemporalSiteClientPool(t))

	// 1) Create: inventory contains one sku not in DB
	id1 := "sku-1"
	inv1 := &cwssaws.SkuInventory{
		Skus: []*cwssaws.Sku{{Id: id1}},
	}
	assert.NoError(t, ms.UpdateSkusInDB(ctx, site.ID, inv1))

	ssd := cdbm.NewSkuDAO(dbSession)
	skus, total, err := ssd.GetAll(ctx, nil, cdbm.SkuFilterInput{SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(100)})
	assert.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Equal(t, id1, skus[0].ID)
	if skus[0].Components == nil {
		t.Fatalf("expected SkuData to be set")
	}

	// 2) Update: same id, ensure still one record
	inv2 := &cwssaws.SkuInventory{Skus: []*cwssaws.Sku{{Id: id1}}}
	assert.NoError(t, ms.UpdateSkusInDB(ctx, site.ID, inv2))

	_, total, err = ssd.GetAll(ctx, nil, cdbm.SkuFilterInput{SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(100)})
	assert.NoError(t, err)
	assert.Equal(t, 1, total)

	// 3) Delete: send empty inventory, final page implied
	inv3 := &cwssaws.SkuInventory{Skus: []*cwssaws.Sku{}}
	assert.NoError(t, ms.UpdateSkusInDB(ctx, site.ID, inv3))

	_, total, err = ssd.GetAll(ctx, nil, cdbm.SkuFilterInput{SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(100)})
	assert.NoError(t, err)
	assert.Equal(t, 0, total)
}

func TestManageSku_InventoryStatusFailed_Skip(t *testing.T) {
	ctx := context.Background()
	_ = config.GetTestConfig()

	dbSession := cwu.TestInitDB(t)
	defer dbSession.Close()
	cwu.TestSetupSchema(t, dbSession)

	// Build site
	ipOrg := "test-ip-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}
	ipu := cwu.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)
	ip := cwu.TestBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)
	site := cwu.TestBuildSite(t, dbSession, ip, "test-site", cdbm.SiteStatusRegistered, nil, ipu)

	// Seed one SKU (ensure SiteID is set)
	_, err := dbSession.DB.NewInsert().Model(&cdbm.SKU{ID: "sku-seed", SiteID: site.ID, Components: &cdbm.SkuComponents{}}).Exec(ctx)
	assert.NoError(t, err)

	ms := NewManageSku(dbSession, cwu.TestTemporalSiteClientPool(t))

	inv := &cwssaws.SkuInventory{
		Skus:            []*cwssaws.Sku{{Id: "sku-other"}},
		InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED,
	}

	assert.NoError(t, ms.UpdateSkusInDB(ctx, site.ID, inv))

	// Ensure original remains and no changes happened
	ssd := cdbm.NewSkuDAO(dbSession)
	_, total, err := ssd.GetAll(ctx, nil, cdbm.SkuFilterInput{SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(100)})
	assert.NoError(t, err)
	assert.Equal(t, 1, total)
}

func TestManageSku_PagedDeletion(t *testing.T) {
	ctx := context.Background()
	_ = config.GetTestConfig()

	dbSession := cwu.TestInitDB(t)
	defer dbSession.Close()
	cwu.TestSetupSchema(t, dbSession)

	// Build site
	ipOrg := "test-ip-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}
	ipu := cwu.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)
	ip := cwu.TestBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)
	site := cwu.TestBuildSite(t, dbSession, ip, "test-site", cdbm.SiteStatusRegistered, nil, ipu)

	// Seed three SKUs (ensure SiteID is set)
	ssd := cdbm.NewSkuDAO(dbSession)
	seed := []string{"sku-1", "sku-2", "sku-3"}
	for _, id := range seed {
		_, err := dbSession.DB.NewInsert().Model(&cdbm.SKU{ID: id, SiteID: site.ID, Components: &cdbm.SkuComponents{}}).Exec(ctx)
		assert.NoError(t, err)
	}

	ms := NewManageSku(dbSession, cwu.TestTemporalSiteClientPool(t))

	// First page: report only first ID, no deletion should occur yet
	inv1 := &cwssaws.SkuInventory{
		Skus:            []*cwssaws.Sku{{Id: seed[0]}},
		InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
		InventoryPage:   &cwssaws.InventoryPage{CurrentPage: 1, TotalPages: 2, PageSize: 1, TotalItems: 2, ItemIds: []string{seed[0], seed[1]}},
	}
	assert.NoError(t, ms.UpdateSkusInDB(ctx, site.ID, inv1))
	_, total, err := ssd.GetAll(ctx, nil, cdbm.SkuFilterInput{SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(100)})
	assert.NoError(t, err)
	assert.Equal(t, 3, total)

	// Last page: report only second ID, third should be deleted
	inv2 := &cwssaws.SkuInventory{
		Skus:            []*cwssaws.Sku{{Id: seed[1]}},
		InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
		InventoryPage:   &cwssaws.InventoryPage{CurrentPage: 2, TotalPages: 2, PageSize: 1, TotalItems: 2, ItemIds: []string{seed[0], seed[1]}},
	}
	assert.NoError(t, ms.UpdateSkusInDB(ctx, site.ID, inv2))

	got, total, err := ssd.GetAll(ctx, nil, cdbm.SkuFilterInput{SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(100)})
	assert.NoError(t, err)
	assert.Equal(t, 2, total)
	// Remaining should be sku-1 and sku-2
	found := map[string]bool{}
	for _, sk := range got {
		found[sk.ID] = true
	}
	assert.True(t, found[seed[0]])
	assert.True(t, found[seed[1]])
	assert.False(t, found[seed[2]])
}
