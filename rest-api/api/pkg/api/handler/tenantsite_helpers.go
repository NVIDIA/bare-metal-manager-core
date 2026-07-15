// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"fmt"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/google/uuid"
)

// EnsureTenantSitesForInfrastructureProvider auto-creates TenantSite records
// linking the given tenant to every registered Site under the given
// InfrastructureProvider. This is used for tenants that should be able to
// operate on any site belonging to their infrastructure provider without
// first needing a compute or network allocation there -- privileged tenants
// (TargetedInstanceCreation enabled) and service accounts.
func EnsureTenantSitesForInfrastructureProvider(
	ctx context.Context,
	tx *cdb.Tx,
	dbSession *cdb.Session,
	tenant *cdbm.Tenant,
	infrastructureProviderID uuid.UUID,
	createdBy uuid.UUID,
) error {
	siteDAO := cdbm.NewSiteDAO(dbSession)
	sites, _, err := siteDAO.GetAll(
		ctx,
		tx,
		cdbm.SiteFilterInput{InfrastructureProviderIDs: []uuid.UUID{infrastructureProviderID}},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)},
		nil,
	)
	if err != nil {
		return fmt.Errorf("error retrieving sites for infrastructure provider: %w", err)
	}
	if len(sites) == 0 {
		return nil
	}

	siteIDs := make([]uuid.UUID, len(sites))
	for i, site := range sites {
		siteIDs[i] = site.ID
	}

	tsDAO := cdbm.NewTenantSiteDAO(dbSession)
	existing, _, err := tsDAO.GetAll(
		ctx,
		tx,
		cdbm.TenantSiteFilterInput{
			TenantIDs: []uuid.UUID{tenant.ID},
			SiteIDs:   siteIDs,
		},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)},
		nil,
	)
	if err != nil {
		return fmt.Errorf("error retrieving existing TenantSite entries: %w", err)
	}

	existingSiteIDs := make(map[uuid.UUID]bool, len(existing))
	for _, ts := range existing {
		existingSiteIDs[ts.SiteID] = true
	}

	for _, site := range sites {
		if existingSiteIDs[site.ID] {
			continue
		}
		_, err := tsDAO.Create(
			ctx,
			tx,
			cdbm.TenantSiteCreateInput{
				TenantID:  tenant.ID,
				TenantOrg: tenant.Org,
				SiteID:    site.ID,
				CreatedBy: createdBy,
			},
		)
		if err != nil {
			return fmt.Errorf("error creating TenantSite entry for site %s: %w", site.ID, err)
		}
	}
	return nil
}