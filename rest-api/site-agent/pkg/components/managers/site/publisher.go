// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"github.com/google/uuid"

	swa "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	sww "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/workflow"
)

// RegisterPublisher registers Site Config inventory workflow and activity with Temporal.
func (api *API) RegisterPublisher() error {
	ManagerAccess.Data.EB.Log.Info().Msg("Site: Registering Site Config inventory workflow and activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.DiscoverSiteConfigInventory)
	ManagerAccess.Data.EB.Log.Info().Msg("Site: Successfully registered DiscoverSiteConfigInventory workflow")

	siteID, err := uuid.Parse(ManagerAccess.Conf.EB.Temporal.ClusterID)
	if err != nil {
		ManagerAccess.Data.EB.Log.Error().Err(err).Msg("Site: invalid Temporal ClusterID")
		return err
	}

	inventoryManager := swa.NewManageSiteConfigInventory(swa.ManageInventoryConfig{
		SiteID:                siteID,
		CoreGrpcAtomicClient:  ManagerAccess.Data.EB.Managers.CoreGrpc.Client,
		TemporalPublishClient: ManagerAccess.Data.EB.Managers.Workflow.Temporal.Publisher,
		TemporalPublishQueue:  ManagerAccess.Conf.EB.Temporal.TemporalPublishQueue,
	})

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(inventoryManager.DiscoverSiteConfigInventory)
	ManagerAccess.Data.EB.Log.Info().Msg("Site: Successfully registered DiscoverSiteConfigInventory activity")

	return api.RegisterCron()
}
