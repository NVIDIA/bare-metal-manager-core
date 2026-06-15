// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"github.com/google/uuid"

	swa "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	sww "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/workflow"
)

// RegisterPublisher registers Site IP Block inventory workflow and activity with Temporal.
func (api *API) RegisterPublisher() error {
	ManagerAccess.Data.EB.Log.Info().Msg("Site: Registering IP Block inventory workflow and activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.DiscoverSiteIPBlockInventory)
	ManagerAccess.Data.EB.Log.Info().Msg("Site: Successfully registered DiscoverSiteIPBlockInventory workflow")

	inventoryManager := swa.NewManageSiteIPBlockInventory(swa.ManageInventoryConfig{
		SiteID:                uuid.MustParse(ManagerAccess.Conf.EB.Temporal.ClusterID),
		CoreGrpcAtomicClient:  ManagerAccess.Data.EB.Managers.CoreGrpc.Client,
		TemporalPublishClient: ManagerAccess.Data.EB.Managers.Workflow.Temporal.Publisher,
		TemporalPublishQueue:  ManagerAccess.Conf.EB.Temporal.TemporalPublishQueue,
	})

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(inventoryManager.DiscoverSiteIPBlockInventory)
	ManagerAccess.Data.EB.Log.Info().Msg("Site: Successfully registered DiscoverSiteIPBlockInventory activity")

	api.RegisterCron()
	return nil
}
