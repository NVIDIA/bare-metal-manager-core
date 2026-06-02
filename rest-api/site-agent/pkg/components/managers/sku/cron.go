// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sku

import (
	"context"

	"go.temporal.io/sdk/client"

	sww "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/workflow"
)

const (
	// InventoryCarbidePageSize is the number of items to be fetched from Carbide API at a time
	InventoryCarbidePageSize = 100
	// InventoryCloudPageSize is the number of items to be sent to Cloud at a time
	InventoryCloudPageSize = 25
	// InventoryDefaultSchedule is the default schedule for inventory discovery
	InventoryDefaultSchedule = "@every 3m"
)

// RegisterCron - Register Cron
func (api *API) RegisterCron() error {
	ManagerAccess.Data.EB.Log.Info().Msg("SKU: Registering Inventory Discovery Cron")

	workflowID := "inventory-sku-" + ManagerAccess.Conf.EB.Temporal.TemporalSubscribeNamespace

	cronSchedule := InventoryDefaultSchedule
	if ManagerAccess.Conf.EB.Temporal.TemporalInventorySchedule != "" {
		cronSchedule = ManagerAccess.Conf.EB.Temporal.TemporalInventorySchedule
	}

	ManagerAccess.Data.EB.Log.Info().Str("Schedule", cronSchedule).Msg("SKU: Inventory Discovery Cron Schedule")

	workflowOptions := client.StartWorkflowOptions{
		ID:           workflowID,
		TaskQueue:    ManagerAccess.Conf.EB.Temporal.TemporalSubscribeQueue,
		CronSchedule: cronSchedule,
	}

	we, err := ManagerAccess.Data.EB.Managers.Workflow.Temporal.Subscriber.ExecuteWorkflow(
		context.Background(),
		workflowOptions,
		sww.DiscoverSkuInventory,
	)
	if err != nil {
		ManagerAccess.Data.EB.Log.Error().Err(err).Msg("SKU: Error registering Inventory Discovery Cron")
		return err
	}

	ManagerAccess.Data.EB.Log.Info().Interface("Workflow ID", we.GetID()).Msg("SKU: successfully registered Inventory Discovery Cron")

	return nil
}
