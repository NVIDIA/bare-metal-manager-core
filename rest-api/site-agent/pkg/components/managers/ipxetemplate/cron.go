/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ipxetemplate

import (
	"context"

	"go.temporal.io/sdk/client"

	sww "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/workflow"
)

const (
	// InventoryDefaultSchedule is the default schedule for iPXE template inventory discovery
	InventoryDefaultSchedule = "@every 3m"
)

// RegisterCron schedules the periodic DiscoverIpxeTemplateInventory workflow
func (api *API) RegisterCron() error {
	ManagerAccess.Data.EB.Log.Info().Msg("IpxeTemplate: Registering Inventory Discovery Cron")

	workflowID := "inventory-ipxetemplate-" + ManagerAccess.Conf.EB.Temporal.TemporalSubscribeNamespace

	cronSchedule := InventoryDefaultSchedule
	if ManagerAccess.Conf.EB.Temporal.TemporalInventorySchedule != "" {
		cronSchedule = ManagerAccess.Conf.EB.Temporal.TemporalInventorySchedule
	}

	ManagerAccess.Data.EB.Log.Info().Str("Schedule", cronSchedule).Msg("IpxeTemplate: Inventory Discovery Cron Schedule")

	workflowOptions := client.StartWorkflowOptions{
		ID:           workflowID,
		TaskQueue:    ManagerAccess.Conf.EB.Temporal.TemporalSubscribeQueue,
		CronSchedule: cronSchedule,
	}

	we, err := ManagerAccess.Data.EB.Managers.Workflow.Temporal.Subscriber.ExecuteWorkflow(
		context.Background(),
		workflowOptions,
		sww.DiscoverIpxeTemplateInventory,
	)
	if err != nil {
		ManagerAccess.Data.EB.Log.Error().Err(err).Msg("IpxeTemplate: Error registering Inventory Discovery Cron")
		return err
	}

	ManagerAccess.Data.EB.Log.Info().Interface("Workflow ID", we.GetID()).Msg("IpxeTemplate: successfully registered Inventory Discovery Cron")

	return nil
}
