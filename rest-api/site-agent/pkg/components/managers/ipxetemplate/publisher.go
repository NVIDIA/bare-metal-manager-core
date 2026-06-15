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
	"fmt"

	"github.com/google/uuid"

	swa "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	sww "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/workflow"
)

// RegisterPublisher registers the IpxeTemplate workflows and activities with the Temporal worker
func (api *API) RegisterPublisher() error {
	ManagerAccess.Data.EB.Log.Info().Msg("IpxeTemplate: Registering the publishers")

	// Register the DiscoverIpxeTemplateInventory workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.DiscoverIpxeTemplateInventory)
	ManagerAccess.Data.EB.Log.Info().Msg("IpxeTemplate: successfully registered the DiscoverIpxeTemplateInventory workflow")

	// Register the DiscoverIpxeTemplateInventory activity
	siteID, err := uuid.Parse(ManagerAccess.Conf.EB.Temporal.ClusterID)
	if err != nil {
		return fmt.Errorf("IpxeTemplate: invalid ClusterID %q: %w", ManagerAccess.Conf.EB.Temporal.ClusterID, err)
	}
	inventoryManager := swa.NewManageIpxeTemplateInventory(swa.ManageInventoryConfig{
		SiteID:                siteID,
		CoreGrpcAtomicClient:  ManagerAccess.Data.EB.Managers.CoreGrpc.Client,
		TemporalPublishClient: ManagerAccess.Data.EB.Managers.Workflow.Temporal.Publisher,
		TemporalPublishQueue:  ManagerAccess.Conf.EB.Temporal.TemporalPublishQueue,
	})
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(inventoryManager.DiscoverIpxeTemplateInventory)
	ManagerAccess.Data.EB.Log.Info().Msg("IpxeTemplate: successfully registered the DiscoverIpxeTemplateInventory activity")

	_ = api.RegisterCron()

	return nil
}
