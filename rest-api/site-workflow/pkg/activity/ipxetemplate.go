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

package activity

import (
	"context"
	"fmt"

	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/rs/zerolog/log"
	tClient "go.temporal.io/sdk/client"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ManageIpxeTemplateInventory is an activity wrapper for iPXE template inventory collection and publishing
type ManageIpxeTemplateInventory struct {
	config ManageInventoryConfig
}

// DiscoverIpxeTemplateInventory is an activity to collect iPXE template inventory from the Site Controller
// and publish it to the cloud Temporal queue
func (mii *ManageIpxeTemplateInventory) DiscoverIpxeTemplateInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverIpxeTemplateInventory").Logger()
	logger.Info().Msg("Starting activity")

	workflowOptions := tClient.StartWorkflowOptions{
		ID:        fmt.Sprintf("update-ipxe-template-inventory-%s", mii.config.SiteID.String()),
		TaskQueue: mii.config.TemporalPublishQueue,
	}
	workflowName := "UpdateIpxeTemplateInventory"

	coreGrpcClient := mii.config.CoreGrpcAtomicClient.GetClient()
	if coreGrpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	forgeClient := coreGrpcClient.GrpcServiceClient()

	result, err := forgeClient.ListIpxeTemplates(ctx, &cwssaws.ListIpxeTemplatesRequest{})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to retrieve iPXE templates from Site Controller")
		inventory := &cwssaws.IpxeTemplateInventory{
			InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED,
			StatusMsg:       err.Error(),
			Timestamp:       timestamppb.Now(),
		}
		if _, execErr := mii.config.TemporalPublishClient.ExecuteWorkflow(ctx, workflowOptions, workflowName, mii.config.SiteID, inventory); execErr != nil {
			logger.Error().Err(execErr).Msg("Failed to publish inventory error to Cloud")
			return execErr
		}
		return err
	}

	// Only propagate PUBLIC templates to REST (core is source of truth, one-way sync).
	var publicTemplates []*cwssaws.IpxeTemplate
	for _, t := range result.Templates {
		if t.Scope == cwssaws.IpxeTemplateScope_PUBLIC {
			publicTemplates = append(publicTemplates, t)
		}
	}

	inventory := &cwssaws.IpxeTemplateInventory{
		InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
		StatusMsg:       "Successfully retrieved from Site Controller",
		Timestamp:       timestamppb.Now(),
		Templates:       publicTemplates,
	}

	if _, err = mii.config.TemporalPublishClient.ExecuteWorkflow(ctx, workflowOptions, workflowName, mii.config.SiteID, inventory); err != nil {
		logger.Error().Err(err).Msg("Failed to publish iPXE template inventory to Cloud")
		return err
	}

	logger.Info().Msgf("Published %d public iPXE templates to Cloud (filtered from %d total)", len(publicTemplates), len(result.Templates))
	logger.Info().Msg("Completed activity")
	return nil
}

// NewManageIpxeTemplateInventory returns a ManageIpxeTemplateInventory activity
func NewManageIpxeTemplateInventory(config ManageInventoryConfig) ManageIpxeTemplateInventory {
	return ManageIpxeTemplateInventory{
		config: config,
	}
}
