// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"fmt"

	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/rs/zerolog/log"
	tClient "go.temporal.io/sdk/client"
)

const updateSiteIPBlockInventoryWorkflowName = "UpdateSiteIPBlockInventory"

// ManageSiteIPBlockInventory is an activity wrapper for Site IP Block inventory collection and publishing.
type ManageSiteIPBlockInventory struct {
	config ManageInventoryConfig
}

// NewManageSiteIPBlockInventory returns a ManageSiteIPBlockInventory implementation.
func NewManageSiteIPBlockInventory(config ManageInventoryConfig) ManageSiteIPBlockInventory {
	return ManageSiteIPBlockInventory{
		config: config,
	}
}

// DiscoverSiteIPBlockInventory collects Site fabric prefixes and publishes
// them to Cloud workflow so matching Site-level IP Blocks can be created.
func (msi *ManageSiteIPBlockInventory) DiscoverSiteIPBlockInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverSiteIPBlockInventory").Logger()
	logger.Info().Msg("Starting activity")

	grpcClient := msi.config.CoreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}

	buildInfo, err := grpcClient.GrpcServiceClient().Version(ctx, &cwssaws.VersionRequest{})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to retrieve Site runtime config using Core gRPC API")
		return err
	}

	siteFabricPrefixes := buildInfo.GetRuntimeConfig().GetSiteFabricPrefixes()
	workflowOptions := tClient.StartWorkflowOptions{
		ID:        fmt.Sprintf("update-site-ip-block-inventory-%s", msi.config.SiteID.String()),
		TaskQueue: msi.config.TemporalPublishQueue,
	}

	if _, err = msi.config.TemporalPublishClient.ExecuteWorkflow(
		ctx,
		workflowOptions,
		updateSiteIPBlockInventoryWorkflowName,
		msi.config.SiteID.String(),
		siteFabricPrefixes,
	); err != nil {
		logger.Error().Err(err).Msg("Failed to publish Site IP Block inventory to Cloud")
		return err
	}

	logger.Info().Msg("Completed activity")
	return nil
}
