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

const updateSiteConfigInventoryWorkflowName = "UpdateSiteConfigInventory"

// ManageSiteConfigInventory is an activity wrapper for Site Config inventory collection and publishing.
type ManageSiteConfigInventory struct {
	config ManageInventoryConfig
}

// NewManageSiteConfigInventory returns a ManageSiteConfigInventory implementation.
func NewManageSiteConfigInventory(config ManageInventoryConfig) ManageSiteConfigInventory {
	return ManageSiteConfigInventory{
		config: config,
	}
}

// DiscoverSiteConfigInventory collects the Site Config inventory (today the
// Site fabric prefixes) and publishes it to the Cloud workflow, which creates
// the matching Site-level IP Blocks.
func (msi *ManageSiteConfigInventory) DiscoverSiteConfigInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverSiteConfigInventory").Logger()
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

	workflowOptions := tClient.StartWorkflowOptions{
		ID:        fmt.Sprintf("update-site-config-inventory-%s", msi.config.SiteID.String()),
		TaskQueue: msi.config.TemporalPublishQueue,
	}

	if _, err = msi.config.TemporalPublishClient.ExecuteWorkflow(
		ctx,
		workflowOptions,
		updateSiteConfigInventoryWorkflowName,
		msi.config.SiteID.String(),
		buildInfo,
	); err != nil {
		logger.Error().Err(err).Msg("Failed to publish Site Config inventory to Cloud")
		return err
	}

	logger.Info().Msg("Completed activity")
	return nil
}
