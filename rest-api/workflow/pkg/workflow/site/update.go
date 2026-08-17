// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	"github.com/google/uuid"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	siteActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/site"

	cwm "github.com/NVIDIA/infra-controller/rest-api/workflow/internal/metrics"
)

// UpdateSiteConfigInventory applies the Site Config inventory reported by the
// Site Agent. Today that inventory carries the Site fabric prefixes, from which
// the workflow creates the matching Site-level IP Blocks.
func UpdateSiteConfigInventory(ctx workflow.Context, siteIDStr string, buildInfo *corev1.BuildInfo) error {
	logger := log.With().Str("Workflow", "UpdateSiteConfigInventory").Str("SiteID", siteIDStr).Logger()

	startTime := workflow.Now(ctx)

	logger.Info().Msg("starting workflow")

	siteID, err := uuid.Parse(siteIDStr)
	if err != nil {
		logger.Warn().Err(err).Msg(fmt.Sprintf("workflow triggered with invalid site ID: %s", siteIDStr))
		return err
	}

	options := workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    1 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    1 * time.Minute,
			MaximumAttempts:    3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, options)

	var manageSite siteActivity.ManageSite

	err = workflow.ExecuteActivity(ctx, manageSite.UpdateSiteInDB, siteID, buildInfo).Get(ctx, nil)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to execute UpdateSiteMetadataInDB activity")
	}

	siteFabricPrefixes := buildInfo.GetRuntimeConfig().GetSiteFabricPrefixes()
	err = workflow.ExecuteActivity(ctx, manageSite.UpdateIPBlocksInDBFromFabricPrefixes, siteID, siteFabricPrefixes).Get(ctx, nil)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to execute UpdateIPBlocksInDBFromFabricPrefixes activity")
	}

	// Record latency for this inventory call
	var inventoryMetricsManager cwm.ManageInventoryMetrics

	serr := workflow.ExecuteActivity(ctx, inventoryMetricsManager.RecordLatency, siteID, "UpdateSiteConfigInventory", err != nil, workflow.Now(ctx).Sub(startTime)).Get(ctx, nil)
	if serr != nil {
		logger.Warn().Err(serr).Msg("failed to execute activity: RecordLatency")
	}

	logger.Info().Msg("completing workflow")

	// Return original error from inventory activity, if any
	return err
}
