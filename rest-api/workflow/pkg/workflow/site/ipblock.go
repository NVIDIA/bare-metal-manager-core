// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	siteActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/site"
)

// UpdateSiteIPBlockInventory creates Site-level IP Blocks from Site fabric
// prefixes reported by the Site Agent.
func UpdateSiteIPBlockInventory(ctx workflow.Context, siteIDStr string, siteFabricPrefixes []string) error {
	logger := log.With().Str("Workflow", "UpdateSiteIPBlockInventory").Str("SiteID", siteIDStr).Logger()
	logger.Info().Msg("starting workflow")

	siteID, err := uuid.Parse(siteIDStr)
	if err != nil {
		logger.Error().Err(err).Msg("invalid Site ID")
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

	err = workflow.ExecuteActivity(ctx, manageSite.UpdateSiteIPBlocksInDB, siteID, siteFabricPrefixes).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to execute UpdateSiteIPBlocksInDB activity")
		return err
	}

	logger.Info().Msg("completing workflow")
	return nil
}
