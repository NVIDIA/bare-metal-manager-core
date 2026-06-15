// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operatingsystem

import (
	"fmt"
	"time"

	cwm "github.com/NVIDIA/infra-controller/rest-api/workflow/internal/metrics"
	osActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/operatingsystem"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

// UpdateOsImageInventory is a workflow called by Site Agent to update image based Operating System for a Site
func UpdateOsImageInventory(ctx workflow.Context, siteID string, osImageInventory *cwssaws.OsImageInventory) (err error) {
	logger := log.With().Str("Workflow", "UpdateOsImageInventory").Str("Site ID", siteID).Logger()

	startTime := workflow.Now(ctx)

	logger.Info().Msg("starting workflow")

	parsedSiteID, err := uuid.Parse(siteID)
	if err != nil {
		logger.Warn().Err(err).Msg(fmt.Sprintf("workflow triggered with invalid site ID: %s", siteID))
		return err
	}

	// RetryPolicy specifies how to automatically handle retries if an Activity fails.
	retryPolicy := &temporal.RetryPolicy{
		InitialInterval:    5 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    30 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		// Timeout options specify when to automatically timeout Activity functions.
		StartToCloseTimeout: 30 * time.Second,
		// Optionally provide a customized RetryPolicy.
		RetryPolicy: retryPolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var osManager osActivity.ManageOperatingSystem

	var osIDs []uuid.UUID

	err = workflow.ExecuteActivity(ctx, osManager.UpdateOsImagesInDB, parsedSiteID, osImageInventory).Get(ctx, &osIDs)
	if err != nil {
		logger.Warn().Err(err).Msg("failed execute activity: UpdateOsImagesInDB")
	} else {
		// Update the status of the corresponding Operating Systems
		for _, osID := range osIDs {
			serr := workflow.ExecuteActivity(ctx, osManager.UpdateOperatingSystemStatusInDB, osID).Get(ctx, nil)
			if serr != nil {
				// Log error but continue as we don't want to interrupt inventory processing
				logger.Warn().Err(serr).Msg("failed to execute activity: UpdateOperatingSystemStatusInDB")
			}
		}
	}

	// Record latency for this inventory call
	var inventoryMetricsManager cwm.ManageInventoryMetrics

	serr := workflow.ExecuteActivity(ctx, inventoryMetricsManager.RecordLatency, parsedSiteID, "UpdateOsImageInventory", err != nil, workflow.Now(ctx).Sub(startTime)).Get(ctx, nil)
	if serr != nil {
		logger.Warn().Err(serr).Msg("failed to execute activity: RecordLatency")
	}

	logger.Info().Msg("completing workflow")

	return err
}

// UpdateOperatingSystemInventory is a workflow called by the Site Agent to reconcile Operating Systems
// synced from nico-core into the operating_system table.
func UpdateOperatingSystemInventory(ctx workflow.Context, siteID string, inventory *cwssaws.OperatingSystemInventory) (err error) {
	logger := log.With().Str("Workflow", "UpdateOperatingSystemInventory").Str("Site ID", siteID).Logger()

	startTime := workflow.Now(ctx)

	logger.Info().Msg("Starting workflow")

	parsedSiteID, err := uuid.Parse(siteID)
	if err != nil {
		logger.Warn().Err(err).Msgf("workflow triggered with invalid site ID: %s", siteID)
		return err
	}

	retryPolicy := &temporal.RetryPolicy{
		InitialInterval:    5 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    30 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         retryPolicy,
	}
	ctx = workflow.WithActivityOptions(ctx, options)

	var osManager osActivity.ManageOperatingSystem

	var osIDs []uuid.UUID

	// TODO: Return IDs for Operating Systems that were updated/needs processing
	err = workflow.ExecuteActivity(ctx, osManager.UpdateOperatingSystemsInDB, parsedSiteID, inventory).Get(ctx, &osIDs)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to execute activity: UpdateOperatingSystemsInDB")
	} else {
		for _, osID := range osIDs {
			serr := workflow.ExecuteActivity(ctx, osManager.UpdateOperatingSystemStatusInDB, osID).Get(ctx, nil)
			if serr != nil {
				logger.Warn().Err(serr).Msg("failed to execute activity: UpdateOperatingSystemStatusInDB")
			}
		}
	}

	logger.Info().Msg("Completing workflow")

	// Record latency for this inventory call
	var inventoryMetricsManager cwm.ManageInventoryMetrics

	serr := workflow.ExecuteActivity(ctx, inventoryMetricsManager.RecordLatency, parsedSiteID, "UpdateOperatingSystemInventory", err != nil, workflow.Now(ctx).Sub(startTime)).Get(ctx, nil)
	if serr != nil {
		logger.Warn().Err(serr).Msg("Failed to execute activity: RecordLatency")
	}

	return err
}
