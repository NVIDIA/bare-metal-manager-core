// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package vpc

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	cwm "github.com/NVIDIA/infra-controller-rest/workflow/internal/metrics"
	vpcActivity "github.com/NVIDIA/infra-controller-rest/workflow/pkg/activity/vpc"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

// UpdateVpcInventory is a workflow called by Site Agent to update VPC inventory for a Site
func UpdateVpcInventory(ctx workflow.Context, siteID string, vpcInventory *cwssaws.VPCInventory) (err error) {
	logger := log.With().Str("Workflow", "UpdateVpcInventory").Str("Site ID", siteID).Logger()

	startTime := time.Now()

	logger.Info().Msg("starting workflow")

	parsedSiteID, err := uuid.Parse(siteID)
	if err != nil {
		logger.Warn().Err(err).Msg(fmt.Sprintf("workflow triggered with invalid site ID: %s", siteID))
		return err
	}

	// RetryPolicy specifies how to automatically handle retries if an Activity fails.
	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    5 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    30 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		// Timeout options specify when to automatically timeout Activity functions.
		StartToCloseTimeout: 30 * time.Second,
		// Optionally provide a customized RetryPolicy.
		RetryPolicy: retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var vpcManager vpcActivity.ManageVpc

	// Execute UpdateVpcsInDB activity and get metrics batch
	var vpcLifecycleEvents []cwm.InventoryObjectLifecycleEvent
	err = workflow.ExecuteActivity(ctx, vpcManager.UpdateVpcsInDB, parsedSiteID, vpcInventory).Get(ctx, &vpcLifecycleEvents)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to execute activity: UpdateVpcsInDB")
	}

	// Record VPC lifecycle metrics
	var lifecycleMetricsManager vpcActivity.ManageVpcLifecycleMetrics
	serr := workflow.ExecuteActivity(ctx, lifecycleMetricsManager.RecordVpcStatusTransitionMetrics, parsedSiteID, vpcLifecycleEvents).Get(ctx, nil)
	if serr != nil {
		logger.Warn().Err(serr).Msg("failed to execute activity: RecordVpcStatusTransitionMetrics")
	}

	// Record latency for this inventory call
	var inventoryMetricsManager cwm.ManageInventoryMetrics

	serr = workflow.ExecuteActivity(ctx, inventoryMetricsManager.RecordLatency, parsedSiteID, "UpdateVpcInventory", err != nil, time.Since(startTime)).Get(ctx, nil)
	if serr != nil {
		logger.Warn().Err(serr).Msg("failed to execute activity: RecordLatency")
	}

	logger.Info().Msg("completing workflow")

	return err
}
