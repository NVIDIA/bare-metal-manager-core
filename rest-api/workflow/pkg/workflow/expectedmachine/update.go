// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package expectedmachine

import (
	"fmt"
	"time"

	cwm "github.com/NVIDIA/infra-controller-rest/workflow/internal/metrics"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	expectedMachineActivity "github.com/NVIDIA/infra-controller-rest/workflow/pkg/activity/expectedmachine"
)

// UpdateExpectedMachineInventory is a workflow called by Site Agent to update ExpectedMachine inventory for a Site
func UpdateExpectedMachineInventory(ctx workflow.Context, siteID string, expectedMachineInventory *cwssaws.ExpectedMachineInventory) (err error) {
	logger := log.With().Str("Workflow", "UpdateExpectedMachineInventory").Str("Site ID", siteID).Logger()

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

	var expectedMachineManager expectedMachineActivity.ManageExpectedMachine

	err = workflow.ExecuteActivity(ctx, expectedMachineManager.UpdateExpectedMachinesInDB, parsedSiteID, expectedMachineInventory).Get(ctx, nil)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to execute activity: UpdateExpectedMachinesInDB")
		return err
	}

	logger.Info().Msg("completing workflow")

	// Record latency for this inventory call
	var inventoryMetricsManager cwm.ManageInventoryMetrics

	err = workflow.ExecuteActivity(ctx, inventoryMetricsManager.RecordLatency, parsedSiteID, "UpdateExpectedMachineInventory", err != nil, time.Since(startTime)).Get(ctx, nil)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to execute activity: RecordLatency")
	}

	return nil
}
