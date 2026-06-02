// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sshkeygroup

import (
	"fmt"
	"time"

	cwm "github.com/NVIDIA/infra-controller-rest/workflow/internal/metrics"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	sshKeyGroupActivity "github.com/NVIDIA/infra-controller-rest/workflow/pkg/activity/sshkeygroup"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

// UpdateSSHKeyGroupInventory is a workflow called by Site Agent to update SSHKeyGroupinventory for a Site
func UpdateSSHKeyGroupInventory(ctx workflow.Context, siteID string, sshKeyGroupInventory *cwssaws.SSHKeyGroupInventory) (err error) {
	logger := log.With().Str("Workflow", "UpdateSSHKeyGroupInventory").Str("Site ID", siteID).Logger()

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

	var sshKeyGroupManager sshKeyGroupActivity.ManageSSHKeyGroup

	var sshKeyGroupIDStrs []string

	err = workflow.ExecuteActivity(ctx, sshKeyGroupManager.UpdateSSHKeyGroupsInDB, parsedSiteID, sshKeyGroupInventory).Get(ctx, &sshKeyGroupIDStrs)
	if err != nil {
		logger.Warn().Err(err).Msg("failed execute activity: UpdateSSHKeyGroupsInDB")
	} else {
		for _, sshKeyGroupIDStr := range sshKeyGroupIDStrs {
			serr := workflow.ExecuteActivity(ctx, sshKeyGroupManager.UpdateSSHKeyGroupStatusInDB, sshKeyGroupIDStr).Get(ctx, nil)
			if serr != nil {
				// Log error but continue as we don't want to interrupt inventory processing
				logger.Warn().Err(serr).Msg("failed to execute activity: UpdateSSHKeyGroupStatusInDB")
			}
		}
	}

	// Record latency for this inventory call
	var inventoryMetricsManager cwm.ManageInventoryMetrics

	serr := workflow.ExecuteActivity(ctx, inventoryMetricsManager.RecordLatency, parsedSiteID, "UpdateSSHKeyGroupInventory", err != nil, time.Since(startTime)).Get(ctx, nil)
	if serr != nil {
		logger.Warn().Err(serr).Msg("failed to execute activity: RecordLatency")
	}

	logger.Info().Msg("completing workflow")

	// Return original error from inventory activity, if any
	return err
}
