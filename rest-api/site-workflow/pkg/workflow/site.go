// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	temporallog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// DiscoverSiteIPBlockInventory collects Site fabric prefixes and publishes
// them to Cloud workflow for Site-level IP Block creation.
func DiscoverSiteIPBlockInventory(ctx workflow.Context) error {
	logger := temporallog.With(workflow.GetLogger(ctx), "Workflow", "DiscoverSiteIPBlockInventory")

	logger.Info("Starting workflow")

	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    2 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    10 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy:         retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var inventoryManager activity.ManageSiteIPBlockInventory

	err := workflow.ExecuteActivity(ctx, inventoryManager.DiscoverSiteIPBlockInventory).Get(ctx, nil)
	if err != nil {
		logger.Error("Failed to execute activity from workflow", "Activity", "DiscoverSiteIPBlockInventory", "Error", err)
		return err
	}

	logger.Info("Completing workflow")

	return nil
}
