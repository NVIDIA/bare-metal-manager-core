// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

// expectedRackActivityOptions returns the common ActivityOptions used by all
// ExpectedRack workflows.
func expectedRackActivityOptions() workflow.ActivityOptions {
	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    1 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    10 * time.Second,
		MaximumAttempts:    2,
	}
	return workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy:         retrypolicy,
	}
}

// DiscoverExpectedRackInventory is a workflow to fetch Expected Rack inventory on Site and publish to Cloud
func DiscoverExpectedRackInventory(ctx workflow.Context) error {
	logger := log.With().Str("Workflow", "DiscoverExpectedRackInventory").Logger()

	logger.Info().Msg("Starting workflow")

	// RetryPolicy specifies how to automatically handle retries if an Activity fails.
	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    2 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    10 * time.Second,
		// This is executed every 3 minutes, so we don't want too many retry attempts
		MaximumAttempts: 2,
	}
	options := workflow.ActivityOptions{
		// Timeout options specify when to automatically timeout Activity functions.
		StartToCloseTimeout: 2 * time.Minute,
		// Optionally provide a customized RetryPolicy.
		RetryPolicy: retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	// Invoke activity
	var inventoryManager activity.ManageExpectedRackInventory

	err := workflow.ExecuteActivity(ctx, inventoryManager.DiscoverExpectedRackInventory).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DiscoverExpectedRackInventory").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("Completing workflow")

	return nil
}

// CreateExpectedRack is a workflow to create a new Expected Rack using the
// CreateExpectedRackOnSite activity, then also creates the rack in Flow via
// CreateExpectedRackOnFlow (best-effort).
func CreateExpectedRack(ctx workflow.Context, request *cwssaws.ExpectedRack) error {
	logger := log.With().Str("Workflow", "ExpectedRack").Str("Action", "Create").Str("ID", request.GetRackId().GetId()).Str("RackProfileID", request.GetRackType()).Logger()

	logger.Info().Msg("starting workflow")

	ctx = workflow.WithActivityOptions(ctx, expectedRackActivityOptions())

	var expectedRackManager activity.ManageExpectedRack

	// Write to Core first
	err := workflow.ExecuteActivity(ctx, expectedRackManager.CreateExpectedRackOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CreateExpectedRackOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	// Then write to Flow (best-effort: log warning but don't fail the workflow)
	err = workflow.ExecuteActivity(ctx, expectedRackManager.CreateExpectedRackOnFlow, request).Get(ctx, nil)
	if err != nil {
		logger.Warn().Err(err).Str("Activity", "CreateExpectedRackOnFlow").Msg("Failed to create rack on Flow, Core write succeeded")
	}

	logger.Info().Msg("completing workflow")

	return nil
}

// UpdateExpectedRack is a workflow to update an Expected Rack using the
// UpdateExpectedRackOnSite activity.
// TODO: Add Flow PatchComponent dual-write when update/delete Flow support is implemented
func UpdateExpectedRack(ctx workflow.Context, request *cwssaws.ExpectedRack) error {
	logger := log.With().Str("Workflow", "ExpectedRack").Str("Action", "Update").Str("ID", request.GetRackId().GetId()).Str("RackProfileID", request.GetRackType()).Logger()

	logger.Info().Msg("starting workflow")

	ctx = workflow.WithActivityOptions(ctx, expectedRackActivityOptions())

	var expectedRackManager activity.ManageExpectedRack

	err := workflow.ExecuteActivity(ctx, expectedRackManager.UpdateExpectedRackOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "UpdateExpectedRackOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("completing workflow")

	return nil
}

// DeleteExpectedRack is a workflow to delete an Expected Rack using the
// DeleteExpectedRackOnSite activity.
// TODO: Add Flow PatchComponent dual-write when update/delete Flow support is implemented
func DeleteExpectedRack(ctx workflow.Context, request *cwssaws.ExpectedRackRequest) error {
	logger := log.With().Str("Workflow", "ExpectedRack").Str("Action", "Delete").Str("ID", request.GetRackId()).Logger()

	logger.Info().Msg("starting workflow")

	ctx = workflow.WithActivityOptions(ctx, expectedRackActivityOptions())

	var expectedRackManager activity.ManageExpectedRack

	err := workflow.ExecuteActivity(ctx, expectedRackManager.DeleteExpectedRackOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteExpectedRackOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("completing workflow")

	return nil
}

// ReplaceAllExpectedRacks is a workflow to replace all Expected Racks on Site
// using the ReplaceAllExpectedRacksOnSite activity.
func ReplaceAllExpectedRacks(ctx workflow.Context, request *cwssaws.ExpectedRackList) error {
	logger := log.With().Str("Workflow", "ExpectedRack").Str("Action", "ReplaceAll").Int("Count", len(request.GetExpectedRacks())).Logger()

	logger.Info().Msg("starting workflow")

	ctx = workflow.WithActivityOptions(ctx, expectedRackActivityOptions())

	var expectedRackManager activity.ManageExpectedRack

	err := workflow.ExecuteActivity(ctx, expectedRackManager.ReplaceAllExpectedRacksOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "ReplaceAllExpectedRacksOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("completing workflow")

	return nil
}

// DeleteAllExpectedRacks is a workflow to delete all Expected Racks on Site
// using the DeleteAllExpectedRacksOnSite activity.
func DeleteAllExpectedRacks(ctx workflow.Context) error {
	logger := log.With().Str("Workflow", "ExpectedRack").Str("Action", "DeleteAll").Logger()

	logger.Info().Msg("starting workflow")

	ctx = workflow.WithActivityOptions(ctx, expectedRackActivityOptions())

	var expectedRackManager activity.ManageExpectedRack

	err := workflow.ExecuteActivity(ctx, expectedRackManager.DeleteAllExpectedRacksOnSite).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteAllExpectedRacksOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("completing workflow")

	return nil
}
