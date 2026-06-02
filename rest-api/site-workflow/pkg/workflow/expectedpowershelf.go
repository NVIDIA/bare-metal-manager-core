// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// DiscoverExpectedPowerShelfInventory is a workflow to fetch Expected Power Shelf inventory on Site and publish to Cloud
func DiscoverExpectedPowerShelfInventory(ctx workflow.Context) error {
	logger := log.With().Str("Workflow", "DiscoverExpectedPowerShelfInventory").Logger()

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
	var inventoryManager activity.ManageExpectedPowerShelfInventory

	err := workflow.ExecuteActivity(ctx, inventoryManager.DiscoverExpectedPowerShelfInventory).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DiscoverExpectedPowerShelfInventory").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("Completing workflow")

	return nil
}

// CreateExpectedPowerShelf is a workflow to create a new Expected Power Shelf using the CreateExpectedPowerShelfOnSite activity,
// then also creates the component in Flow via CreateExpectedPowerShelfOnFlow.
func CreateExpectedPowerShelf(ctx workflow.Context, request *cwssaws.ExpectedPowerShelf) error {
	logger := log.With().Str("Workflow", "ExpectedPowerShelf").Str("Action", "Create").Str("ID", request.GetExpectedPowerShelfId().GetValue()).Str("Expected MAC address", request.BmcMacAddress).Str("Serial", request.ShelfSerialNumber).Logger()

	logger.Info().Msg("starting workflow")

	// RetryPolicy specifies how to automatically handle retries if an Activity fails.
	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    1 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    10 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		// Timeout options specify when to automatically timeout Activity functions.
		StartToCloseTimeout: 2 * time.Minute,
		// Optionally provide a customized RetryPolicy.
		RetryPolicy: retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var expectedPowerShelfManager activity.ManageExpectedPowerShelf

	// Write to Core first
	err := workflow.ExecuteActivity(ctx, expectedPowerShelfManager.CreateExpectedPowerShelfOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CreateExpectedPowerShelfOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	// Then write to Flow (best-effort: log warning but don't fail the workflow)
	err = workflow.ExecuteActivity(ctx, expectedPowerShelfManager.CreateExpectedPowerShelfOnFlow, request).Get(ctx, nil)
	if err != nil {
		logger.Warn().Err(err).Str("Activity", "CreateExpectedPowerShelfOnFlow").Msg("Failed to create component on Flow, Core write succeeded")
	}

	logger.Info().Msg("completing workflow")

	return nil
}

// UpdateExpectedPowerShelf is a workflow to update an Expected Power Shelf using the UpdateExpectedPowerShelfOnSite activity
// TODO: Add Flow PatchComponent dual-write when update/delete Flow support is implemented
func UpdateExpectedPowerShelf(ctx workflow.Context, request *cwssaws.ExpectedPowerShelf) error {
	logger := log.With().Str("Workflow", "ExpectedPowerShelf").Str("Action", "Update").Str("ID", request.GetExpectedPowerShelfId().GetValue()).Str("Expected MAC address", request.BmcMacAddress).Str("Serial", request.ShelfSerialNumber).Logger()

	logger.Info().Msg("starting workflow")

	// RetryPolicy specifies how to automatically handle retries if an Activity fails.
	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    1 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    10 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		// Timeout options specify when to automatically timeout Activity functions.
		StartToCloseTimeout: 2 * time.Minute,
		// Optionally provide a customized RetryPolicy.
		RetryPolicy: retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var expectedPowerShelfManager activity.ManageExpectedPowerShelf

	err := workflow.ExecuteActivity(ctx, expectedPowerShelfManager.UpdateExpectedPowerShelfOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "UpdateExpectedPowerShelfOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("completing workflow")

	return nil
}

// DeleteExpectedPowerShelf is a workflow to Delete an Expected Power Shelf using the DeleteExpectedPowerShelfOnSite activity
// TODO: Add Flow DeleteComponent dual-write when update/delete Flow support is implemented
func DeleteExpectedPowerShelf(ctx workflow.Context, request *cwssaws.ExpectedPowerShelfRequest) error {
	logger := log.With().Str("Workflow", "ExpectedPowerShelf").Str("Action", "Delete").Str("ID", request.GetExpectedPowerShelfId().GetValue()).Str("optional MAC address", request.BmcMacAddress).Logger()

	logger.Info().Msg("starting workflow")

	// RetryPolicy specifies how to automatically handle retries if an Activity fails.
	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    1 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    10 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		// Timeout options specify when to automatically timeout Activity functions.
		StartToCloseTimeout: 2 * time.Minute,
		// Optionally provide a customized RetryPolicy.
		RetryPolicy: retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var expectedPowerShelfManager activity.ManageExpectedPowerShelf

	err := workflow.ExecuteActivity(ctx, expectedPowerShelfManager.DeleteExpectedPowerShelfOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteExpectedPowerShelfOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("completing workflow")

	return nil
}
