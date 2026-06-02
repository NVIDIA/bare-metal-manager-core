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

// DiscoverExpectedMachineInventory is a workflow to fetch Expected Machine inventory on Site and publish to Cloud
func DiscoverExpectedMachineInventory(ctx workflow.Context) error {
	logger := log.With().Str("Workflow", "DiscoverExpectedMachineInventory").Logger()

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
	var inventoryManager activity.ManageExpectedMachineInventory

	err := workflow.ExecuteActivity(ctx, inventoryManager.DiscoverExpectedMachineInventory).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DiscoverExpectedMachineInventory").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("Completing workflow")

	return nil
}

// CreateExpectedMachine is a workflow to create new Expected Machines using the CreateExpectedMachineOnSite activity,
// then also creates the component in Flow via CreateExpectedMachineOnFlow.
func CreateExpectedMachine(ctx workflow.Context, request *cwssaws.ExpectedMachine) error {
	logger := log.With().Str("Workflow", "ExpectedMachine").Str("Action", "Create").Str("ID", request.GetId().GetValue()).Str("Expected MAC address", request.BmcMacAddress).Str("Serial", request.ChassisSerialNumber).Logger()

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

	var expectedMachineManager activity.ManageExpectedMachine

	// Write to Core first
	err := workflow.ExecuteActivity(ctx, expectedMachineManager.CreateExpectedMachineOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CreateExpectedMachineOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	// Then write to Flow (best-effort: log warning but don't fail the workflow)
	err = workflow.ExecuteActivity(ctx, expectedMachineManager.CreateExpectedMachineOnFlow, request).Get(ctx, nil)
	if err != nil {
		logger.Warn().Err(err).Str("Activity", "CreateExpectedMachineOnFlow").Msg("Failed to create component on Flow, Core write succeeded")
	}

	logger.Info().Msg("completing workflow")

	return nil
}

// UpdateExpectedMachine is a workflow to update Expected Machines using the UpdateExpectedMachineOnSite activity
// TODO: Add Flow PatchComponent dual-write when update/delete Flow support is implemented
func UpdateExpectedMachine(ctx workflow.Context, request *cwssaws.ExpectedMachine) error {
	logger := log.With().Str("Workflow", "ExpectedMachine").Str("Action", "Update").Str("ID", request.GetId().GetValue()).Str("Expected MAC address", request.BmcMacAddress).Str("Serial", request.ChassisSerialNumber).Logger()

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

	var expectedMachineManager activity.ManageExpectedMachine

	err := workflow.ExecuteActivity(ctx, expectedMachineManager.UpdateExpectedMachineOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "UpdateExpectedMachineOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("completing workflow")

	return nil
}

// CreateExpectedMachines is a workflow to create multiple Expected Machines using the CreateExpectedMachinesOnSite activity,
// then also creates the components in Flow via CreateExpectedMachinesOnFlow.
func CreateExpectedMachines(ctx workflow.Context, request *cwssaws.BatchExpectedMachineOperationRequest) (*cwssaws.BatchExpectedMachineOperationResponse, error) {
	logger := log.With().Str("Workflow", "ExpectedMachines").Str("Action", "Create").Int("Count", len(request.GetExpectedMachines().GetExpectedMachines())).Logger()

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
		// Longer timeout for batch operations since they process multiple machines
		StartToCloseTimeout: 5 * time.Minute,
		// Optionally provide a customized RetryPolicy.
		RetryPolicy: retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var expectedMachineManager activity.ManageExpectedMachine
	var response cwssaws.BatchExpectedMachineOperationResponse

	// Write to Core first
	err := workflow.ExecuteActivity(ctx, expectedMachineManager.CreateExpectedMachinesOnSite, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CreateExpectedMachinesOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	// Then write to Flow (best-effort: log warning but don't fail the workflow)
	err = workflow.ExecuteActivity(ctx, expectedMachineManager.CreateExpectedMachinesOnFlow, request).Get(ctx, nil)
	if err != nil {
		logger.Warn().Err(err).Str("Activity", "CreateExpectedMachinesOnFlow").Msg("Failed to create components on Flow, Core write succeeded")
	}

	logger.Info().Msg("completing workflow")

	return &response, nil
}

// UpdateExpectedMachines is a workflow to update multiple Expected Machines using the UpdateExpectedMachinesOnSite activity
func UpdateExpectedMachines(ctx workflow.Context, request *cwssaws.BatchExpectedMachineOperationRequest) (*cwssaws.BatchExpectedMachineOperationResponse, error) {
	logger := log.With().Str("Workflow", "ExpectedMachines").Str("Action", "Update").Int("Count", len(request.GetExpectedMachines().GetExpectedMachines())).Logger()

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
		// Longer timeout for batch operations since they process multiple machines
		StartToCloseTimeout: 5 * time.Minute,
		// Optionally provide a customized RetryPolicy.
		RetryPolicy: retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var expectedMachineManager activity.ManageExpectedMachine
	var response cwssaws.BatchExpectedMachineOperationResponse

	err := workflow.ExecuteActivity(ctx, expectedMachineManager.UpdateExpectedMachinesOnSite, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "UpdateExpectedMachinesOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("completing workflow")

	return &response, nil
}

// DeleteExpectedMachine is a workflow to Delete Expected Machines using the DeleteExpectedMachineOnSite activity
// TODO: Add Flow DeleteComponent dual-write when update/delete Flow support is implemented
func DeleteExpectedMachine(ctx workflow.Context, request *cwssaws.ExpectedMachineRequest) error {
	logger := log.With().Str("Workflow", "ExpectedMachine").Str("Action", "Delete").Str("ID", request.GetId().GetValue()).Str("optional MAC address", request.BmcMacAddress).Logger()

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

	var expectedMachineManager activity.ManageExpectedMachine

	err := workflow.ExecuteActivity(ctx, expectedMachineManager.DeleteExpectedMachineOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteExpectedMachineOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("completing workflow")

	return nil
}
