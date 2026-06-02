// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

// DiscoverDpuExtensionServiceInventory is a workflow to discover DPU Extension Services on Site and publish to Cloud
func DiscoverDpuExtensionServiceInventory(ctx workflow.Context) error {
	logger := log.With().Str("Workflow", "DiscoverDpuExtensionServiceInventory").Logger()

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
	var inventoryManager activity.ManageDpuExtensionServiceInventory

	err := workflow.ExecuteActivity(ctx, inventoryManager.DiscoverDpuExtensionServiceInventory).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DiscoverDpuExtensionServiceInventory").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("Completing workflow")

	return nil
}

// CreateDpuExtensionService is a workflow to create a new DPU Extension Service
func CreateDpuExtensionService(ctx workflow.Context, request *cwssaws.CreateDpuExtensionServiceRequest) (*cwssaws.DpuExtensionService, error) {
	serviceID := ""
	if request.ServiceId != nil {
		serviceID = *request.ServiceId
	}

	logger := log.With().Str("Workflow", "CreateDpuExtensionService").Str("ID", serviceID).Logger()

	logger.Info().Msg("Starting workflow")

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

	// Invoke activity
	var dpuExtensionServiceManager activity.ManageDpuExtensionService

	var result cwssaws.DpuExtensionService

	err := workflow.ExecuteActivity(ctx, dpuExtensionServiceManager.CreateDpuExtensionServiceOnSite, request).Get(ctx, &result)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CreateDpuExtensionServiceOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")

	return &result, nil
}

// UpdateDpuExtensionService is a workflow to update a DPU Extension Service
func UpdateDpuExtensionService(ctx workflow.Context, request *cwssaws.UpdateDpuExtensionServiceRequest) (*cwssaws.DpuExtensionService, error) {
	logger := log.With().Str("Workflow", "UpdateDpuExtensionService").Str("ID", request.ServiceId).Logger()

	logger.Info().Msg("Starting workflow")

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

	// Invoke activity
	var dpuExtensionServiceManager activity.ManageDpuExtensionService

	var result cwssaws.DpuExtensionService
	err := workflow.ExecuteActivity(ctx, dpuExtensionServiceManager.UpdateDpuExtensionServiceOnSite, request).Get(ctx, &result)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "UpdateDpuExtensionServiceOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &result, nil
}

// DeleteDpuExtensionService is a workflow to delete a DPU Extension Service
func DeleteDpuExtensionService(ctx workflow.Context, request *cwssaws.DeleteDpuExtensionServiceRequest) error {
	logger := log.With().Str("Workflow", "DeleteDpuExtensionService").Str("ID", request.ServiceId).Logger()

	logger.Info().Msg("Starting workflow")

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

	// Invoke activity
	var dpuExtensionServiceManager activity.ManageDpuExtensionService

	err := workflow.ExecuteActivity(ctx, dpuExtensionServiceManager.DeleteDpuExtensionServiceOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteDpuExtensionServiceOnSite").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Msg("Completing workflow")

	return nil
}

// GetDpuExtensionServiceVersionsInfo is a workflow to get detailed information for various versions of a DPU Extension Service
func GetDpuExtensionServiceVersionsInfo(ctx workflow.Context, request *cwssaws.GetDpuExtensionServiceVersionsInfoRequest) (*cwssaws.DpuExtensionServiceVersionInfoList, error) {
	logger := log.With().Str("Workflow", "GetDpuExtensionServiceVersionsInfo").Str("ServiceID", request.ServiceId).Logger()

	logger.Info().Msg("Starting workflow")

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

	// Invoke activity
	var dpuExtensionServiceManager activity.ManageDpuExtensionService

	var result cwssaws.DpuExtensionServiceVersionInfoList

	err := workflow.ExecuteActivity(ctx, dpuExtensionServiceManager.GetDpuExtensionServiceVersionsInfoOnSite, request).Get(ctx, &result)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetDpuExtensionServiceVersionsInfoOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")

	return &result, nil
}
