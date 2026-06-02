// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// GetTray is a workflow to get a tray by its UUID from Flow
func GetTray(ctx workflow.Context, request *flowv1.GetComponentInfoByIDRequest) (*flowv1.GetComponentInfoResponse, error) {
	logger := log.With().Str("Workflow", "Tray").Str("Action", "Get").Logger()
	if request != nil && request.Id != nil {
		logger = log.With().Str("Workflow", "Tray").Str("Action", "Get").Str("TrayID", request.Id.Id).Logger()
	}

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

	var trayManager activity.ManageTray
	var response flowv1.GetComponentInfoResponse

	err := workflow.ExecuteActivity(ctx, trayManager.GetTray, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetTray").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("completing workflow")

	return &response, nil
}

// GetTrays is a workflow to get a list of trays from Flow with optional filters.
func GetTrays(ctx workflow.Context, request *flowv1.GetComponentsRequest) (*flowv1.GetComponentsResponse, error) {
	logger := log.With().Str("Workflow", "Tray").Str("Action", "GetAll").Logger()

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

	var trayManager activity.ManageTray
	var response flowv1.GetComponentsResponse

	err := workflow.ExecuteActivity(ctx, trayManager.GetTrays, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetTrays").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Int32("Total", response.GetTotal()).Msg("completing workflow")

	return &response, nil
}
