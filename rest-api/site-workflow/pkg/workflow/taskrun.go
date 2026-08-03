// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	flowv1 "github.com/NVIDIA/infra-controller/rest-api/proto/flow/gen/v1"
	"github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
)

// runActivityOptions returns the activity options shared by every Run
// workflow: short start-to-close, single retry, fail-fast on
// permanent errors. Mirrors ruleActivityOptions since these are equally thin
// gRPC pass-throughs to Flow.
func runActivityOptions() workflow.ActivityOptions {
	return workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    1 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    10 * time.Second,
			MaximumAttempts:    2,
		},
	}
}

// CreateTaskRun is a workflow to create a new operation run via Flow.
func CreateTaskRun(ctx workflow.Context, request *flowv1.CreateOperationRunRequest) (*flowv1.CreateOperationRunResponse, error) {
	logger := log.With().Str("Workflow", "Run").Str("Action", "Create").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, runActivityOptions())

	var runManager activity.ManageTaskRun
	var response flowv1.CreateOperationRunResponse

	err := workflow.ExecuteActivity(ctx, runManager.CreateTaskRunOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CreateTaskRunOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Str("RunID", response.GetId().GetId()).Msg("Completing workflow")
	return &response, nil
}

// GetTaskRun is a workflow to retrieve an operation run by ID via Flow.
func GetTaskRun(ctx workflow.Context, request *flowv1.GetOperationRunRequest) (*flowv1.GetOperationRunResponse, error) {
	logger := log.With().Str("Workflow", "Run").Str("Action", "Get").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, runActivityOptions())

	var runManager activity.ManageTaskRun
	var response flowv1.GetOperationRunResponse

	err := workflow.ExecuteActivity(ctx, runManager.GetTaskRunFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetTaskRunFromFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetAllTaskRuns is a workflow to list operation runs via Flow.
func GetAllTaskRuns(ctx workflow.Context, request *flowv1.ListOperationRunsRequest) (*flowv1.ListOperationRunsResponse, error) {
	logger := log.With().Str("Workflow", "Run").Str("Action", "GetAll").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, runActivityOptions())

	var runManager activity.ManageTaskRun
	var response flowv1.ListOperationRunsResponse

	err := workflow.ExecuteActivity(ctx, runManager.GetAllTaskRunsFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetAllTaskRunsFromFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().
		Int("RunCount", len(response.GetOperationRuns())).
		Int32("Total", response.GetTotal()).
		Msg("Completing workflow")
	return &response, nil
}

// GetAllTaskRunTargets is a workflow to list the rack execution targets of one
// operation run via Flow.
func GetAllTaskRunTargets(ctx workflow.Context, request *flowv1.ListOperationRunTargetsRequest) (*flowv1.ListOperationRunTargetsResponse, error) {
	logger := log.With().Str("Workflow", "Run").Str("Action", "GetTargets").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, runActivityOptions())

	var runManager activity.ManageTaskRun
	var response flowv1.ListOperationRunTargetsResponse

	err := workflow.ExecuteActivity(ctx, runManager.GetAllTaskRunTargetsFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetAllTaskRunTargetsFromFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().
		Int("TargetCount", len(response.GetTargets())).
		Int32("Total", response.GetTotal()).
		Msg("Completing workflow")
	return &response, nil
}

// PauseTaskRun is a workflow to pause a running operation run via Flow.
func PauseTaskRun(ctx workflow.Context, request *flowv1.PauseOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Workflow", "Run").Str("Action", "Pause").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, runActivityOptions())

	var runManager activity.ManageTaskRun
	var response flowv1.OperationRun

	err := workflow.ExecuteActivity(ctx, runManager.PauseTaskRunOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "PauseTaskRunOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// ResumeTaskRun is a workflow to resume an operator-paused operation run via
// Flow.
func ResumeTaskRun(ctx workflow.Context, request *flowv1.ResumeOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Workflow", "Run").Str("Action", "Resume").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, runActivityOptions())

	var runManager activity.ManageTaskRun
	var response flowv1.OperationRun

	err := workflow.ExecuteActivity(ctx, runManager.ResumeTaskRunOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "ResumeTaskRunOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// AdvanceTaskRunPhase is a workflow to open the next phase of a phase-gated
// operation run via Flow.
func AdvanceTaskRunPhase(ctx workflow.Context, request *flowv1.AdvanceOperationRunPhaseRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Workflow", "Run").Str("Action", "AdvancePhase").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, runActivityOptions())

	var runManager activity.ManageTaskRun
	var response flowv1.OperationRun

	err := workflow.ExecuteActivity(ctx, runManager.AdvanceTaskRunPhaseOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "AdvanceTaskRunPhaseOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// CancelTaskRun is a workflow to cancel an operation run and its in-flight
// targets via Flow.
func CancelTaskRun(ctx workflow.Context, request *flowv1.CancelOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Workflow", "Run").Str("Action", "Cancel").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, runActivityOptions())

	var runManager activity.ManageTaskRun
	var response flowv1.OperationRun

	err := workflow.ExecuteActivity(ctx, runManager.CancelTaskRunOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CancelTaskRunOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}
