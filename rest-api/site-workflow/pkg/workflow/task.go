// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
)

// GetTask is a workflow to get a task by its ID
func GetTask(ctx workflow.Context, request *flowv1.GetTasksByIDsRequest) (*flowv1.GetTasksByIDsResponse, error) {
	logger := log.With().Str("Workflow", "Task").Str("Action", "GetTask").Logger()

	logger.Info().Msg("Starting workflow")

	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    1 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    10 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy:         retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var taskManager activity.ManageTask
	var response flowv1.GetTasksByIDsResponse

	err := workflow.ExecuteActivity(ctx, taskManager.GetTaskFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetTask").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Int("TaskCount", len(response.GetTasks())).Msg("Completing workflow")

	return &response, nil
}

// CancelTask is a workflow to cancel a task by its UUID via Flow.
//
// Cancel is best-effort: Flow marks the task Terminated and terminates the
// underlying Temporal workflow if one was scheduled. The returned task carries
// the post-cancel status reported by Flow.
func CancelTask(ctx workflow.Context, request *flowv1.CancelTaskRequest) (*flowv1.CancelTaskResponse, error) {
	logger := log.With().Str("Workflow", "Task").Str("Action", "CancelTask").Logger()

	logger.Info().Msg("Starting workflow")

	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    1 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    10 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy:         retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var taskManager activity.ManageTask
	var response flowv1.CancelTaskResponse

	err := workflow.ExecuteActivity(ctx, taskManager.CancelTaskOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CancelTaskOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")

	return &response, nil
}

// GetTasks is a workflow to list tasks matching the filters in the
// request (rack_id, component_id, active_only, pagination) via Flow.
func GetTasks(ctx workflow.Context, request *flowv1.ListTasksRequest) (*flowv1.ListTasksResponse, error) {
	logger := log.With().Str("Workflow", "Task").Str("Action", "GetTasks").Logger()

	logger.Info().Msg("Starting workflow")

	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    1 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    10 * time.Second,
		MaximumAttempts:    2,
	}
	options := workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy:         retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var taskManager activity.ManageTask
	var response flowv1.ListTasksResponse

	err := workflow.ExecuteActivity(ctx, taskManager.GetTasksFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetTasksFromFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().
		Int("TaskCount", len(response.GetTasks())).
		Int32("Total", response.GetTotal()).
		Msg("Completing workflow")

	return &response, nil
}
