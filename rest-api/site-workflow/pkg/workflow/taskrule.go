// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

// ruleActivityOptions returns the activity options shared by every TaskRule
// workflow: short start-to-close, single retry, fail-fast on permanent errors.
func ruleActivityOptions() workflow.ActivityOptions {
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

// CreateTaskRule is a workflow to create a new Operation Rule via Flow.
func CreateTaskRule(ctx workflow.Context, request *flowv1.CreateOperationRuleRequest) (*flowv1.CreateOperationRuleResponse, error) {
	logger := log.With().Str("Workflow", "TaskRule").Str("Action", "Create").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, ruleActivityOptions())

	var ruleManager activity.ManageTaskRule
	var response flowv1.CreateOperationRuleResponse

	err := workflow.ExecuteActivity(ctx, ruleManager.CreateTaskRuleOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CreateTaskRuleOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Str("RuleID", response.GetId().GetId()).Msg("Completing workflow")
	return &response, nil
}

// GetTaskRule is a workflow to retrieve an Operation Rule by ID via Flow.
func GetTaskRule(ctx workflow.Context, request *flowv1.GetOperationRuleRequest) (*flowv1.OperationRule, error) {
	logger := log.With().Str("Workflow", "TaskRule").Str("Action", "Get").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, ruleActivityOptions())

	var ruleManager activity.ManageTaskRule
	var response flowv1.OperationRule

	err := workflow.ExecuteActivity(ctx, ruleManager.GetTaskRuleFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetTaskRuleFromFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Str("RuleID", response.GetId().GetId()).Msg("Completing workflow")
	return &response, nil
}

// GetAllTaskRules is a workflow to list Operation Rules via Flow.
func GetAllTaskRules(ctx workflow.Context, request *flowv1.ListOperationRulesRequest) (*flowv1.ListOperationRulesResponse, error) {
	logger := log.With().Str("Workflow", "TaskRule").Str("Action", "GetAll").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, ruleActivityOptions())

	var ruleManager activity.ManageTaskRule
	var response flowv1.ListOperationRulesResponse

	err := workflow.ExecuteActivity(ctx, ruleManager.GetAllTaskRulesFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetAllTaskRulesFromFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().
		Int("RuleCount", len(response.GetRules())).
		Int32("Total", response.GetTotalCount()).
		Msg("Completing workflow")
	return &response, nil
}

// UpdateTaskRule is a workflow to update an Operation Rule via Flow.
func UpdateTaskRule(ctx workflow.Context, request *flowv1.UpdateOperationRuleRequest) error {
	logger := log.With().Str("Workflow", "TaskRule").Str("Action", "Update").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, ruleActivityOptions())

	var ruleManager activity.ManageTaskRule

	if err := workflow.ExecuteActivity(ctx, ruleManager.UpdateTaskRuleOnFlow, request).Get(ctx, nil); err != nil {
		logger.Error().Err(err).Str("Activity", "UpdateTaskRuleOnFlow").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Str("RuleID", request.GetRuleId().GetId()).Msg("Completing workflow")
	return nil
}

// DeleteTaskRule is a workflow to delete an Operation Rule by ID via Flow.
// Flow rejects deletion of rules still bound to racks or active as default
// for an operation.
func DeleteTaskRule(ctx workflow.Context, request *flowv1.DeleteOperationRuleRequest) error {
	logger := log.With().Str("Workflow", "TaskRule").Str("Action", "Delete").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, ruleActivityOptions())

	var ruleManager activity.ManageTaskRule

	if err := workflow.ExecuteActivity(ctx, ruleManager.DeleteTaskRuleOnFlow, request).Get(ctx, nil); err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteTaskRuleOnFlow").Msg("Failed to execute activity from workflow")
		return err
	}

	logger.Info().Str("RuleID", request.GetRuleId().GetId()).Msg("Completing workflow")
	return nil
}
