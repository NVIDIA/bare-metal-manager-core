// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

// ruleActivityOptions returns the shared activity options used by every rule
// workflow. Mirrors task.go: short start-to-close, single retry to absorb
// transient Flow blips, fail-fast on permanent errors.
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

// CreateOperationRule is a workflow to create a new Operation Rule via Flow.
func CreateOperationRule(ctx workflow.Context, request *flowv1.CreateOperationRuleRequest) (*flowv1.CreateOperationRuleResponse, error) {
	logger := log.With().Str("Workflow", "Rule").Str("Action", "CreateOperationRule").Logger()
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

// GetOperationRule is a workflow to retrieve an Operation Rule by ID via Flow.
func GetOperationRule(ctx workflow.Context, request *flowv1.GetOperationRuleRequest) (*flowv1.OperationRule, error) {
	logger := log.With().Str("Workflow", "Rule").Str("Action", "GetOperationRule").Logger()
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

// ListOperationRules is a workflow to list Operation Rules matching the
// filters in the request (operation_type, operation_code, default_only) via
// Flow. Pagination and totals are computed by Flow.
func ListOperationRules(ctx workflow.Context, request *flowv1.ListOperationRulesRequest) (*flowv1.ListOperationRulesResponse, error) {
	logger := log.With().Str("Workflow", "Rule").Str("Action", "ListOperationRules").Logger()
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

// UpdateOperationRule is a workflow to update an Operation Rule via Flow.
// is_default cannot be updated via this path; use SetRuleAsDefault on Flow for
// that (not exposed in this MVP).
func UpdateOperationRule(ctx workflow.Context, request *flowv1.UpdateOperationRuleRequest) (*emptypb.Empty, error) {
	logger := log.With().Str("Workflow", "Rule").Str("Action", "UpdateOperationRule").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, ruleActivityOptions())

	var ruleManager activity.ManageTaskRule
	var response emptypb.Empty

	err := workflow.ExecuteActivity(ctx, ruleManager.UpdateTaskRuleOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "UpdateTaskRuleOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Str("RuleID", request.GetRuleId().GetId()).Msg("Completing workflow")
	return &response, nil
}

// DeleteOperationRule is a workflow to delete an Operation Rule by ID via
// Flow. Flow rejects deletion of rules that are still associated with racks or
// are the active default for an operation; the caller must dissociate first.
func DeleteOperationRule(ctx workflow.Context, request *flowv1.DeleteOperationRuleRequest) (*emptypb.Empty, error) {
	logger := log.With().Str("Workflow", "Rule").Str("Action", "DeleteOperationRule").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, ruleActivityOptions())

	var ruleManager activity.ManageTaskRule
	var response emptypb.Empty

	err := workflow.ExecuteActivity(ctx, ruleManager.DeleteTaskRuleOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteTaskRuleOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Str("RuleID", request.GetRuleId().GetId()).Msg("Completing workflow")
	return &response, nil
}
