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

// campaignActivityOptions returns the activity options shared by every Campaign
// (operation-run) workflow: short start-to-close, single retry, fail-fast on
// permanent errors. Mirrors ruleActivityOptions since these are equally thin
// gRPC pass-throughs to Flow.
func campaignActivityOptions() workflow.ActivityOptions {
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

// CreateCampaign is a workflow to create a new operation run via Flow.
func CreateCampaign(ctx workflow.Context, request *flowv1.CreateOperationRunRequest) (*flowv1.CreateOperationRunResponse, error) {
	logger := log.With().Str("Workflow", "Campaign").Str("Action", "Create").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, campaignActivityOptions())

	var campaignManager activity.ManageCampaign
	var response flowv1.CreateOperationRunResponse

	err := workflow.ExecuteActivity(ctx, campaignManager.CreateCampaignOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CreateCampaignOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Str("CampaignID", response.GetId().GetId()).Msg("Completing workflow")
	return &response, nil
}

// GetCampaign is a workflow to retrieve an operation run by ID via Flow.
func GetCampaign(ctx workflow.Context, request *flowv1.GetOperationRunRequest) (*flowv1.GetOperationRunResponse, error) {
	logger := log.With().Str("Workflow", "Campaign").Str("Action", "Get").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, campaignActivityOptions())

	var campaignManager activity.ManageCampaign
	var response flowv1.GetOperationRunResponse

	err := workflow.ExecuteActivity(ctx, campaignManager.GetCampaignFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetCampaignFromFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetAllCampaigns is a workflow to list operation runs via Flow.
func GetAllCampaigns(ctx workflow.Context, request *flowv1.ListOperationRunsRequest) (*flowv1.ListOperationRunsResponse, error) {
	logger := log.With().Str("Workflow", "Campaign").Str("Action", "GetAll").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, campaignActivityOptions())

	var campaignManager activity.ManageCampaign
	var response flowv1.ListOperationRunsResponse

	err := workflow.ExecuteActivity(ctx, campaignManager.GetAllCampaignsFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetAllCampaignsFromFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().
		Int("CampaignCount", len(response.GetOperationRuns())).
		Int32("Total", response.GetTotal()).
		Msg("Completing workflow")
	return &response, nil
}

// GetCampaignTargets is a workflow to list the rack execution targets of one
// operation run via Flow.
func GetCampaignTargets(ctx workflow.Context, request *flowv1.ListOperationRunTargetsRequest) (*flowv1.ListOperationRunTargetsResponse, error) {
	logger := log.With().Str("Workflow", "Campaign").Str("Action", "GetTargets").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, campaignActivityOptions())

	var campaignManager activity.ManageCampaign
	var response flowv1.ListOperationRunTargetsResponse

	err := workflow.ExecuteActivity(ctx, campaignManager.GetCampaignTargetsFromFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "GetCampaignTargetsFromFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().
		Int("TargetCount", len(response.GetTargets())).
		Int32("Total", response.GetTotal()).
		Msg("Completing workflow")
	return &response, nil
}

// PauseCampaign is a workflow to pause a running operation run via Flow.
func PauseCampaign(ctx workflow.Context, request *flowv1.PauseOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Workflow", "Campaign").Str("Action", "Pause").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, campaignActivityOptions())

	var campaignManager activity.ManageCampaign
	var response flowv1.OperationRun

	err := workflow.ExecuteActivity(ctx, campaignManager.PauseCampaignOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "PauseCampaignOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// ResumeCampaign is a workflow to resume an operator-paused operation run via
// Flow.
func ResumeCampaign(ctx workflow.Context, request *flowv1.ResumeOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Workflow", "Campaign").Str("Action", "Resume").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, campaignActivityOptions())

	var campaignManager activity.ManageCampaign
	var response flowv1.OperationRun

	err := workflow.ExecuteActivity(ctx, campaignManager.ResumeCampaignOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "ResumeCampaignOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// AdvanceCampaignPhase is a workflow to open the next phase of a phase-gated
// operation run via Flow.
func AdvanceCampaignPhase(ctx workflow.Context, request *flowv1.AdvanceOperationRunPhaseRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Workflow", "Campaign").Str("Action", "AdvancePhase").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, campaignActivityOptions())

	var campaignManager activity.ManageCampaign
	var response flowv1.OperationRun

	err := workflow.ExecuteActivity(ctx, campaignManager.AdvanceCampaignPhaseOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "AdvanceCampaignPhaseOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// CancelCampaign is a workflow to cancel an operation run and its in-flight
// targets via Flow.
func CancelCampaign(ctx workflow.Context, request *flowv1.CancelOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Workflow", "Campaign").Str("Action", "Cancel").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, campaignActivityOptions())

	var campaignManager activity.ManageCampaign
	var response flowv1.OperationRun

	err := workflow.ExecuteActivity(ctx, campaignManager.CancelCampaignOnFlow, request).Get(ctx, &response)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "CancelCampaignOnFlow").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}
