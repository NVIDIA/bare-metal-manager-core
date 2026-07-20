// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"

	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"

	flowv1 "github.com/NVIDIA/infra-controller/rest-api/proto/flow/gen/v1"
	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
)

// ManageCampaign is an activity wrapper for Operation Run ("campaign")
// management via Flow. A campaign is Flow's operation-run: a phased, policy-
// gated rollout of one operation across many racks.
type ManageCampaign struct {
	flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient
}

// NewManageCampaign returns a new ManageCampaign client.
func NewManageCampaign(flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient) ManageCampaign {
	return ManageCampaign{
		flowGrpcAtomicClient: flowGrpcAtomicClient,
	}
}

// requireCampaignID returns a non-retryable error when the request is missing
// its operation-run identifier so the workflow fails fast on bad input.
func requireCampaignID(id *flowv1.UUID) error {
	if id == nil || id.GetId() == "" {
		err := errors.New("received campaign request without operation run ID")
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	return nil
}

// CreateCampaignOnFlow creates an operation run via Flow.
func (mc *ManageCampaign) CreateCampaignOnFlow(ctx context.Context, request *flowv1.CreateOperationRunRequest) (*flowv1.CreateOperationRunResponse, error) {
	logger := log.With().Str("Activity", "CreateCampaignOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty create operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mc.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().CreateOperationRun(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create operation run using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}
	if response == nil {
		return nil, swe.WrapErr(errors.New("Flow CreateOperationRun returned nil response"))
	}

	logger.Info().Str("CampaignID", response.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// GetCampaignFromFlow retrieves an operation run by ID via Flow.
func (mc *ManageCampaign) GetCampaignFromFlow(ctx context.Context, request *flowv1.GetOperationRunRequest) (*flowv1.GetOperationRunResponse, error) {
	logger := log.With().Str("Activity", "GetCampaignFromFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty get operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireCampaignID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mc.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().GetOperationRun(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get operation run using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("CampaignID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// GetAllCampaignsFromFlow lists operation runs via Flow.
func (mc *ManageCampaign) GetAllCampaignsFromFlow(ctx context.Context, request *flowv1.ListOperationRunsRequest) (*flowv1.ListOperationRunsResponse, error) {
	logger := log.With().Str("Activity", "GetAllCampaignsFromFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty list operation runs request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mc.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().ListOperationRuns(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to list operation runs using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}
	if response == nil {
		return nil, swe.WrapErr(errors.New("Flow ListOperationRuns returned nil response"))
	}

	logger.Info().
		Int("CampaignCount", len(response.GetOperationRuns())).
		Int32("Total", response.GetTotal()).
		Msg("Completed activity")
	return response, nil
}

// GetCampaignTargetsFromFlow lists the materialized rack execution targets for
// one operation run via Flow.
func (mc *ManageCampaign) GetCampaignTargetsFromFlow(ctx context.Context, request *flowv1.ListOperationRunTargetsRequest) (*flowv1.ListOperationRunTargetsResponse, error) {
	logger := log.With().Str("Activity", "GetCampaignTargetsFromFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty list operation run targets request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireCampaignID(request.GetOperationRunId()); err != nil {
		return nil, err
	}

	grpcClient := mc.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().ListOperationRunTargets(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to list operation run targets using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}
	if response == nil {
		return nil, swe.WrapErr(errors.New("Flow ListOperationRunTargets returned nil response"))
	}

	logger.Info().
		Str("CampaignID", request.GetOperationRunId().GetId()).
		Int("TargetCount", len(response.GetTargets())).
		Int32("Total", response.GetTotal()).
		Msg("Completed activity")
	return response, nil
}

// PauseCampaignOnFlow pauses a running operation run via Flow.
func (mc *ManageCampaign) PauseCampaignOnFlow(ctx context.Context, request *flowv1.PauseOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Activity", "PauseCampaignOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty pause operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireCampaignID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mc.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().PauseOperationRun(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to pause operation run using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("CampaignID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// ResumeCampaignOnFlow resumes an operator-paused operation run via Flow.
func (mc *ManageCampaign) ResumeCampaignOnFlow(ctx context.Context, request *flowv1.ResumeOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Activity", "ResumeCampaignOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty resume operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireCampaignID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mc.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().ResumeOperationRun(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to resume operation run using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("CampaignID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// AdvanceCampaignPhaseOnFlow opens the next phase of a phase-gated operation
// run via Flow.
func (mc *ManageCampaign) AdvanceCampaignPhaseOnFlow(ctx context.Context, request *flowv1.AdvanceOperationRunPhaseRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Activity", "AdvanceCampaignPhaseOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty advance operation run phase request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireCampaignID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mc.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().AdvanceOperationRunPhase(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to advance operation run phase using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("CampaignID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// CancelCampaignOnFlow cancels an operation run and its in-flight targets via
// Flow.
func (mc *ManageCampaign) CancelCampaignOnFlow(ctx context.Context, request *flowv1.CancelOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Activity", "CancelCampaignOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty cancel operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireCampaignID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mc.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().CancelOperationRun(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to cancel operation run using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("CampaignID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}
