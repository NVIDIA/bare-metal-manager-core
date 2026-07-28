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

// ManageTaskRun is an activity wrapper for operation-run management via Flow. A
// run is a phased, policy-gated execution of one operation across many racks.
type ManageTaskRun struct {
	flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient
}

// NewManageTaskRun returns a new ManageTaskRun client.
func NewManageTaskRun(flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient) ManageTaskRun {
	return ManageTaskRun{
		flowGrpcAtomicClient: flowGrpcAtomicClient,
	}
}

// requireRunID returns a non-retryable error when the request is missing
// its operation-run identifier so the workflow fails fast on bad input.
func requireRunID(id *flowv1.UUID) error {
	if id == nil || id.GetId() == "" {
		err := errors.New("received run request without operation run ID")
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	return nil
}

// CreateTaskRunOnFlow creates an operation run via Flow.
func (mr *ManageTaskRun) CreateTaskRunOnFlow(ctx context.Context, request *flowv1.CreateOperationRunRequest) (*flowv1.CreateOperationRunResponse, error) {
	logger := log.With().Str("Activity", "CreateTaskRunOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty create operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
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

	logger.Info().Str("RunID", response.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// GetTaskRunFromFlow retrieves an operation run by ID via Flow.
func (mr *ManageTaskRun) GetTaskRunFromFlow(ctx context.Context, request *flowv1.GetOperationRunRequest) (*flowv1.GetOperationRunResponse, error) {
	logger := log.With().Str("Activity", "GetTaskRunFromFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty get operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireRunID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().GetOperationRun(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get operation run using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("RunID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// GetAllTaskRunsFromFlow lists operation runs via Flow.
func (mr *ManageTaskRun) GetAllTaskRunsFromFlow(ctx context.Context, request *flowv1.ListOperationRunsRequest) (*flowv1.ListOperationRunsResponse, error) {
	logger := log.With().Str("Activity", "GetAllTaskRunsFromFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty list operation runs request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
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
		Int("RunCount", len(response.GetOperationRuns())).
		Int32("Total", response.GetTotal()).
		Msg("Completed activity")
	return response, nil
}

// GetAllTaskRunTargetsFromFlow lists the materialized rack execution targets for
// one operation run via Flow.
func (mr *ManageTaskRun) GetAllTaskRunTargetsFromFlow(ctx context.Context, request *flowv1.ListOperationRunTargetsRequest) (*flowv1.ListOperationRunTargetsResponse, error) {
	logger := log.With().Str("Activity", "GetAllTaskRunTargetsFromFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty list operation run targets request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireRunID(request.GetOperationRunId()); err != nil {
		return nil, err
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
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
		Str("RunID", request.GetOperationRunId().GetId()).
		Int("TargetCount", len(response.GetTargets())).
		Int32("Total", response.GetTotal()).
		Msg("Completed activity")
	return response, nil
}

// PauseTaskRunOnFlow pauses a running operation run via Flow.
func (mr *ManageTaskRun) PauseTaskRunOnFlow(ctx context.Context, request *flowv1.PauseOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Activity", "PauseTaskRunOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty pause operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireRunID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().PauseOperationRun(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to pause operation run using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("RunID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// ResumeTaskRunOnFlow resumes an operator-paused operation run via Flow.
func (mr *ManageTaskRun) ResumeTaskRunOnFlow(ctx context.Context, request *flowv1.ResumeOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Activity", "ResumeTaskRunOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty resume operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireRunID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().ResumeOperationRun(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to resume operation run using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("RunID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// AdvanceTaskRunPhaseOnFlow opens the next phase of a phase-gated operation
// run via Flow.
func (mr *ManageTaskRun) AdvanceTaskRunPhaseOnFlow(ctx context.Context, request *flowv1.AdvanceOperationRunPhaseRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Activity", "AdvanceTaskRunPhaseOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty advance operation run phase request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireRunID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().AdvanceOperationRunPhase(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to advance operation run phase using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("RunID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// CancelTaskRunOnFlow cancels an operation run and its in-flight targets via
// Flow.
func (mr *ManageTaskRun) CancelTaskRunOnFlow(ctx context.Context, request *flowv1.CancelOperationRunRequest) (*flowv1.OperationRun, error) {
	logger := log.With().Str("Activity", "CancelTaskRunOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty cancel operation run request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if err := requireRunID(request.GetId()); err != nil {
		return nil, err
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().CancelOperationRun(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to cancel operation run using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("RunID", request.GetId().GetId()).Msg("Completed activity")
	return response, nil
}
