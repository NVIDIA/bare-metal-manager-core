// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"

	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"

	swe "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/error"
	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
)

// ManageTask is an activity wrapper for Task management via Flow
type ManageTask struct {
	flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient
}

// NewManageTask returns a new ManageTask client
func NewManageTask(flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient) ManageTask {
	return ManageTask{
		flowGrpcAtomicClient: flowGrpcAtomicClient,
	}
}

// GetTasksFromFlow lists tasks matching the given filters via Flow. The
// filters in flowv1.ListTasksRequest combine with AND; pagination, ordering,
// and totals are computed by Flow over the post-filter result set.
func (mt *ManageTask) GetTasksFromFlow(ctx context.Context, request *flowv1.ListTasksRequest) (*flowv1.ListTasksResponse, error) {
	logger := log.With().Str("Activity", "GetTasksFromFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty list tasks request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mt.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.ListTasks(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to list tasks using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}
	if response == nil {
		return nil, swe.WrapErr(errors.New("Flow ListTasks returned nil response"))
	}

	logger.Info().
		Int("TaskCount", len(response.GetTasks())).
		Int32("Total", response.GetTotal()).
		Msg("Completed activity")

	return response, nil
}

// GetTaskFromFlow retrieves tasks by ID via Flow GetTasksByIDs.
func (mt *ManageTask) GetTaskFromFlow(ctx context.Context, request *flowv1.GetTasksByIDsRequest) (*flowv1.GetTasksByIDsResponse, error) {
	logger := log.With().Str("Activity", "GetTask").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	switch {
	case request == nil:
		err = errors.New("received empty get task request")
	case len(request.GetTaskIds()) == 0:
		err = errors.New("received get task request without task IDs")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mt.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.GetTasksByIDs(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get task by ID using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Int("TaskCount", len(response.GetTasks())).Msg("Completed activity")

	return response, nil
}

// CancelTask cancels a task by its UUID via Flow.
//
// Cancel is best-effort: Flow marks the task Terminated and terminates the
// underlying Temporal workflow if one was scheduled. Already-finished tasks
// (Succeeded/Failed) cannot be cancelled and the Flow call returns an error.
func (mt *ManageTask) CancelTaskOnFlow(ctx context.Context, request *flowv1.CancelTaskRequest) (*flowv1.CancelTaskResponse, error) {
	logger := log.With().Str("Activity", "CancelTask").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	switch {
	case request == nil:
		err = errors.New("received empty cancel task request")
	case request.GetTaskId() == nil || request.GetTaskId().GetId() == "":
		err = errors.New("received cancel task request without task ID")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mt.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.CancelTask(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to cancel task using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("TaskID", request.GetTaskId().GetId()).Msg("Completed activity")

	return response, nil
}
