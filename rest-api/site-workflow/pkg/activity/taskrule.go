// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"

	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"

	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

// ManageTaskRule is an activity wrapper for Operation Rule management via Flow
type ManageTaskRule struct {
	flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient
}

// NewManageRule returns a new ManageTaskRule client
func NewManageRule(flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient) ManageTaskRule {
	return ManageTaskRule{
		flowGrpcAtomicClient: flowGrpcAtomicClient,
	}
}

// CreateTaskRuleOnFlow creates an Operation Rule via Flow.
func (mr *ManageTaskRule) CreateTaskRuleOnFlow(ctx context.Context, request *flowv1.CreateOperationRuleRequest) (*flowv1.CreateOperationRuleResponse, error) {
	logger := log.With().Str("Activity", "CreateTaskRuleOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty create operation rule request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().CreateOperationRule(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create operation rule using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}
	if response == nil {
		return nil, swe.WrapErr(errors.New("Flow CreateOperationRule returned nil response"))
	}

	logger.Info().Str("RuleID", response.GetId().GetId()).Msg("Completed activity")
	return response, nil
}

// GetTaskRuleFromFlow retrieves an Operation Rule by ID via Flow.
func (mr *ManageTaskRule) GetTaskRuleFromFlow(ctx context.Context, request *flowv1.GetOperationRuleRequest) (*flowv1.OperationRule, error) {
	logger := log.With().Str("Activity", "GetTaskRuleFromFlow").Logger()
	logger.Info().Msg("Starting activity")

	var err error
	switch {
	case request == nil:
		err = errors.New("received empty get operation rule request")
	case request.GetRuleId() == nil || request.GetRuleId().GetId() == "":
		err = errors.New("received get operation rule request without rule ID")
	}
	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().GetOperationRule(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get operation rule using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Str("RuleID", request.GetRuleId().GetId()).Msg("Completed activity")
	return response, nil
}

// GetAllTaskRulesFromFlow lists Operation Rules via Flow.
func (mr *ManageTaskRule) GetAllTaskRulesFromFlow(ctx context.Context, request *flowv1.ListOperationRulesRequest) (*flowv1.ListOperationRulesResponse, error) {
	logger := log.With().Str("Activity", "GetAllTaskRulesFromFlow").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty list operation rules request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	response, err := grpcClient.GrpcServiceClient().ListOperationRules(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to list operation rules using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}
	if response == nil {
		return nil, swe.WrapErr(errors.New("Flow ListOperationRules returned nil response"))
	}

	logger.Info().
		Int("RuleCount", len(response.GetRules())).
		Int32("Total", response.GetTotalCount()).
		Msg("Completed activity")
	return response, nil
}

// UpdateTaskRuleOnFlow updates an Operation Rule via Flow.
func (mr *ManageTaskRule) UpdateTaskRuleOnFlow(ctx context.Context, request *flowv1.UpdateOperationRuleRequest) error {
	logger := log.With().Str("Activity", "UpdateTaskRuleOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	var err error
	switch {
	case request == nil:
		err = errors.New("received empty update operation rule request")
	case request.GetRuleId() == nil || request.GetRuleId().GetId() == "":
		err = errors.New("received update operation rule request without rule ID")
	}
	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrFlowGrpcClientNotConnected
	}

	if _, err := grpcClient.GrpcServiceClient().UpdateOperationRule(ctx, request); err != nil {
		logger.Warn().Err(err).Msg("Failed to update operation rule using Flow gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Str("RuleID", request.GetRuleId().GetId()).Msg("Completed activity")
	return nil
}

// DeleteTaskRuleOnFlow deletes an Operation Rule via Flow.
func (mr *ManageTaskRule) DeleteTaskRuleOnFlow(ctx context.Context, request *flowv1.DeleteOperationRuleRequest) error {
	logger := log.With().Str("Activity", "DeleteTaskRuleOnFlow").Logger()
	logger.Info().Msg("Starting activity")

	var err error
	switch {
	case request == nil:
		err = errors.New("received empty delete operation rule request")
	case request.GetRuleId() == nil || request.GetRuleId().GetId() == "":
		err = errors.New("received delete operation rule request without rule ID")
	}
	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrFlowGrpcClientNotConnected
	}

	if _, err := grpcClient.GrpcServiceClient().DeleteOperationRule(ctx, request); err != nil {
		logger.Warn().Err(err).Msg("Failed to delete operation rule using Flow gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Str("RuleID", request.GetRuleId().GetId()).Msg("Completed activity")
	return nil
}
