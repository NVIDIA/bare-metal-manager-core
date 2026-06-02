// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"

	"github.com/rs/zerolog/log"

	swe "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/error"
	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	"go.temporal.io/sdk/temporal"
)

// ManageTray is an activity wrapper for Tray management via Flow
type ManageTray struct {
	flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient
}

// GetTray retrieves a tray by its UUID from Flow
func (mt *ManageTray) GetTray(ctx context.Context, request *flowv1.GetComponentInfoByIDRequest) (*flowv1.GetComponentInfoResponse, error) {
	logger := log.With().Str("Activity", "GetTray").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	switch {
	case request == nil:
		err = errors.New("received empty get tray request")
	case request.Id == nil || request.Id.Id == "":
		err = errors.New("received get tray request missing tray ID")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Flow gRPC endpoint
	grpcClient := mt.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.GetComponentInfoByID(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get tray by ID using Flow API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return response, nil
}

// GetTrays retrieves a list of trays from Flow with optional filters.
func (mt *ManageTray) GetTrays(ctx context.Context, request *flowv1.GetComponentsRequest) (*flowv1.GetComponentsResponse, error) {
	logger := log.With().Str("Activity", "GetTrays").Logger()
	logger.Info().Msg("Starting activity")

	// Request can be nil or empty for getting all trays
	if request == nil {
		request = &flowv1.GetComponentsRequest{}
	}

	// Call Flow gRPC endpoint
	grpcClient := mt.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.GetComponents(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get list of trays using Flow API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Int32("Total", response.GetTotal()).Msg("Completed activity")

	return response, nil
}

// NewManageTray returns a new ManageTray client
func NewManageTray(flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient) ManageTray {
	return ManageTray{
		flowGrpcAtomicClient: flowGrpcAtomicClient,
	}
}
