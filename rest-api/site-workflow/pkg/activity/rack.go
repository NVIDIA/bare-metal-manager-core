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

// ManageRack is an activity wrapper for Rack management via Flow
type ManageRack struct {
	flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient
}

// NewManageRack returns a new ManageRack client
func NewManageRack(flowGrpcAtomicClient *cClient.FlowGrpcAtomicClient) ManageRack {
	return ManageRack{
		flowGrpcAtomicClient: flowGrpcAtomicClient,
	}
}

// GetRack retrieves a rack by its UUID from Flow
func (mr *ManageRack) GetRack(ctx context.Context, request *flowv1.GetRackInfoByIDRequest) (*flowv1.GetRackInfoResponse, error) {
	logger := log.With().Str("Activity", "GetRack").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	switch {
	case request == nil:
		err = errors.New("received empty get rack request")
	case request.Id == nil || request.Id.Id == "":
		err = errors.New("received get rack request without rack ID")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Flow gRPC endpoint
	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.GetRackInfoByID(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get Rack by ID using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}
	return response, nil
}

// GetRacks retrieves a list of racks from Flow with optional filters
func (mr *ManageRack) GetRacks(ctx context.Context, request *flowv1.GetListOfRacksRequest) (*flowv1.GetListOfRacksResponse, error) {
	logger := log.With().Str("Activity", "GetRacks").Logger()
	logger.Info().Msg("Starting activity")

	// Request can be nil or empty for getting all racks
	if request == nil {
		request = &flowv1.GetListOfRacksRequest{}
	}

	// Call Flow gRPC endpoint
	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.GetListOfRacks(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get list of Racks using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Int32("Total", response.GetTotal()).Msg("Completed activity")

	return response, nil
}

// ValidateRackComponents validates rack components by comparing expected vs actual state via Flow.
// Supports validating a single rack, multiple racks with filters, or all racks in a site.
func (mr *ManageRack) ValidateRackComponents(ctx context.Context, request *flowv1.ValidateComponentsRequest) (*flowv1.ValidateComponentsResponse, error) {
	logger := log.With().Str("Activity", "ValidateRackComponents").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	switch {
	case request == nil:
		err = errors.New("received empty validate rack components request")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Flow gRPC endpoint
	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.ValidateComponents(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to validate rack components using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Int32("TotalDiffs", response.GetTotalDiffs()).Msg("Completed activity")

	return response, nil
}

// PowerOnRack powers on a rack or its specified components via Flow
func (mr *ManageRack) PowerOnRack(ctx context.Context, request *flowv1.PowerOnRackRequest) (*flowv1.SubmitTaskResponse, error) {
	logger := log.With().Str("Activity", "PowerOnRack").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	switch {
	case request == nil:
		err = errors.New("received empty power on rack request")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Flow gRPC endpoint
	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.PowerOnRack(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to power on rack using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Int("TaskCount", len(response.GetTaskIds())).Msg("Completed activity")

	return response, nil
}

// PowerOffRack powers off a rack or its specified components via Flow
func (mr *ManageRack) PowerOffRack(ctx context.Context, request *flowv1.PowerOffRackRequest) (*flowv1.SubmitTaskResponse, error) {
	logger := log.With().Str("Activity", "PowerOffRack").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	switch {
	case request == nil:
		err = errors.New("received empty power off rack request")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Flow gRPC endpoint
	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.PowerOffRack(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to power off rack using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Int("TaskCount", len(response.GetTaskIds())).Msg("Completed activity")

	return response, nil
}

// PowerResetRack resets (power cycles) a rack or its specified components via Flow
func (mr *ManageRack) PowerResetRack(ctx context.Context, request *flowv1.PowerResetRackRequest) (*flowv1.SubmitTaskResponse, error) {
	logger := log.With().Str("Activity", "PowerResetRack").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	switch {
	case request == nil:
		err = errors.New("received empty power reset rack request")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Flow gRPC endpoint
	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.PowerResetRack(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to power reset rack using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Int("TaskCount", len(response.GetTaskIds())).Msg("Completed activity")

	return response, nil
}

// BringUpRack brings up a rack or its specified components via Flow
func (mr *ManageRack) BringUpRack(ctx context.Context, request *flowv1.BringUpRackRequest) (*flowv1.SubmitTaskResponse, error) {
	logger := log.With().Str("Activity", "BringUpRack").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	switch {
	case request == nil:
		err = errors.New("received empty bring up rack request")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.BringUpRack(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to bring up rack using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Int("TaskCount", len(response.GetTaskIds())).Msg("Completed activity")

	return response, nil
}

// UpgradeFirmware upgrades firmware on racks or components via Flow
func (mr *ManageRack) UpgradeFirmware(ctx context.Context, request *flowv1.UpgradeFirmwareRequest) (*flowv1.SubmitTaskResponse, error) {
	logger := log.With().Str("Activity", "UpgradeFirmware").Logger()
	logger.Info().Msg("Starting activity")

	var err error

	switch {
	case request == nil:
		err = errors.New("received empty upgrade firmware request")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	grpcClient := mr.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrFlowGrpcClientNotConnected
	}

	grpcServiceClient := grpcClient.GrpcServiceClient()

	response, err := grpcServiceClient.UpgradeFirmware(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to upgrade firmware using Flow gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Int("TaskCount", len(response.GetTaskIds())).Msg("Completed activity")

	return response, nil
}
