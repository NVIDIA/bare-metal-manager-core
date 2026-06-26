// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/protobuf"
	operationrunmanager "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun/manager"
	pb "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/proto/v1"
)

const operationRunUnimplementedMessage = "operation run API is not implemented"

func (rs *FlowServerImpl) CreateOperationRun(
	ctx context.Context,
	req *pb.CreateOperationRunRequest,
) (*pb.CreateOperationRunResponse, error) {
	run, err := protobuf.OperationRunFrom(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if rs == nil || rs.operationRunManager == nil {
		return nil, status.Error(codes.FailedPrecondition, "operation run manager is not configured")
	}

	id, err := rs.operationRunManager.Create(ctx, run)
	if err != nil {
		return nil, operationRunStatusError(codes.Internal, err)
	}

	return &pb.CreateOperationRunResponse{
		Id: protobuf.UUIDTo(id),
	}, nil
}

func operationRunStatusError(
	defaultCode codes.Code,
	err error,
) error {
	if _, ok := status.FromError(err); ok {
		return err
	}

	var c codes.Code
	if errors.Is(err, operationrunmanager.ErrOperationRunRequired) {
		c = codes.InvalidArgument
	} else if errors.Is(err, operationrunmanager.ErrNoPlannedTargets) {
		c = codes.InvalidArgument
	} else {
		c = defaultCode
	}

	return status.Error(c, err.Error())
}

func (rs *FlowServerImpl) GetOperationRun(
	ctx context.Context,
	req *pb.GetOperationRunRequest,
) (*pb.GetOperationRunResponse, error) {
	return nil, status.Error(codes.Unimplemented, operationRunUnimplementedMessage)
}

func (rs *FlowServerImpl) ListOperationRuns(
	ctx context.Context,
	req *pb.ListOperationRunsRequest,
) (*pb.ListOperationRunsResponse, error) {
	return nil, status.Error(codes.Unimplemented, operationRunUnimplementedMessage)
}

func (rs *FlowServerImpl) ListOperationRunTargets(
	ctx context.Context,
	req *pb.ListOperationRunTargetsRequest,
) (*pb.ListOperationRunTargetsResponse, error) {
	return nil, status.Error(codes.Unimplemented, operationRunUnimplementedMessage)
}

func (rs *FlowServerImpl) PauseOperationRun(
	ctx context.Context,
	req *pb.PauseOperationRunRequest,
) (*pb.OperationRun, error) {
	return nil, status.Error(codes.Unimplemented, operationRunUnimplementedMessage)
}

func (rs *FlowServerImpl) ResumeOperationRun(
	ctx context.Context,
	req *pb.ResumeOperationRunRequest,
) (*pb.OperationRun, error) {
	return nil, status.Error(codes.Unimplemented, operationRunUnimplementedMessage)
}

func (rs *FlowServerImpl) CancelOperationRun(
	ctx context.Context,
	req *pb.CancelOperationRunRequest,
) (*pb.OperationRun, error) {
	return nil, status.Error(codes.Unimplemented, operationRunUnimplementedMessage)
}
