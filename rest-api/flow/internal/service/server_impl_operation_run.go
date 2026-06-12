// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/proto/v1"
)

const operationRunUnimplementedMessage = "operation run API is not implemented"

func (rs *FlowServerImpl) CreateOperationRun(
	ctx context.Context,
	req *pb.CreateOperationRunRequest,
) (*pb.CreateOperationRunResponse, error) {
	return nil, status.Error(codes.Unimplemented, operationRunUnimplementedMessage)
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
