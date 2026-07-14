// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/protobuf"
	dbquery "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/query"
	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
	operationrunmanager "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun/manager"
	pb "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/proto/v1"
)

func (rs *FlowServerImpl) CreateOperationRun(
	ctx context.Context,
	req *pb.CreateOperationRunRequest,
) (*pb.CreateOperationRunResponse, error) {
	run, err := protobuf.OperationRunFrom(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	manager, err := rs.requireOperationRunManager()
	if err != nil {
		return nil, err
	}

	id, err := manager.Create(ctx, run)
	if err != nil {
		return nil, operationRunStatusError(codes.Internal, err)
	}

	return &pb.CreateOperationRunResponse{
		Id: protobuf.UUIDTo(id),
	}, nil
}

func (rs *FlowServerImpl) requireOperationRunManager() (operationrunmanager.Manager, error) {
	if rs == nil || rs.operationRunManager == nil {
		return nil, status.Error(codes.FailedPrecondition, "operation run manager is not configured")
	}

	return rs.operationRunManager, nil
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
	} else if errors.Is(err, operationrunmanager.ErrOperationRunNotFound) {
		c = codes.NotFound
	} else if errors.Is(err, operationrunmanager.ErrNoPlannedTargets) {
		c = codes.InvalidArgument
	} else if errors.Is(err, operationrunmanager.ErrOperationRunInvalidState) ||
		errors.Is(err, operationrunmanager.ErrOperationRunSafetyGateTripped) {
		c = codes.FailedPrecondition
	} else {
		c = defaultCode
	}

	return status.Error(c, err.Error())
}

func (rs *FlowServerImpl) GetOperationRun(
	ctx context.Context,
	req *pb.GetOperationRunRequest,
) (*pb.GetOperationRunResponse, error) {
	manager, err := rs.requireOperationRunManager()
	if err != nil {
		return nil, err
	}

	id := protobuf.UUIDFrom(req.GetId())
	if id == uuid.Nil {
		return nil, status.Error(codes.InvalidArgument, "operation run ID is required")
	}

	run, err := manager.Get(ctx, id)
	if err != nil {
		return nil, operationRunStatusError(codes.Internal, err)
	}

	result, err := protobuf.OperationRunTo(run)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if req.GetIncludeStats() {
		stats, err := operationRunStatsForTargets(ctx, manager, id)
		if err != nil {
			return nil, operationRunStatusError(codes.Internal, err)
		}
		result.Stats = protobuf.ProgressStatsTo(stats)
	}

	return &pb.GetOperationRunResponse{OperationRun: result}, nil
}

func (rs *FlowServerImpl) ListOperationRuns(
	ctx context.Context,
	req *pb.ListOperationRunsRequest,
) (*pb.ListOperationRunsResponse, error) {
	manager, err := rs.requireOperationRunManager()
	if err != nil {
		return nil, err
	}

	opts, err := protobuf.OperationRunListOptionsFrom(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	runs, total, err := manager.List(ctx, opts)
	if err != nil {
		return nil, operationRunStatusError(codes.Internal, err)
	}

	result, err := convertSlice(runs, protobuf.OperationRunSummaryTo)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.ListOperationRunsResponse{
		OperationRuns: result,
		Total:         total,
	}, nil
}

func (rs *FlowServerImpl) ListOperationRunTargets(
	ctx context.Context,
	req *pb.ListOperationRunTargetsRequest,
) (*pb.ListOperationRunTargetsResponse, error) {
	manager, err := rs.requireOperationRunManager()
	if err != nil {
		return nil, err
	}

	id := protobuf.UUIDFrom(req.GetOperationRunId())
	if id == uuid.Nil {
		return nil, status.Error(codes.InvalidArgument, "operation run ID is required")
	}

	opts, err := protobuf.OperationRunTargetListOptionsFrom(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	targets, total, err := manager.ListTargets(ctx, id, opts)
	if err != nil {
		return nil, operationRunStatusError(codes.Internal, err)
	}

	result, err := convertSlice(targets, protobuf.OperationRunTargetTo)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.ListOperationRunTargetsResponse{
		Targets: result,
		Total:   total,
	}, nil
}

func convertSlice[T any, U any](
	items []T,
	convert func(T) (U, error),
) ([]U, error) {
	result := make([]U, 0, len(items))
	for _, item := range items {
		converted, err := convert(item)
		if err != nil {
			return nil, err
		}
		result = append(result, converted)
	}

	return result, nil
}

func operationRunStatsForTargets(
	ctx context.Context,
	manager operationrunmanager.Manager,
	id uuid.UUID,
) (operationrun.ProgressStats, error) {
	// TODO: Move this to a store/manager aggregate query that reuses the
	// phase-scope filtering and groups by phase_index/status. Listing and
	// hydrating every target row is correct but scales with fleet size.
	stats := operationrun.ProgressStats{}
	offset := 0
	for {
		page, total, err := manager.ListTargets(
			ctx,
			id,
			operationrun.TargetListOptions{
				PhaseScope: operationrun.TargetPhaseScopeCurrentAndCompletedPhases,
				Pagination: &dbquery.Pagination{
					Offset: offset,
					Limit:  dbquery.DefaultPaginationLimit,
				},
			},
		)
		if err != nil {
			return operationrun.ProgressStats{}, err
		}

		if len(page) == 0 {
			if int32(offset) >= total {
				return stats, nil
			}

			return operationrun.ProgressStats{}, fmt.Errorf(
				"operation run target stats query returned 0 targets at offset %d before total %d",
				offset,
				total,
			)
		}

		stats.AddTargets(page)
		offset += len(page)
		if int32(offset) >= total {
			return stats, nil
		}
	}
}

func (rs *FlowServerImpl) PauseOperationRun(
	ctx context.Context,
	req *pb.PauseOperationRunRequest,
) (*pb.OperationRun, error) {
	return rs.handleOperationRunControl(
		req.GetId(),
		func(manager operationrunmanager.Manager, id uuid.UUID) (*operationrun.OperationRun, error) {
			return manager.Pause(ctx, id)
		},
	)
}

func (rs *FlowServerImpl) ResumeOperationRun(
	ctx context.Context,
	req *pb.ResumeOperationRunRequest,
) (*pb.OperationRun, error) {
	return rs.handleOperationRunControl(
		req.GetId(),
		func(manager operationrunmanager.Manager, id uuid.UUID) (*operationrun.OperationRun, error) {
			return manager.Resume(ctx, id)
		},
	)
}

func (rs *FlowServerImpl) AdvanceOperationRunPhase(
	ctx context.Context,
	req *pb.AdvanceOperationRunPhaseRequest,
) (*pb.OperationRun, error) {
	return rs.handleOperationRunControl(
		req.GetId(),
		func(manager operationrunmanager.Manager, id uuid.UUID) (*operationrun.OperationRun, error) {
			return manager.AdvancePhase(ctx, id, req.ExpectedPhaseIndex)
		},
	)
}

func (rs *FlowServerImpl) CancelOperationRun(
	ctx context.Context,
	req *pb.CancelOperationRunRequest,
) (*pb.OperationRun, error) {
	if rs.taskManager == nil {
		return nil, status.Error(codes.FailedPrecondition, "task manager is not configured")
	}

	return rs.handleOperationRunControl(
		req.GetId(),
		func(manager operationrunmanager.Manager, id uuid.UUID) (*operationrun.OperationRun, error) {
			return manager.Cancel(ctx, id, req.GetReason(), rs.taskManager)
		},
	)
}

func (rs *FlowServerImpl) handleOperationRunControl(
	reqID *pb.UUID,
	action func(operationrunmanager.Manager, uuid.UUID) (*operationrun.OperationRun, error),
) (*pb.OperationRun, error) {
	manager, err := rs.requireOperationRunManager()
	if err != nil {
		return nil, err
	}

	id := protobuf.UUIDFrom(reqID)
	if id == uuid.Nil {
		return nil, status.Error(codes.InvalidArgument, "operation run ID is required")
	}

	run, err := action(manager, id)
	if err != nil {
		return nil, operationRunStatusError(codes.Internal, err)
	}

	result, err := protobuf.OperationRunTo(run)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return result, nil
}
