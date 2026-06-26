// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
	operationrunmanager "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun/manager"
	pb "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/proto/v1"
)

var _ operationrunmanager.Manager = (*mockOperationRunManager)(nil)

func TestCreateOperationRunCallsManager(t *testing.T) {
	createdID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	manager := &mockOperationRunManager{createID: createdID}
	server := &FlowServerImpl{operationRunManager: manager}

	resp, err := server.CreateOperationRun(
		context.Background(),
		validCreateOperationRunRequest(),
	)
	require.NoError(t, err)

	require.Equal(t, createdID.String(), resp.GetId().GetId())
	require.Equal(t, 1, manager.createCalls)
	require.NotNil(t, manager.createdRun)
	require.Equal(t, "firmware canary", manager.createdRun.Name)
	require.Equal(t, operationrun.OperationRunStatusPending, manager.createdRun.Status)
	require.NotEmpty(t, manager.createdRun.Selector)
	require.NotEmpty(t, manager.createdRun.Options)
	require.NotEmpty(t, manager.createdRun.OperationTemplate)
}

func TestCreateOperationRunRejectsInvalidRequest(t *testing.T) {
	manager := &mockOperationRunManager{}
	server := &FlowServerImpl{operationRunManager: manager}

	resp, err := server.CreateOperationRun(
		context.Background(),
		&pb.CreateOperationRunRequest{},
	)

	require.Nil(t, resp)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, 0, manager.createCalls)
}

func TestCreateOperationRunRequiresManager(t *testing.T) {
	server := &FlowServerImpl{}

	resp, err := server.CreateOperationRun(
		context.Background(),
		validCreateOperationRunRequest(),
	)

	require.Nil(t, resp)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestCreateOperationRunReturnsManagerError(t *testing.T) {
	manager := &mockOperationRunManager{
		createErr: errors.New("planning failed"),
	}
	server := &FlowServerImpl{operationRunManager: manager}

	resp, err := server.CreateOperationRun(
		context.Background(),
		validCreateOperationRunRequest(),
	)

	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	require.ErrorContains(t, err, "planning failed")
}

func TestCreateOperationRunMapsManagerInvalidArgumentErrors(t *testing.T) {
	manager := &mockOperationRunManager{
		createErr: operationrunmanager.ErrNoPlannedTargets,
	}
	server := &FlowServerImpl{operationRunManager: manager}

	resp, err := server.CreateOperationRun(
		context.Background(),
		validCreateOperationRunRequest(),
	)

	require.Nil(t, resp)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.ErrorContains(t, err, "operation run has no planned targets")
}

func TestCreateOperationRunPreservesManagerStatusError(t *testing.T) {
	manager := &mockOperationRunManager{
		createErr: status.Error(codes.InvalidArgument, "invalid target scope"),
	}
	server := &FlowServerImpl{operationRunManager: manager}

	resp, err := server.CreateOperationRun(
		context.Background(),
		validCreateOperationRunRequest(),
	)

	require.Nil(t, resp)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.ErrorContains(t, err, "invalid target scope")
}

type mockOperationRunManager struct {
	createID    uuid.UUID
	createErr   error
	createCalls int
	createdRun  *operationrun.OperationRun
}

func (m *mockOperationRunManager) Create(
	_ context.Context,
	run *operationrun.OperationRun,
) (uuid.UUID, error) {
	m.createCalls++
	m.createdRun = run
	if m.createErr != nil {
		return uuid.Nil, m.createErr
	}

	return m.createID, nil
}

func (m *mockOperationRunManager) Get(
	_ context.Context,
	_ uuid.UUID,
) (*operationrun.OperationRun, error) {
	return nil, errors.New("not implemented")
}

func (m *mockOperationRunManager) List(
	_ context.Context,
	_ operationrun.ListOptions,
) ([]*operationrun.OperationRun, int32, error) {
	return nil, 0, errors.New("not implemented")
}

func (m *mockOperationRunManager) ListTargets(
	_ context.Context,
	_ uuid.UUID,
	_ operationrun.TargetListOptions,
) ([]*operationrun.OperationRunTarget, int32, error) {
	return nil, 0, errors.New("not implemented")
}

func validCreateOperationRunRequest() *pb.CreateOperationRunRequest {
	targetVersion := "1.2.3"

	return &pb.CreateOperationRunRequest{
		Name: "firmware canary",
		Configuration: &pb.OperationRunConfiguration{
			Selector: &pb.OperationRunSelector{
				Selector: &pb.OperationRunSelector_Percentage{
					Percentage: &pb.PercentageSelector{Percentage: 10},
				},
			},
			Options: &pb.OperationRunOptions{
				MaxConcurrentTargets: 2,
				SafetyPolicy: &pb.OperationRunSafetyPolicy{
					Gates: []*pb.OperationRunSafetyGate{
						{
							Gate: &pb.OperationRunSafetyGate_FailureRate{
								FailureRate: &pb.OperationRunFailureRateGate{
									FailureThresholdPercent: 20,
								},
							},
						},
					},
				},
			},
			Operation: &pb.OperationRunOperation{
				Operation: &pb.OperationRunOperation_UpgradeFirmware{
					UpgradeFirmware: &pb.UpgradeFirmwareRequest{
						TargetVersion: &targetVersion,
						Description:   "roll rack firmware",
						QueueOptions: &pb.QueueOptions{
							ConflictStrategy:    pb.ConflictStrategy_CONFLICT_STRATEGY_QUEUE,
							QueueTimeoutSeconds: 300,
						},
						RuleId: &pb.UUID{
							Id: "33333333-3333-3333-3333-333333333333",
						},
						SubTargets:             []string{"bmc"},
						OverrideReadinessCheck: true,
					},
				},
			},
		},
	}
}
