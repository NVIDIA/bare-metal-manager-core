// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operation"
	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun/manager/planner"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

var _ Store = (*mockStore)(nil)
var _ planner.TargetLookup = (*mockTargetLookup)(nil)

func TestCreatePersistsRunAndPlannedTargets(t *testing.T) {
	runID := uuid.New()
	store := &mockStore{runID: runID}
	manager := newTestManager(t, store, planner.New(&mockTargetLookup{
		defaultScope: testExecutionTargets(3),
	}, planner.Config{}))

	got, err := manager.Create(context.Background(), testOperationRun(t))
	require.NoError(t, err)
	require.Equal(t, runID, got)

	require.Equal(t, 1, store.txCalls)
	require.Equal(t, 1, store.createCalls)
	require.Len(t, store.createdTargets, 3)
	require.Equal(t, []int32{0, 0, 1}, targetPhaseIndexes(store.createdTargets))
	require.Equal(t, []int32{0, 1, 2}, targetSequenceIndexes(store.createdTargets))
	for _, target := range store.createdTargets {
		require.Equal(t, runID, target.OperationRunID)
		require.Equal(t, operationrun.OperationRunTargetStatusPending, target.Status)
	}
}

func TestCreateRejectsEmptyPlannedTargetsBeforeStoreWrite(t *testing.T) {
	store := &mockStore{runID: uuid.New()}
	manager := newTestManager(t, store, planner.New(&mockTargetLookup{}, planner.Config{}))

	_, err := manager.Create(context.Background(), testOperationRun(t))
	require.ErrorIs(t, err, ErrNoPlannedTargets)
	require.ErrorContains(t, err, "operation run has no planned targets")
	require.Zero(t, store.txCalls)
	require.Zero(t, store.createCalls)
	require.Zero(t, store.createTargetsCalls)
}

func TestCreateRejectsNilRunBeforeStoreWrite(t *testing.T) {
	store := &mockStore{runID: uuid.New()}
	manager := newTestManager(t, store, planner.New(&mockTargetLookup{}, planner.Config{}))

	_, err := manager.Create(context.Background(), nil)

	require.ErrorIs(t, err, ErrOperationRunRequired)
	require.ErrorContains(t, err, "operation run is required")
	require.Zero(t, store.txCalls)
	require.Zero(t, store.createCalls)
	require.Zero(t, store.createTargetsCalls)
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	store := &mockStore{runID: uuid.New()}
	plan := planner.New(&mockTargetLookup{}, planner.Config{})

	_, err := New(nil, plan)
	require.ErrorContains(t, err, "operation run store is required")

	_, err = New(store, nil)
	require.ErrorContains(t, err, "operation run planner is required")
}

type mockStore struct {
	runID uuid.UUID

	txCalls            int
	createCalls        int
	createTargetsCalls int
	createdRun         *operationrun.OperationRun
	createdTargets     []*operationrun.OperationRunTarget
}

func newTestManager(
	t *testing.T,
	store Store,
	plan planner.Planner,
) *ManagerImpl {
	t.Helper()

	manager, err := New(store, plan)
	require.NoError(t, err)
	return manager
}

func (m *mockStore) Create(
	ctx context.Context,
	run *operationrun.OperationRun,
) (uuid.UUID, error) {
	m.createCalls++
	m.createdRun = run
	return m.runID, nil
}

func (m *mockStore) Get(
	ctx context.Context,
	id uuid.UUID,
) (*operationrun.OperationRun, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStore) List(
	ctx context.Context,
	opts operationrun.ListOptions,
) ([]*operationrun.OperationRun, int32, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

func (m *mockStore) CreateTargets(
	ctx context.Context,
	runID uuid.UUID,
	targets []*operationrun.OperationRunTarget,
) error {
	m.createTargetsCalls++
	m.createdTargets = make([]*operationrun.OperationRunTarget, 0, len(targets))
	for _, target := range targets {
		copied := *target
		copied.OperationRunID = runID
		copied.Status = operationrun.OperationRunTargetStatusPending
		m.createdTargets = append(m.createdTargets, &copied)
	}
	return nil
}

func (m *mockStore) ListTargets(
	ctx context.Context,
	runID uuid.UUID,
	opts operationrun.TargetListOptions,
) ([]*operationrun.OperationRunTarget, int32, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

func (m *mockStore) RunInTransaction(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	m.txCalls++
	return fn(ctx)
}

type mockTargetLookup struct {
	defaultScope []operation.RackExecutionTarget
	targetSpec   []operation.RackExecutionTarget
	priorRuns    []operation.RackExecutionTarget
}

func (m *mockTargetLookup) TargetsFromDefaultScope(
	_ context.Context,
	_ *operationrun.Operation,
	_ planner.TargetLookupOptions,
) ([]operation.RackExecutionTarget, error) {
	return m.defaultScope, nil
}

func (m *mockTargetLookup) TargetsFromSpec(
	_ context.Context,
	_ *operation.TargetSpec,
	_ planner.TargetLookupOptions,
) ([]operation.RackExecutionTarget, error) {
	return m.targetSpec, nil
}

func (m *mockTargetLookup) TargetsFromRuns(
	_ context.Context,
	_ []uuid.UUID,
	_ planner.TargetLookupOptions,
) ([]operation.RackExecutionTarget, error) {
	return m.priorRuns, nil
}

func testOperationRun(t *testing.T) *operationrun.OperationRun {
	t.Helper()

	selectorRaw, err := operationrun.MarshalConfig(&operationrun.PercentageSelector{
		Percentage: 100,
		Seed:       "selector-seed",
	})
	require.NoError(t, err)

	optionsRaw, err := operationrun.MarshalConfig(operationrun.Options{
		MaxConcurrentTargets: 1,
		SafetyPolicy: operationrun.SafetyPolicy{
			Gates: []operationrun.SafetyGate{
				&operationrun.FailureCountGate{
					Scope:                 operationrun.SafetyGateScopeCurrentPhase,
					FailureThresholdCount: 1,
				},
			},
		},
		ConflictPolicy: operationrun.ConflictPolicy{
			Payload: &operationrun.ConflictRetryPolicy{
				RetryTimeout:      time.Hour,
				InitialRetryDelay: time.Second,
				MaxRetryDelay:     time.Minute,
			},
		},
		OrderingPolicy: operationrun.OrderingPolicy{
			Payload: &operationrun.RandomOrdering{Seed: "ordering-seed"},
		},
		PhasePolicy: operationrun.PhasePolicy{
			Plan: &operationrun.EqualPhases{PhaseCount: 2},
		},
	})
	require.NoError(t, err)

	firmware := &operations.FirmwareControlTaskInfo{
		Operation: operations.FirmwareOperationUpgrade,
	}
	operationRaw, err := operationrun.MarshalConfig(operationrun.Operation{
		Type:    firmware.Type(),
		Code:    firmware.CodeString(),
		Payload: firmware,
	})
	require.NoError(t, err)

	return &operationrun.OperationRun{
		Name:              "firmware rollout",
		Selector:          selectorRaw,
		Options:           optionsRaw,
		OperationTemplate: operationRaw,
		OperationType:     firmware.Type(),
		OperationCode:     firmware.CodeString(),
	}
}

func testExecutionTargets(count int) []operation.RackExecutionTarget {
	targets := make([]operation.RackExecutionTarget, 0, count)
	for i := range count {
		id := i + 1
		targets = append(targets, operation.RackExecutionTarget{
			RackID: mustUUID(fmt.Sprintf("00000000-0000-0000-0000-%012d", id)),
			ComponentsByType: map[devicetypes.ComponentType][]uuid.UUID{
				devicetypes.ComponentTypeCompute: {
					mustUUID(fmt.Sprintf("10000000-0000-0000-0000-%012d", id)),
				},
			},
		})
	}
	return targets
}

func mustUUID(value string) uuid.UUID {
	id, err := uuid.Parse(value)
	if err != nil {
		panic(err)
	}
	return id
}

func targetPhaseIndexes(
	targets []*operationrun.OperationRunTarget,
) []int32 {
	indexes := make([]int32, 0, len(targets))
	for _, target := range targets {
		indexes = append(indexes, target.PhaseIndex)
	}
	return indexes
}

func targetSequenceIndexes(
	targets []*operationrun.OperationRunTarget,
) []int32 {
	indexes := make([]int32, 0, len(targets))
	for _, target := range targets {
		indexes = append(indexes, target.SequenceIndex)
	}
	return indexes
}
