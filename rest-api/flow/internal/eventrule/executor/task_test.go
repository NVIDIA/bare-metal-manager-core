// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package executor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operation"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

func TestTaskExecutorExecute(t *testing.T) {
	rackID := uuid.New()
	componentID := uuid.New()
	request := submitTaskExecutionRequest(t, rackID, componentID)
	manager := &recordingTaskManager{taskIDs: []uuid.UUID{uuid.New()}}
	associations := newExecutionTaskStore()
	executor := &TaskExecutor{manager: manager, associations: associations}

	require.NoError(t, executor.Execute(context.Background(), request))
	require.Len(t, manager.requests, 1)

	submitted := manager.requests[0]

	require.Equal(t, rackID, submitted.RequiredRackID)
	require.Equal(t, taskIdempotencyKey(request.ExecutionID, rackID), submitted.IdempotencyKey)
	require.Equal(t, operation.TargetSpec{
		Components: []operation.ComponentTarget{{UUID: componentID}},
	}, submitted.TargetSpec)

	// A retry reconciles the persisted association and does not resubmit.
	require.NoError(t, executor.Execute(context.Background(), request))
	require.Len(t, manager.requests, 1)
}

func TestTaskExecutorClassifiesFailures(t *testing.T) {
	request := submitTaskExecutionRequest(t, uuid.New(), uuid.New())
	tests := map[string]struct {
		manager        *recordingTaskManager
		associations   *memoryExecutionTaskStore
		mutate         func(*ExecutionRequest)
		wantErr        string
		classification error
	}{
		"submission failure is retryable": {
			manager:        &recordingTaskManager{err: errors.New("task service unavailable")},
			associations:   newExecutionTaskStore(),
			wantErr:        "task service unavailable",
			classification: ErrRetryable,
		},
		"invalid task count is terminal": {
			manager:        &recordingTaskManager{},
			associations:   newExecutionTaskStore(),
			wantErr:        "exactly one valid task id",
			classification: ErrTerminal,
		},
		"wrong plan is terminal": {
			manager:      &recordingTaskManager{},
			associations: newExecutionTaskStore(),
			mutate: func(request *ExecutionRequest) {
				request.Plan = &eventrule.NoopPlan{}
			},
			wantErr:        "received plan",
			classification: ErrTerminal,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			input := request
			input.Plan = eventrule.CloneExecutionPlan(request.Plan)

			if test.mutate != nil {
				test.mutate(&input)
			}

			executor := &TaskExecutor{
				manager:      test.manager,
				associations: test.associations,
			}

			err := executor.Execute(context.Background(), input)

			require.ErrorContains(t, err, test.wantErr)
			require.ErrorIs(t, err, test.classification)
		})
	}
}

func submitTaskExecutionRequest(
	t *testing.T,
	rackID uuid.UUID,
	componentID uuid.UUID,
) ExecutionRequest {
	t.Helper()

	operationInfo := &operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationForcePowerOff,
	}

	info, err := operationInfo.Marshal()
	require.NoError(t, err)

	execution, err := eventrule.NewExecution(
		uuid.New(),
		"power_off",
		&eventrule.SubmitTaskPlan{
			Operation: operation.Wrapper{
				Type: taskcommon.TaskTypePowerControl,
				Code: operationInfo.CodeString(),
				Info: info,
			},
			Description:      "Power off affected component",
			ConflictStrategy: operation.ConflictStrategyQueue,
			Targets: []operation.RackExecutionTarget{{
				RackID: rackID,
				ComponentsByType: operation.ComponentsByType{
					devicetypes.ComponentTypeCompute: []uuid.UUID{componentID},
				},
			}},
		},
		testTime,
	)
	require.NoError(t, err)

	return ExecutionRequest{
		ExecutionID: execution.ID,
		Plan:        execution.Plan,
	}
}

var testTime = mustTestTime()

func mustTestTime() time.Time {
	return time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
}

type recordingTaskManager struct {
	requests []*operation.Request
	taskIDs  []uuid.UUID
	err      error
}

func (m *recordingTaskManager) SubmitTask(
	_ context.Context,
	request *operation.Request,
) ([]uuid.UUID, error) {
	m.requests = append(m.requests, request)

	return m.taskIDs, m.err
}

type memoryExecutionTaskStore struct {
	mu      sync.Mutex
	records map[string]eventrule.ExecutionTask
}

func newExecutionTaskStore() *memoryExecutionTaskStore {
	return &memoryExecutionTaskStore{records: make(map[string]eventrule.ExecutionTask)}
}

func (s *memoryExecutionTaskStore) GetExecutionTask(
	_ context.Context,
	executionID uuid.UUID,
	rackID uuid.UUID,
) (*eventrule.ExecutionTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[executionID.String()+":"+rackID.String()]
	if !ok {
		return nil, nil
	}

	return &record, nil
}

func (s *memoryExecutionTaskStore) CreateExecutionTask(
	_ context.Context,
	association eventrule.ExecutionTask,
) (*eventrule.ExecutionTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := association.ExecutionID.String() + ":" + association.RackID.String()

	if existing, ok := s.records[key]; ok {
		return &existing, nil
	}

	s.records[key] = association

	return &association, nil
}
