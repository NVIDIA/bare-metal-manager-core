// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operation"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
)

func TestNewExecution(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	execution, err := NewExecution(uuid.New(), "notify", &NoopPlan{Reason: "test"}, now)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, execution.ID)
	require.Equal(t, ExecutionStatusPending, execution.Status)
	require.Zero(t, execution.Attempts)
	require.Equal(t, now, execution.CreatedAt)
	require.Equal(t, now, execution.UpdatedAt)
	require.NoError(t, execution.Validate())
}

func TestPlannedExecutionValidate(t *testing.T) {
	tests := map[string]struct {
		planned PlannedExecution
		wantErr string
	}{
		"valid": {
			planned: PlannedExecution{ActionName: "notify", ExecutionPlan: &NoopPlan{}},
		},
		"missing action name": {
			planned: PlannedExecution{ExecutionPlan: &NoopPlan{}},
			wantErr: "event rule action name is empty",
		},
		"missing execution plan": {
			planned: PlannedExecution{ActionName: "notify"},
			wantErr: "execution plan is required",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.planned.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestNewExecutionSkipsEmptySubmitTaskPlan(t *testing.T) {
	operationInfo := &operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationForcePowerOff,
	}
	info, err := operationInfo.Marshal()
	require.NoError(t, err)
	execution, err := NewExecution(
		uuid.New(),
		"power_off",
		&SubmitTaskPlan{
			Operation: operation.Wrapper{
				Type: operationInfo.Type(),
				Code: operationInfo.CodeString(),
				Info: info,
			},
			ConflictStrategy: operation.ConflictStrategyReject,
		},
		time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
	)
	require.NoError(t, err)
	require.Equal(t, ExecutionStatusSkipped, execution.Status)
	require.Equal(t, ExecutionReasonNoTargets, execution.Reason)
	require.Zero(t, execution.Attempts)
	require.NoError(t, execution.Validate())
}

func TestExecutionTransitionTo(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	execution, err := NewExecution(uuid.New(), "notify", &NoopPlan{}, now)
	require.NoError(t, err)

	retryAt := now.Add(time.Second)
	require.NoError(t, execution.TransitionTo(
		DeferredExecutionResult(ExecutionReasonAttemptFailed, "temporary", time.Minute),
		retryAt,
	))
	require.Equal(t, ExecutionStatusDeferred, execution.Status)
	require.Equal(t, 1, execution.Attempts)
	require.Equal(t, retryAt.Add(time.Minute), execution.NextAttemptAt)

	completedAt := retryAt.Add(time.Second)
	require.NoError(t, execution.TransitionTo(CompletedExecutionResult(), completedAt))
	require.Equal(t, ExecutionStatusCompleted, execution.Status)
	require.Equal(t, 2, execution.Attempts)
	require.True(t, execution.NextAttemptAt.IsZero())
	require.ErrorContains(
		t,
		execution.TransitionTo(FailedExecutionResult("late"), completedAt.Add(time.Second)),
		"cannot transition",
	)
}

func TestExecutionValidate(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	valid, err := NewExecution(uuid.New(), "notify", &NoopPlan{}, now)
	require.NoError(t, err)
	tests := map[string]struct {
		mutate  func(*Execution)
		wantErr string
	}{
		"valid": {},
		"missing id": {
			mutate:  func(execution *Execution) { execution.ID = uuid.Nil },
			wantErr: "execution id is required",
		},
		"missing event": {
			mutate:  func(execution *Execution) { execution.EventID = uuid.Nil },
			wantErr: "execution event id is required",
		},
		"missing action": {
			mutate:  func(execution *Execution) { execution.ActionName = "" },
			wantErr: "event rule action name is empty",
		},
		"missing plan": {
			mutate:  func(execution *Execution) { execution.Plan = nil },
			wantErr: "execution plan is required",
		},
		"pending with attempt": {
			mutate:  func(execution *Execution) { execution.Attempts = 1 },
			wantErr: "pending execution cannot have attempts",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			execution := valid.Clone()
			if test.mutate != nil {
				test.mutate(&execution)
			}
			err := execution.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestExecutionResultValidate(t *testing.T) {
	tests := map[string]struct {
		result  ExecutionResult
		wantErr string
	}{
		"completed": {result: CompletedExecutionResult()},
		"skipped":   {result: SkippedExecutionResult(ExecutionReasonNoTargets)},
		"deferred":  {result: DeferredExecutionResult(ExecutionReasonAttemptFailed, "temporary", time.Second)},
		"failed":    {result: FailedExecutionResult("terminal")},
		"pending result": {
			result:  ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
			wantErr: "pending is not an execution result",
		},
		"negative retry": {
			result:  DeferredExecutionResult(ExecutionReasonAttemptFailed, "temporary", -time.Second),
			wantErr: "cannot be negative",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.result.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestExecutionTask_Validate(t *testing.T) {
	valid := ExecutionTask{
		ExecutionID: uuid.New(),
		RackID:      uuid.New(),
		TaskID:      uuid.New(),
	}

	tests := map[string]struct {
		association ExecutionTask
		mutate      func(*ExecutionTask)
		wantErr     string
	}{
		"valid": {association: valid},
		"missing execution": {
			association: valid,
			mutate:      func(a *ExecutionTask) { a.ExecutionID = uuid.Nil },
			wantErr:     "execution id is required",
		},
		"missing rack": {
			association: valid,
			mutate:      func(a *ExecutionTask) { a.RackID = uuid.Nil },
			wantErr:     "rack id is required",
		},
		"missing task": {
			association: valid,
			mutate:      func(a *ExecutionTask) { a.TaskID = uuid.Nil },
			wantErr:     "task id is required",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			association := test.association

			if test.mutate != nil {
				test.mutate(&association)
			}

			err := association.Validate()

			if test.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, test.wantErr)
		})
	}
}
