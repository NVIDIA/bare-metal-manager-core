// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"context"
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

func TestExecution_Claim(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		updatedAt time.Time
		claimAt   time.Time
		wantErr   string
	}{
		"claimed": {
			claimAt: now.Add(time.Second),
		},
		"claim time before latest update": {
			updatedAt: now.Add(2 * time.Second),
			claimAt:   now.Add(time.Second),
			wantErr:   "execution claim time cannot precede update time",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			execution, err := NewExecution(uuid.New(), "notify", &NoopPlan{}, now)
			require.NoError(t, err)
			if !test.updatedAt.IsZero() {
				execution.UpdatedAt = test.updatedAt
			}

			before := execution.Clone()
			token := uuid.New()
			err = execution.Claim("scheduler-1", token, test.claimAt)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				require.Equal(t, before, *execution)

				return
			}

			require.NoError(t, err)
			require.Equal(t, ExecutionStatusRunning, execution.Status)
			require.Equal(t, 1, execution.Attempts)
			require.Equal(t, token, execution.ClaimToken)
			require.Equal(t, "scheduler-1", execution.ClaimOwner)
			require.True(t, execution.NextAttemptAt.IsZero())
			require.Equal(t, test.claimAt, execution.UpdatedAt)
			require.NoError(t, execution.Validate())

			require.ErrorContains(
				t,
				execution.Claim("scheduler-1", uuid.New(), now.Add(2*time.Second)),
				"cannot be claimed",
			)
		})
	}
}

func TestExecution_TransitionClaimedTo(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		result          ExecutionResult
		token           func(uuid.UUID) uuid.UUID
		claimAfter      time.Duration
		transitionAfter time.Duration
		want            ExecutionStatus
		wantAttempts    int
		wantErr         string
	}{
		"completed": {
			result:          CompletedExecutionResult(),
			transitionAfter: time.Second,
			want:            ExecutionStatusCompleted,
			wantAttempts:    1,
		},
		"deferred": {
			result:          DeferredExecutionResult(ExecutionReasonAttemptFailed, "temporary", time.Minute),
			transitionAfter: time.Second,
			want:            ExecutionStatusDeferred,
			wantAttempts:    1,
		},
		"interrupted": {
			result: DeferredExecutionResult(
				ExecutionReasonAttemptInterrupted,
				context.Canceled.Error(),
				time.Minute,
			),
			transitionAfter: time.Second,
			want:            ExecutionStatusDeferred,
		},
		"failed": {
			result:          FailedExecutionResult("terminal"),
			transitionAfter: time.Second,
			want:            ExecutionStatusFailed,
			wantAttempts:    1,
		},
		"stale token": {
			result:          CompletedExecutionResult(),
			token:           func(uuid.UUID) uuid.UUID { return uuid.New() },
			transitionAfter: time.Second,
			wantErr:         "execution claim lost",
		},
		"transition time before latest update": {
			result:          CompletedExecutionResult(),
			claimAfter:      2 * time.Second,
			transitionAfter: time.Second,
			wantErr:         "execution transition time cannot precede update time",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			execution, err := NewExecution(uuid.New(), "notify", &NoopPlan{}, now)
			require.NoError(t, err)

			claimToken := uuid.New()
			require.NoError(t, execution.Claim("scheduler-1", claimToken, now.Add(test.claimAfter)))
			before := execution.Clone()

			transitionToken := claimToken
			if test.token != nil {
				transitionToken = test.token(claimToken)
			}

			err = execution.TransitionClaimedTo(
				transitionToken,
				test.result,
				now.Add(test.transitionAfter),
			)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				require.Equal(t, before, *execution)

				return
			}

			require.NoError(t, err)
			require.Equal(t, test.want, execution.Status)
			require.Equal(t, test.wantAttempts, execution.Attempts)
			require.Equal(t, uuid.Nil, execution.ClaimToken)
			require.Empty(t, execution.ClaimOwner)
			require.NoError(t, execution.Validate())
		})
	}
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
		"running without claim token": {
			mutate: func(execution *Execution) {
				execution.ExecutionState = ExecutionState{
					ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusRunning},
				}
				execution.Attempts = 1
				execution.ClaimOwner = "scheduler-1"
			},
			wantErr: "running execution requires claim token",
		},
		"running with invalid claim owner": {
			mutate: func(execution *Execution) {
				execution.ExecutionState = ExecutionState{
					ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusRunning},
				}
				execution.Attempts = 1
				execution.ClaimToken = uuid.New()
			},
			wantErr: "execution claim owner is empty",
		},
		"non-running with claim token": {
			mutate:  func(execution *Execution) { execution.ClaimToken = uuid.New() },
			wantErr: "pending execution cannot have claim token",
		},
		"non-running with claim owner": {
			mutate:  func(execution *Execution) { execution.ClaimOwner = "scheduler-1" },
			wantErr: "pending execution cannot have claim owner",
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
		"deferred":  {result: DeferredExecutionResult(ExecutionReasonAttemptFailed, "temporary", time.Second)},
		"failed":    {result: FailedExecutionResult("terminal")},
		"pending result": {
			result:  ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
			wantErr: "pending is not an execution result",
		},
		"running result": {
			result:  ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusRunning}},
			wantErr: "running is not an execution result",
		},
		"skipped result": {
			result: ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{
				Status: ExecutionStatusSkipped,
				Reason: ExecutionReasonNoTargets,
			}},
			wantErr: "skipped is not an execution result",
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
