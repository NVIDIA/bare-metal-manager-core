// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestExecution_Validate(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	valid := Execution{
		ExecutionState: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
		ExecutionIdentity: ExecutionIdentity{
			EventID:  uuid.New(),
			RuleID:   uuid.New(),
			ActionID: "notify",
		},
		ID:           uuid.New(),
		Observations: 1,
		Attempts:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	tests := map[string]struct {
		execution *Execution
		mutate    func(*Execution)
		wantErr   string
	}{
		"valid pending": {execution: &valid},
		"nil":           {wantErr: "execution is nil"},
		"missing id": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.ID = uuid.Nil },
			wantErr:   "execution id is required",
		},
		"missing event id": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.EventID = uuid.Nil },
			wantErr:   "event id is required",
		},
		"missing rule id": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.RuleID = uuid.Nil },
			wantErr:   "event rule id is required",
		},
		"missing action id": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.ActionID = "" },
			wantErr:   "event rule action id is empty",
		},
		"zero observations": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.Observations = 0 },
			wantErr:   "execution observations must be positive",
		},
		"zero attempts": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.Attempts = 0 },
			wantErr:   "execution attempts must be positive",
		},
		"missing creation time": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.CreatedAt = time.Time{} },
			wantErr:   "execution creation time is required",
		},
		"missing updated time": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.UpdatedAt = time.Time{} },
			wantErr:   "execution updated time is required",
		},
		"updated before creation": {
			execution: &valid,
			mutate: func(execution *Execution) {
				execution.UpdatedAt = execution.CreatedAt.Add(-time.Second)
			},
			wantErr: "execution updated time cannot precede creation time",
		},
		"unknown status": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.Status = "unknown" },
			wantErr:   "unknown execution status",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var execution *Execution
			if test.execution != nil {
				copy := *test.execution
				execution = &copy
				if test.mutate != nil {
					test.mutate(execution)
				}
			}

			err := execution.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}

	t.Run("increments repeated deferred attempts", func(t *testing.T) {
		execution, err := NewExecution(ExecutionIdentity{
			EventID:  uuid.New(),
			RuleID:   uuid.New(),
			ActionID: "retry",
		}, now)
		require.NoError(t, err)

		result := DeferredExecutionResult(
			ExecutionReasonAttemptFailed,
			"retry",
			0,
		)
		require.NoError(t, execution.TransitionTo(result, now.Add(time.Second)))
		require.Equal(t, 1, execution.Attempts)

		require.NoError(t, execution.TransitionTo(result, now.Add(2*time.Second)))
		require.Equal(t, 2, execution.Attempts)

		require.NoError(t, execution.TransitionTo(result, now.Add(3*time.Second)))
		require.Equal(t, 3, execution.Attempts)

		require.NoError(t, execution.TransitionTo(
			CompletedExecutionResult(),
			now.Add(4*time.Second),
		))
		require.Equal(t, 4, execution.Attempts)
	})
}

func TestExecutionStatus_CanTransitionTo(t *testing.T) {
	tests := map[string]struct {
		from ExecutionStatus
		to   ExecutionStatus
		want bool
	}{
		"pending to completed": {
			from: ExecutionStatusPending,
			to:   ExecutionStatusCompleted,
			want: true,
		},
		"pending to deferred": {
			from: ExecutionStatusPending,
			to:   ExecutionStatusDeferred,
			want: true,
		},
		"deferred to completed": {
			from: ExecutionStatusDeferred,
			to:   ExecutionStatusCompleted,
			want: true,
		},
		"pending to pending": {
			from: ExecutionStatusPending,
			to:   ExecutionStatusPending,
		},
		"completed to failed": {
			from: ExecutionStatusCompleted,
			to:   ExecutionStatusFailed,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, test.want, test.from.CanTransitionTo(test.to))
		})
	}
}

func TestExecution_TransitionTo(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	zero := time.Time{}
	beforeCreation := now.Add(-time.Second)
	tests := map[string]struct {
		execution  *Execution
		result     ExecutionResult
		transition *time.Time
		wantErr    string
	}{
		"pending to completed": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
			},
			result: ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusCompleted}},
		},
		"deferred to completed": {
			execution: &Execution{
				ID: uuid.New(),
				ExecutionState: ExecutionState{
					ExecutionStatusDetails: ExecutionStatusDetails{
						Status: ExecutionStatusDeferred,
						Reason: ExecutionReasonAttemptFailed,
					},
					NextAttemptAt: now,
				},
			},
			result: ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusCompleted}},
		},
		"pending to deferred uses transition time": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
			},
			result: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusDeferred,
					Reason: ExecutionReasonAttemptFailed,
				},
				RetryAfter: time.Minute,
			},
		},
		"pending is not an result": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
			},
			result:  ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
			wantErr: "pending is not an execution result",
		},
		"terminal source": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusCompleted}},
			},
			result:  ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusFailed}},
			wantErr: "cannot transition",
		},
		"missing transition time": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
			},
			result:     ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusCompleted}},
			transition: &zero,
			wantErr:    "execution transition time is required",
		},
		"transition before creation": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
				CreatedAt:      now,
			},
			result:     ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusCompleted}},
			transition: &beforeCreation,
			wantErr:    "cannot precede creation time",
		},
		"nil execution": {
			result:  ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusCompleted}},
			wantErr: "execution is nil",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			transitionAt := now
			if test.transition != nil {
				transitionAt = *test.transition
			}
			err := test.execution.TransitionTo(test.result, transitionAt)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.result.Status, test.execution.Status)
			require.Equal(t, test.result.Reason, test.execution.Reason)
			require.Equal(t, test.result.StatusMessage, test.execution.StatusMessage)
			if test.result.Status == ExecutionStatusDeferred {
				require.Equal(t, transitionAt.Add(test.result.RetryAfter), test.execution.NextAttemptAt)
			} else {
				require.True(t, test.execution.NextAttemptAt.IsZero())
			}
			require.Equal(t, transitionAt, test.execution.UpdatedAt)
		})
	}
}

func TestExecutionState_Validate(t *testing.T) {
	nextAttemptAt := time.Now().Add(time.Minute)
	tests := map[string]struct {
		state   ExecutionState
		wantErr string
	}{
		"pending": {state: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}}},
		"skipped": {
			state: ExecutionState{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusSkipped,
					Reason: ExecutionReasonNoTargets,
				},
			},
		},
		"deferred": {
			state: ExecutionState{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status:        ExecutionStatusDeferred,
					Reason:        ExecutionReasonAttemptFailed,
					StatusMessage: "inventory unavailable",
				},
				NextAttemptAt: nextAttemptAt,
			},
		},
		"deferred after interrupted creator attempt": {
			state: ExecutionState{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusDeferred,
					Reason: ExecutionReasonAttemptInterrupted,
				},
				NextAttemptAt: nextAttemptAt,
			},
		},
		"submitted": {state: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusSubmitted}}},
		"completed": {state: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusCompleted}}},
		"failed":    {state: ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusFailed}}},
		"unknown status": {
			state:   ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: "unknown"}},
			wantErr: "unknown execution status",
		},
		"skipped without reason": {
			state:   ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusSkipped}},
			wantErr: "skipped execution requires one of reasons",
		},
		"deferred without next attempt": {
			state: ExecutionState{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusDeferred,
					Reason: ExecutionReasonAttemptFailed,
				},
			},
			wantErr: "deferred execution requires next attempt time",
		},
		"completed with next attempt": {
			state: ExecutionState{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusCompleted,
				},
				NextAttemptAt: nextAttemptAt,
			},
			wantErr: "completed execution cannot have next attempt time",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.state.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestExecutionResultConstructors(t *testing.T) {
	tests := map[string]struct {
		result ExecutionResult
		want   ExecutionResult
	}{
		"submitted": {
			result: SubmittedExecutionResult(),
			want: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusSubmitted,
				},
			},
		},
		"completed": {
			result: CompletedExecutionResult(),
			want: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusCompleted,
				},
			},
		},
		"skipped": {
			result: SkippedExecutionResult(ExecutionReasonNoTargets),
			want: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusSkipped,
					Reason: ExecutionReasonNoTargets,
				},
			},
		},
		"deferred": {
			result: DeferredExecutionResult(
				ExecutionReasonAttemptFailed,
				"downstream unavailable",
				time.Second,
			),
			want: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status:        ExecutionStatusDeferred,
					Reason:        ExecutionReasonAttemptFailed,
					StatusMessage: "downstream unavailable",
				},
				RetryAfter: time.Second,
			},
		},
		"failed": {
			result: FailedExecutionResult("invalid executor result"),
			want: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status:        ExecutionStatusFailed,
					StatusMessage: "invalid executor result",
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, test.want, test.result)
			require.NoError(t, test.result.Validate())
		})
	}
}

func TestExecutionResult_Validate(t *testing.T) {
	tests := map[string]struct {
		result  ExecutionResult
		wantErr string
	}{
		"completed": {result: ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusCompleted}}},
		"deferred": {
			result: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusDeferred,
					Reason: ExecutionReasonAttemptFailed,
				},
				RetryAfter: time.Second,
			},
		},
		"immediate deferred": {
			result: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusDeferred,
					Reason: ExecutionReasonAttemptInterrupted,
				},
			},
		},
		"pending": {
			result:  ExecutionResult{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}},
			wantErr: "pending is not an execution result",
		},
		"negative retry delay": {
			result: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusDeferred,
					Reason: ExecutionReasonAttemptFailed,
				},
				RetryAfter: -time.Second,
			},
			wantErr: "retry delay cannot be negative",
		},
		"terminal retry delay": {
			result: ExecutionResult{
				ExecutionStatusDetails: ExecutionStatusDetails{
					Status: ExecutionStatusCompleted,
				},
				RetryAfter: time.Second,
			},
			wantErr: "completed execution cannot have retry delay",
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

func TestExecutionState_RetryDue(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	state := ExecutionState{
		ExecutionStatusDetails: ExecutionStatusDetails{
			Status: ExecutionStatusDeferred,
			Reason: ExecutionReasonAttemptFailed,
		},
		NextAttemptAt: now,
	}
	require.False(t, state.RetryDue(now.Add(-time.Nanosecond)))
	require.True(t, state.RetryDue(now))
	require.False(t, (ExecutionState{ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusPending}}).RetryDue(now))
}

func TestExecution_TryDeduplicate(t *testing.T) {
	createdAt := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		dedupe     *Dedupe
		observedAt time.Time
		want       bool
	}{
		"nil deduplication policy": {observedAt: createdAt.Add(time.Second)},
		"within window": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: createdAt.Add(time.Second),
			want:       true,
		},
		"at window boundary": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: createdAt.Add(time.Minute),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			execution := Execution{
				CreatedAt:    createdAt,
				UpdatedAt:    createdAt,
				Observations: 1,
			}
			require.Equal(t, test.want, execution.TryDeduplicate(test.dedupe, test.observedAt))
			if test.want {
				require.Equal(t, 2, execution.Observations)
				require.Equal(t, test.observedAt, execution.UpdatedAt)
				return
			}
			require.Equal(t, 1, execution.Observations)
			require.Equal(t, createdAt, execution.UpdatedAt)
		})
	}

	t.Run("out-of-order observation preserves latest update time", func(t *testing.T) {
		updatedAt := createdAt.Add(30 * time.Second)
		execution := Execution{
			CreatedAt:    createdAt,
			UpdatedAt:    updatedAt,
			Observations: 1,
		}
		require.True(
			t,
			execution.TryDeduplicate(
				&Dedupe{Window: time.Minute},
				createdAt.Add(time.Second),
			),
		)
		require.Equal(t, 2, execution.Observations)
		require.Equal(t, updatedAt, execution.UpdatedAt)
	})
}

func TestExecutionIdentity(t *testing.T) {
	eventID := uuid.New()
	ruleID := uuid.New()
	identity := ExecutionIdentity{
		EventID:        eventID,
		RuleID:         ruleID,
		ActionID:       "notify",
		CorrelationKey: "incident-1",
	}

	t.Run("keys", func(t *testing.T) {
		require.Equal(t, ExecutionDeliveryKey{
			EventID:  eventID,
			RuleID:   ruleID,
			ActionID: "notify",
		}, identity.DeliveryKey())
		require.Equal(t, ExecutionSemanticKey{
			RuleID:         ruleID,
			ActionID:       "notify",
			CorrelationKey: "incident-1",
		}, identity.SemanticKey())
	})

	tests := map[string]struct {
		identity ExecutionIdentity
		wantErr  string
	}{
		"valid delivery": {
			identity: ExecutionIdentity{
				EventID:  eventID,
				RuleID:   ruleID,
				ActionID: "notify",
			},
		},
		"missing event id": {
			identity: ExecutionIdentity{RuleID: ruleID, ActionID: "notify"},
			wantErr:  "event id is required",
		},
		"missing rule id": {
			identity: ExecutionIdentity{EventID: eventID, ActionID: "notify"},
			wantErr:  "event rule id is required",
		},
		"missing action id": {
			identity: ExecutionIdentity{EventID: eventID, RuleID: ruleID},
			wantErr:  "event rule action id is empty",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.identity.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestNewExecution(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	identity := ExecutionIdentity{
		EventID:  uuid.New(),
		RuleID:   uuid.New(),
		ActionID: "notify",
	}

	t.Run("new pending execution", func(t *testing.T) {
		execution, err := NewExecution(identity, now)
		require.NoError(t, err)
		require.NotEqual(t, uuid.Nil, execution.ID)
		require.Equal(t, identity, execution.ExecutionIdentity)
		require.Equal(t, ExecutionStatusPending, execution.Status)
		require.Equal(t, 1, execution.Observations)
		require.Equal(t, 1, execution.Attempts)
		require.Equal(t, now, execution.CreatedAt)
		require.Equal(t, now, execution.UpdatedAt)
		require.NoError(t, execution.Validate())
	})

	t.Run("invalid identity", func(t *testing.T) {
		execution, err := NewExecution(ExecutionIdentity{}, now)
		require.Error(t, err)
		require.Nil(t, execution)
	})

	t.Run("missing store time", func(t *testing.T) {
		execution, err := NewExecution(identity, time.Time{})
		require.ErrorContains(t, err, "execution creation time is required")
		require.Nil(t, execution)
	})
}
