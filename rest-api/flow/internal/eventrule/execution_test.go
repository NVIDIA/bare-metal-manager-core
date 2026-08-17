// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestExecution_Validate(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	valid := Execution{
		ExecutionState: ExecutionState{Status: ExecutionStatusClaimed},
		ID:             uuid.New(), EventID: uuid.New(), RuleID: uuid.New(), ActionID: "notify",
		Observations: 1, Attempts: 1,
		FirstClaimedAt: now, UpdatedAt: now,
	}
	tests := map[string]struct {
		execution *Execution
		mutate    func(*Execution)
		wantErr   string
	}{
		"valid claimed": {execution: &valid},
		"nil":           {wantErr: "event action execution is nil"},
		"claimed with status message": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.StatusMessage = "unexpected" },
		},
		"missing id": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.ID = uuid.Nil },
			wantErr:   "event action execution id is required",
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
		"missing first claimed time": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.FirstClaimedAt = time.Time{} },
			wantErr:   "execution first claimed time is required",
		},
		"missing updated time": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.UpdatedAt = time.Time{} },
			wantErr:   "execution updated time is required",
		},
		"updated before first claim": {
			execution: &valid,
			mutate: func(execution *Execution) {
				execution.UpdatedAt = execution.FirstClaimedAt.Add(-time.Second)
			},
			wantErr: "execution updated time cannot precede first claimed time",
		},
		"skipped without reason": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.Status = ExecutionStatusSkipped },
			wantErr:   "skipped execution requires one of reasons",
		},
		"deferred without status message": {
			execution: &valid,
			mutate: func(execution *Execution) {
				execution.Status = ExecutionStatusDeferred
				execution.Reason = ExecutionReasonAttemptFailed
				execution.NextAttemptAt = now.Add(time.Minute)
			},
		},
		"failed without status message": {
			execution: &valid,
			mutate:    func(execution *Execution) { execution.Status = ExecutionStatusFailed },
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
				mutated := *test.execution
				execution = &mutated
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
}

func TestExecution_IsOwned(t *testing.T) {
	tests := map[string]struct {
		status ExecutionStatus
		want   bool
	}{
		"claimed": {
			status: ExecutionStatusClaimed,
			want:   true,
		},
		"deferred": {
			status: ExecutionStatusDeferred,
		},
		"completed": {
			status: ExecutionStatusCompleted,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			execution := Execution{
				ExecutionState: ExecutionState{Status: test.status},
			}
			require.Equal(t, test.want, execution.IsOwned())
		})
	}
}

func TestExecutionState_ValidateTransition(t *testing.T) {
	tests := map[string]struct {
		state   ExecutionState
		wantErr string
	}{
		"completed": {
			state: ExecutionState{Status: ExecutionStatusCompleted},
		},
		"claimed": {
			state:   ExecutionState{Status: ExecutionStatusClaimed},
			wantErr: "cannot transition execution to claimed status",
		},
		"invalid state": {
			state:   ExecutionState{Status: ExecutionStatusSkipped},
			wantErr: "skipped execution requires one of reasons",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.state.ValidateTransition()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestExecutionStatus_CanTransitionTo(t *testing.T) {
	tests := map[string]struct {
		from ExecutionStatus
		to   ExecutionStatus
		want bool
	}{
		"claimed to submitted": {
			from: ExecutionStatusClaimed,
			to:   ExecutionStatusSubmitted,
			want: true,
		},
		"claimed to completed": {
			from: ExecutionStatusClaimed,
			to:   ExecutionStatusCompleted,
			want: true,
		},
		"claimed to skipped": {
			from: ExecutionStatusClaimed,
			to:   ExecutionStatusSkipped,
			want: true,
		},
		"claimed to deferred": {
			from: ExecutionStatusClaimed,
			to:   ExecutionStatusDeferred,
			want: true,
		},
		"claimed to failed": {
			from: ExecutionStatusClaimed,
			to:   ExecutionStatusFailed,
			want: true,
		},
		"claimed to claimed": {
			from: ExecutionStatusClaimed,
			to:   ExecutionStatusClaimed,
		},
		"completed to claimed": {
			from: ExecutionStatusCompleted,
			to:   ExecutionStatusClaimed,
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
	beforeFirstClaim := now.Add(-time.Second)
	tests := map[string]struct {
		execution  *Execution
		state      ExecutionState
		transition *time.Time
		wantErr    string
	}{
		"completed": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{Status: ExecutionStatusClaimed},
			},
			state: ExecutionState{Status: ExecutionStatusCompleted},
		},
		"invalid target state": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{Status: ExecutionStatusClaimed},
			},
			state:   ExecutionState{Status: ExecutionStatusSkipped},
			wantErr: "skipped execution requires one of reasons",
		},
		"missing transition time": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{Status: ExecutionStatusClaimed},
			},
			state:      ExecutionState{Status: ExecutionStatusCompleted},
			transition: &zero,
			wantErr:    "execution transition time is required",
		},
		"transition before first claim": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{Status: ExecutionStatusClaimed},
				FirstClaimedAt: now,
			},
			state:      ExecutionState{Status: ExecutionStatusCompleted},
			transition: &beforeFirstClaim,
			wantErr:    "execution transition time cannot precede first claimed time",
		},
		"target with stale next attempt": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{Status: ExecutionStatusClaimed},
			},
			state: ExecutionState{
				Status:        ExecutionStatusCompleted,
				NextAttemptAt: now.Add(time.Minute),
			},
			wantErr: "completed execution cannot have next attempt time",
		},
		"not owned": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{Status: ExecutionStatusCompleted},
			},
			state:   ExecutionState{Status: ExecutionStatusFailed},
			wantErr: "is not owned",
		},
		"not owned with invalid target": {
			execution: &Execution{
				ID:             uuid.New(),
				ExecutionState: ExecutionState{Status: ExecutionStatusCompleted},
			},
			state:   ExecutionState{Status: ExecutionStatusClaimed},
			wantErr: "is not owned",
		},
		"nil execution": {
			state:   ExecutionState{Status: ExecutionStatusCompleted},
			wantErr: "event action execution is nil",
		},
		"nil execution with invalid target": {
			state:   ExecutionState{Status: ExecutionStatusClaimed},
			wantErr: "event action execution is nil",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			transitionAt := now
			if test.transition != nil {
				transitionAt = *test.transition
			}
			err := test.execution.TransitionTo(test.state, transitionAt)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.state, test.execution.ExecutionState)
			require.Equal(t, transitionAt, test.execution.UpdatedAt)
		})
	}
}

func TestExecution_TryClaim(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	nextAttemptAt := now.Add(time.Minute)
	tests := map[string]struct {
		execution     *Execution
		now           time.Time
		wantExecution bool
		wantErr       error
	}{
		"due deferred execution": {
			execution: &Execution{
				ExecutionState: ExecutionState{
					Status:        ExecutionStatusDeferred,
					Reason:        ExecutionReasonAttemptFailed,
					NextAttemptAt: nextAttemptAt,
				},
				Observations: 1,
				Attempts:     1,
			},
			now:           nextAttemptAt,
			wantExecution: true,
		},
		"deferred execution not due": {
			execution: &Execution{
				ExecutionState: ExecutionState{
					Status:        ExecutionStatusDeferred,
					Reason:        ExecutionReasonAttemptFailed,
					NextAttemptAt: nextAttemptAt,
				},
				Observations: 1,
				Attempts:     1,
			},
			now:     now,
			wantErr: ErrRetryScheduled,
		},
		"existing claimed execution": {
			execution: &Execution{
				ExecutionState: ExecutionState{Status: ExecutionStatusClaimed},
				Observations:   1,
				Attempts:       1,
			},
			now: now,
		},
		"nil execution": {
			now:     now,
			wantErr: errors.New("event action execution is nil"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := test.execution.TryClaim(test.now)
			if test.wantExecution {
				require.Same(t, test.execution, result)
			} else {
				require.Nil(t, result)
			}
			if test.wantErr != nil {
				require.ErrorContains(t, err, test.wantErr.Error())
				if errors.Is(test.wantErr, ErrRetryScheduled) {
					require.ErrorIs(t, err, ErrRetryScheduled)
				}
			} else {
				require.NoError(t, err)
			}
			if test.execution == nil {
				return
			}
			require.Equal(t, 2, test.execution.Observations)
			require.Equal(t, test.now, test.execution.UpdatedAt)
			if test.wantExecution {
				require.Equal(t, ExecutionStatusClaimed, test.execution.Status)
				require.Equal(t, 2, test.execution.Attempts)
			}
		})
	}
}

func TestExecution_TryDeduplicate(t *testing.T) {
	firstClaimedAt := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		dedupe     *Dedupe
		observedAt time.Time
		want       bool
	}{
		"nil deduplication policy": {
			observedAt: firstClaimedAt.Add(time.Second),
		},
		"within window": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: firstClaimedAt.Add(time.Second),
			want:       true,
		},
		"at window boundary": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: firstClaimedAt.Add(time.Minute),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			execution := Execution{
				FirstClaimedAt: firstClaimedAt,
				UpdatedAt:      firstClaimedAt,
				Observations:   1,
			}

			require.Equal(
				t,
				test.want,
				execution.TryDeduplicate(test.dedupe, test.observedAt),
			)
			if test.want {
				require.Equal(t, 2, execution.Observations)
				require.Equal(t, test.observedAt, execution.UpdatedAt)
				return
			}
			require.Equal(t, 1, execution.Observations)
			require.Equal(t, firstClaimedAt, execution.UpdatedAt)
		})
	}
}

func TestNewExecutionClaim(t *testing.T) {
	eventID := uuid.New()
	ruleID := uuid.New()
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		envelope    Envelope
		rule        Rule
		actionID    string
		now         time.Time
		want        ExecutionClaim
		wantMessage string
	}{
		"delivery identity without semantic dedupe": {
			envelope: Envelope{ID: eventID, CorrelationKey: "unused"},
			rule:     Rule{ID: ruleID},
			actionID: "notify",
			now:      now,
			want: ExecutionClaim{
				EventID:        eventID,
				RuleID:         ruleID,
				ActionID:       "notify",
				CorrelationKey: "unused",
				Now:            now,
			},
		},
		"semantic dedupe identity": {
			envelope: Envelope{ID: eventID, CorrelationKey: "incident-1"},
			rule: Rule{
				ID:     ruleID,
				Policy: Policy{Dedupe: &Dedupe{Window: time.Minute}},
			},
			actionID: "notify",
			now:      now,
			want: ExecutionClaim{
				EventID:        eventID,
				RuleID:         ruleID,
				ActionID:       "notify",
				CorrelationKey: "incident-1",
				Dedupe:         &Dedupe{Window: time.Minute},
				Now:            now,
			},
		},
		"missing event id": {
			rule:        Rule{ID: ruleID},
			actionID:    "notify",
			now:         now,
			wantMessage: "event id is required",
		},
		"missing rule id": {
			envelope:    Envelope{ID: eventID},
			actionID:    "notify",
			now:         now,
			wantMessage: "event rule id is required",
		},
		"missing action id": {
			envelope:    Envelope{ID: eventID},
			rule:        Rule{ID: ruleID},
			now:         now,
			wantMessage: "event rule action id is empty",
		},
		"missing claim time": {
			envelope:    Envelope{ID: eventID},
			rule:        Rule{ID: ruleID},
			actionID:    "notify",
			wantMessage: "execution claim time is required",
		},
		"dedupe requires correlation key": {
			envelope: Envelope{ID: eventID},
			rule: Rule{
				ID:     ruleID,
				Policy: Policy{Dedupe: &Dedupe{Window: time.Minute}},
			},
			actionID:    "notify",
			now:         now,
			wantMessage: "correlation key is required",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			claim, err := NewExecutionClaim(
				test.envelope,
				test.rule,
				test.actionID,
				test.now,
			)
			if test.wantMessage != "" {
				require.ErrorContains(t, err, test.wantMessage)
				require.Equal(t, ExecutionClaim{}, claim)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.want, claim)
		})
	}
}

func TestExecutionClaim_Validate(t *testing.T) {
	valid := ExecutionClaim{
		EventID:  uuid.New(),
		RuleID:   uuid.New(),
		ActionID: "notify",
		Now:      time.Now(),
	}
	tests := map[string]struct {
		mutate  func(*ExecutionClaim)
		wantErr string
	}{
		"valid delivery claim": {},
		"valid semantic dedupe claim": {
			mutate: func(claim *ExecutionClaim) {
				claim.CorrelationKey = "incident-1"
				claim.Dedupe = &Dedupe{Window: time.Minute}
			},
		},
		"negative dedupe window": {
			mutate:  func(claim *ExecutionClaim) { claim.Dedupe = &Dedupe{Window: -time.Second} },
			wantErr: "dedupe window must be positive",
		},
		"dedupe without correlation key": {
			mutate:  func(claim *ExecutionClaim) { claim.Dedupe = &Dedupe{Window: time.Minute} },
			wantErr: "correlation key is required",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			claim := valid
			if test.mutate != nil {
				test.mutate(&claim)
			}
			err := claim.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestExecutionClaim_DeliveryKey(t *testing.T) {
	claim := ExecutionClaim{
		EventID:  uuid.New(),
		RuleID:   uuid.New(),
		ActionID: "notify",
	}
	require.Equal(t, ExecutionDeliveryKey{
		EventID:  claim.EventID,
		RuleID:   claim.RuleID,
		ActionID: claim.ActionID,
	}, claim.DeliveryKey())
}

func TestExecutionClaim_SemanticKey(t *testing.T) {
	claim := ExecutionClaim{
		RuleID:         uuid.New(),
		ActionID:       "notify",
		CorrelationKey: "incident-1",
	}

	require.Equal(t, ExecutionSemanticKey{
		RuleID:         claim.RuleID,
		ActionID:       claim.ActionID,
		CorrelationKey: claim.CorrelationKey,
	}, claim.SemanticKey())
}

func TestExecutionClaim_NewExecution(t *testing.T) {
	t.Run("invalid claim", func(t *testing.T) {
		invalid, err := (ExecutionClaim{}).NewExecution()
		require.Error(t, err)
		require.Nil(t, invalid)
	})

	t.Run("valid claim", func(t *testing.T) {
		now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
		claim := ExecutionClaim{
			EventID:        uuid.New(),
			RuleID:         uuid.New(),
			ActionID:       "notify",
			CorrelationKey: "incident-1",
			Now:            now,
		}

		execution, err := claim.NewExecution()
		require.NoError(t, err)
		require.NotEqual(t, uuid.Nil, execution.ID)
		require.Equal(t, claim.EventID, execution.EventID)
		require.Equal(t, claim.RuleID, execution.RuleID)
		require.Equal(t, claim.ActionID, execution.ActionID)
		require.Equal(t, claim.CorrelationKey, execution.CorrelationKey)
		require.Equal(t, ExecutionStatusClaimed, execution.Status)
		require.Equal(t, 1, execution.Observations)
		require.Equal(t, 1, execution.Attempts)
		require.Equal(t, now, execution.FirstClaimedAt)
		require.Equal(t, now, execution.UpdatedAt)
		require.NoError(t, execution.Validate())
	})
}

func TestExecutionState_Validate(t *testing.T) {
	nextAttemptAt := time.Now().Add(time.Minute)
	tests := map[string]struct {
		state   ExecutionState
		wantErr string
	}{
		"skipped": {
			state: ExecutionState{
				Status: ExecutionStatusSkipped,
				Reason: ExecutionReasonNoTargets,
			},
		},
		"deferred": {
			state: ExecutionState{
				Status:        ExecutionStatusDeferred,
				Reason:        ExecutionReasonAttemptFailed,
				StatusMessage: "inventory unavailable",
				NextAttemptAt: nextAttemptAt,
			},
		},
		"submitted": {
			state: ExecutionState{Status: ExecutionStatusSubmitted},
		},
		"completed": {
			state: ExecutionState{
				Status:        ExecutionStatusCompleted,
				StatusMessage: "action completed",
			},
		},
		"failed": {
			state: ExecutionState{
				Status:        ExecutionStatusFailed,
				StatusMessage: "invalid target",
			},
		},
		"unknown status": {
			state:   ExecutionState{Status: "unknown"},
			wantErr: "unknown execution status",
		},
		"skipped without reason": {
			state:   ExecutionState{Status: ExecutionStatusSkipped},
			wantErr: "skipped execution requires one of reasons",
		},
		"deferred without next attempt": {
			state: ExecutionState{
				Status:        ExecutionStatusDeferred,
				Reason:        ExecutionReasonAttemptFailed,
				StatusMessage: "inventory unavailable",
			},
			wantErr: "deferred execution requires next attempt time",
		},
		"completed with next attempt": {
			state: ExecutionState{
				Status:        ExecutionStatusCompleted,
				NextAttemptAt: nextAttemptAt,
			},
			wantErr: "completed execution cannot have next attempt time",
		},
		"submitted with next attempt": {
			state: ExecutionState{
				Status:        ExecutionStatusSubmitted,
				NextAttemptAt: nextAttemptAt,
			},
			wantErr: "submitted execution cannot have next attempt time",
		},
		"failed with next attempt": {
			state: ExecutionState{
				Status:        ExecutionStatusFailed,
				NextAttemptAt: nextAttemptAt,
			},
			wantErr: "failed execution cannot have next attempt time",
		},
		"failed without status message": {
			state: ExecutionState{Status: ExecutionStatusFailed},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.state.Validate()
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestExecutionState_RetryDue(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		state ExecutionState
		want  bool
	}{
		"deferred before retry time": {
			state: ExecutionState{
				Status:        ExecutionStatusDeferred,
				NextAttemptAt: now.Add(time.Second),
			},
		},
		"deferred at retry time": {
			state: ExecutionState{
				Status:        ExecutionStatusDeferred,
				NextAttemptAt: now,
			},
			want: true,
		},
		"deferred after retry time": {
			state: ExecutionState{
				Status:        ExecutionStatusDeferred,
				NextAttemptAt: now.Add(-time.Second),
			},
			want: true,
		},
		"deferred without retry time": {
			state: ExecutionState{Status: ExecutionStatusDeferred},
		},
		"completed": {
			state: ExecutionState{
				Status:        ExecutionStatusCompleted,
				NextAttemptAt: now,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, test.want, test.state.RetryDue(now))
		})
	}
}
