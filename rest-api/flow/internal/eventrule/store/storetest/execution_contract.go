// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// ExecutionFactory constructs an empty execution store.
type ExecutionFactory func() eventrule.ExecutionStore

// RunExecutionContract executes the shared execution store contract.
func RunExecutionContract(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	t.Run("claim and retry", func(t *testing.T) {
		testExecutionClaimAndRetry(t, factory)
	})
	t.Run("delivery deduplication", func(t *testing.T) {
		testExecutionDeliveryDeduplication(t, factory)
	})
	t.Run("semantic deduplication", func(t *testing.T) {
		testExecutionSemanticDeduplication(t, factory)
	})
	t.Run("semantic deduplication window expiry", func(t *testing.T) {
		testExecutionSemanticDedupeWindowExpiry(t, factory)
	})
	t.Run("transitions", func(t *testing.T) {
		testExecutionTransitions(t, factory)
	})
	t.Run("unknown execution transition", func(t *testing.T) {
		testUnknownExecutionTransition(t, factory)
	})
	t.Run("terminal execution is not owned", func(t *testing.T) {
		testExecutionOwnership(t, factory)
	})
}

func testUnknownExecutionTransition(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	execution, err := factory().Transition(
		context.Background(),
		uuid.New(),
		eventrule.ExecutionState{Status: eventrule.ExecutionStatusCompleted},
		time.Now(),
	)
	require.ErrorIs(t, err, eventrule.ErrExecutionNotFound)
	require.Nil(t, execution)
}

func testExecutionOwnership(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory()
	execution, err := store.Claim(ctx, newExecutionClaim(now))
	require.NoError(t, err)
	require.NotNil(t, execution)

	transitioned, err := store.Transition(ctx, execution.ID, eventrule.ExecutionState{
		Status: eventrule.ExecutionStatusCompleted,
	}, now)
	require.NoError(t, err)
	require.NotNil(t, transitioned)

	transitioned, err = store.Transition(ctx, execution.ID, eventrule.ExecutionState{
		Status: eventrule.ExecutionStatusFailed,
	}, now.Add(time.Second))
	require.ErrorContains(t, err, "is not owned")
	require.Nil(t, transitioned)
}

func testExecutionClaimAndRetry(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	ctx := context.Background()
	firstClaimedAt := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	nextAttemptAt := firstClaimedAt.Add(time.Minute)
	store := factory()
	claim := newExecutionClaim(firstClaimedAt)

	execution, err := store.Claim(ctx, claim)
	require.NoError(t, err)
	require.NotNil(t, execution)
	require.Equal(t, eventrule.ExecutionStatusClaimed, execution.Status)
	require.Equal(t, firstClaimedAt, execution.FirstClaimedAt)
	require.Equal(t, 1, execution.Observations)
	require.Equal(t, 1, execution.Attempts)

	_, err = store.Transition(ctx, execution.ID, eventrule.ExecutionState{
		Status:        eventrule.ExecutionStatusDeferred,
		Reason:        eventrule.ExecutionReasonAttemptFailed,
		StatusMessage: "inventory unavailable",
		NextAttemptAt: nextAttemptAt,
	}, firstClaimedAt.Add(time.Second))
	require.NoError(t, err)

	claim.Now = nextAttemptAt.Add(-time.Second)
	execution, err = store.Claim(ctx, claim)
	require.Nil(t, execution)
	require.ErrorIs(t, err, eventrule.ErrRetryScheduled)

	claim.Now = nextAttemptAt
	execution, err = store.Claim(ctx, claim)
	require.NoError(t, err)
	require.NotNil(t, execution)
	require.Equal(t, eventrule.ExecutionStatusClaimed, execution.Status)
	require.Equal(t, eventrule.ExecutionReasonNone, execution.Reason)
	require.Empty(t, execution.StatusMessage)
	require.True(t, execution.NextAttemptAt.IsZero())
	require.Equal(t, firstClaimedAt, execution.FirstClaimedAt)
	require.Equal(t, 3, execution.Observations)
	require.Equal(t, 2, execution.Attempts)
}

func testExecutionDeliveryDeduplication(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory()
	claim := newExecutionClaim(now)

	execution, err := store.Claim(ctx, claim)
	require.NoError(t, err)
	require.NotNil(t, execution)

	claim.Now = now.Add(time.Second)
	duplicate, err := store.Claim(ctx, claim)
	require.NoError(t, err)
	require.Nil(t, duplicate)

	transitioned, err := store.Transition(ctx, execution.ID, eventrule.ExecutionState{
		Status: eventrule.ExecutionStatusCompleted,
	}, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Equal(t, 2, transitioned.Observations)
}

func testExecutionSemanticDeduplication(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory()
	claim := newExecutionClaim(now)
	claim.CorrelationKey = "incident-1"
	claim.Dedupe = &eventrule.Dedupe{Window: time.Minute}

	execution, err := store.Claim(ctx, claim)
	require.NoError(t, err)
	require.NotNil(t, execution)

	claim.EventID = uuid.New()
	claim.Now = now.Add(time.Second)
	duplicate, err := store.Claim(ctx, claim)
	require.NoError(t, err)
	require.Nil(t, duplicate)

	transitioned, err := store.Transition(ctx, execution.ID, eventrule.ExecutionState{
		Status: eventrule.ExecutionStatusCompleted,
	}, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Equal(t, 2, transitioned.Observations)
}

func testExecutionSemanticDedupeWindowExpiry(
	t *testing.T,
	factory ExecutionFactory,
) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory()
	claim := newExecutionClaim(now)
	claim.CorrelationKey = "incident-1"
	claim.Dedupe = &eventrule.Dedupe{Window: time.Minute}

	first, err := store.Claim(ctx, claim)
	require.NoError(t, err)
	require.NotNil(t, first)

	claim.EventID = uuid.New()
	claim.Now = now.Add(claim.Dedupe.Window)
	second, err := store.Claim(ctx, claim)
	require.NoError(t, err)
	require.NotNil(t, second)
	require.NotEqual(t, first.ID, second.ID)
}

func testExecutionTransitions(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		state   eventrule.ExecutionState
		wantErr bool
	}{
		"invalid status": {
			state:   eventrule.ExecutionState{Status: "invalid"},
			wantErr: true,
		},
		"claimed is not a transition target": {
			state:   eventrule.ExecutionState{Status: eventrule.ExecutionStatusClaimed},
			wantErr: true,
		},
		"completed": {
			state: eventrule.ExecutionState{Status: eventrule.ExecutionStatusCompleted},
		},
		"skipped without reason": {
			state:   eventrule.ExecutionState{Status: eventrule.ExecutionStatusSkipped},
			wantErr: true,
		},
		"skipped": {
			state: eventrule.ExecutionState{
				Status: eventrule.ExecutionStatusSkipped,
				Reason: eventrule.ExecutionReasonNoTargets,
			},
		},
		"deferred without reason": {
			state: eventrule.ExecutionState{
				Status:        eventrule.ExecutionStatusDeferred,
				NextAttemptAt: now.Add(time.Minute),
			},
			wantErr: true,
		},
		"deferred without next attempt": {
			state: eventrule.ExecutionState{
				Status: eventrule.ExecutionStatusDeferred,
				Reason: eventrule.ExecutionReasonAttemptFailed,
			},
			wantErr: true,
		},
		"deferred": {
			state: eventrule.ExecutionState{
				Status:        eventrule.ExecutionStatusDeferred,
				Reason:        eventrule.ExecutionReasonAttemptFailed,
				NextAttemptAt: now.Add(time.Minute),
			},
		},
		"submitted": {
			state: eventrule.ExecutionState{Status: eventrule.ExecutionStatusSubmitted},
		},
		"failed": {
			state: eventrule.ExecutionState{Status: eventrule.ExecutionStatusFailed},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := factory()
			execution, err := store.Claim(ctx, newExecutionClaim(now))
			require.NoError(t, err)
			require.NotNil(t, execution)

			transitionAt := now.Add(time.Second)
			transitioned, err := store.Transition(
				ctx,
				execution.ID,
				test.state,
				transitionAt,
			)
			if test.wantErr {
				require.Error(t, err)
				require.Nil(t, transitioned)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.state, transitioned.ExecutionState)
			require.Equal(t, transitionAt, transitioned.UpdatedAt)
		})
	}
}

func newExecutionClaim(now time.Time) eventrule.ExecutionClaim {
	return eventrule.ExecutionClaim{
		EventID:  uuid.New(),
		RuleID:   uuid.New(),
		ActionID: "action",
		Now:      now,
	}
}
