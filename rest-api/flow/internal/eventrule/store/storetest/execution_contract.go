// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
)

// EventExecutionStore is the combined persistence boundary exercised by this
// contract.
type EventExecutionStore interface {
	eventrule.EventPlanStore
	eventrule.ExecutionStore
}

// ExecutionFactory constructs an empty store whose authoritative clock reads
// the supplied time.
type ExecutionFactory func(*time.Time) EventExecutionStore

// RunExecutionContract executes the shared durable event, plan, and claim
// contract.
func RunExecutionContract(t *testing.T, factory ExecutionFactory) {
	t.Helper()

	t.Run("atomic event lifecycle", func(t *testing.T) { testAtomicEventLifecycle(t, factory) })
	t.Run("concurrent event deduplication", func(t *testing.T) {
		testConcurrentEventDeduplication(t, factory)
	})
	t.Run("execution claim lifecycle", func(t *testing.T) {
		testExecutionClaimLifecycle(t, factory)
	})
	t.Run("interrupted attempt refund", func(t *testing.T) {
		testInterruptedAttemptRefund(t, factory)
	})
	t.Run("execution claim limit", func(t *testing.T) {
		testExecutionClaimLimit(t, factory)
	})
	t.Run("ordered atomic plan commit", func(t *testing.T) {
		testOrderedAtomicPlanCommit(t, factory)
	})
	t.Run("concurrent claim fencing", func(t *testing.T) {
		testConcurrentClaimFencing(t, factory)
	})
}

func testInterruptedAttemptRefund(t *testing.T, factory ExecutionFactory) {
	t.Helper()

	ctx := context.Background()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	_, err := store.CommitEventPlan(ctx, newEventDefinition(), newEventPlan())
	require.NoError(t, err)

	claims, err := store.ClaimPendingExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-1",
		Limit: 1,
	})
	require.NoError(t, err)
	require.Len(t, claims, 1)

	first := claims[0]
	require.Equal(t, 1, first.Execution.Attempts)

	require.NoError(t, store.TransitionClaimedExecution(
		ctx,
		first.Execution.ID,
		first.Token,
		eventrule.DeferredExecutionResult(
			eventrule.ExecutionReasonAttemptInterrupted,
			context.Canceled.Error(),
			time.Minute,
		),
	))

	now = now.Add(time.Minute)
	claims, err = store.ClaimRetryExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-2",
		Limit: 1,
	})
	require.NoError(t, err)
	require.Len(t, claims, 1)

	second := claims[0]
	// The interrupted first claim was refunded before this claim allocated the
	// next attempt.
	require.Equal(t, 1, second.Execution.Attempts)
}

func testExecutionClaimLimit(t *testing.T, factory ExecutionFactory) {
	t.Helper()

	ctx := context.Background()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	definition := newEventDefinition()
	definition.EffectivePolicy.Actions = append(
		definition.EffectivePolicy.Actions,
		eventrule.Action{Name: "archive", Spec: &eventrule.Noop{Reason: "test"}},
	)
	plan := append(
		newEventPlan(),
		eventrule.PlannedExecution{
			ActionName:    "archive",
			ExecutionPlan: &eventrule.NoopPlan{Reason: "test"},
		},
	)

	created, err := store.CommitEventPlan(ctx, definition, plan)
	require.NoError(t, err)
	require.NotNil(t, created)

	first, err := store.ClaimPendingExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-1",
		Limit: 1,
	})
	require.NoError(t, err)
	require.Len(t, first, 1)
	requireValidClaims(t, first, "scheduler-1")

	second, err := store.ClaimPendingExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-1",
		Limit: 1,
	})
	require.NoError(t, err)
	require.Len(t, second, 1)
	requireValidClaims(t, second, "scheduler-1")
	require.NotEqual(t, first[0].Execution.ID, second[0].Execution.ID)
}

func testAtomicEventLifecycle(t *testing.T, factory ExecutionFactory) {
	t.Helper()

	ctx := context.Background()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	definition := newEventDefinition()
	plan := newEventPlan()

	missing, err := store.ObserveEvent(ctx, definition.Key)
	require.NoError(t, err)
	require.Nil(t, missing)

	created, err := store.CommitEventPlan(ctx, definition, plan)
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Equal(t, 1, created.Observations)
	require.Equal(t, now, created.CreatedAt)

	now = now.Add(time.Second)
	duplicate, err := store.CommitEventPlan(ctx, definition, plan)
	require.NoError(t, err)
	require.Nil(t, duplicate)

	observed, err := store.ObserveEvent(ctx, definition.Key)
	require.NoError(t, err)
	require.Equal(t, created.ID, observed.ID)
	require.Equal(t, 3, observed.Observations)
	require.Equal(t, now, observed.LastObservedAt)

	empty := newEventDefinition()
	empty.EffectivePolicy = eventrule.Policy{}
	created, err = store.CommitEventPlan(ctx, empty, nil)
	require.NoError(t, err)
	require.NotNil(t, created)

	claims, err := store.ClaimPendingExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-1",
		Limit: 10,
	})
	require.NoError(t, err)
	require.Len(t, claims, 1, "only the first event has a dispatchable execution")
	requireValidClaims(t, claims, "scheduler-1")
}

func testConcurrentEventDeduplication(t *testing.T, factory ExecutionFactory) {
	t.Helper()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	definition := newEventDefinition()
	plan := newEventPlan()

	const deliveries = 20

	var wg sync.WaitGroup
	results := make(chan *eventrule.Event, deliveries)
	errs := make(chan error, deliveries)
	for range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()

			created, err := store.CommitEventPlan(context.Background(), definition, plan)

			results <- created
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	insertions := 0
	for created := range results {
		if created != nil {
			insertions++
		}
	}
	for err := range errs {
		require.NoError(t, err)
	}

	require.Equal(t, 1, insertions)

	stored, err := store.ObserveEvent(context.Background(), definition.Key)
	require.NoError(t, err)
	require.Equal(t, deliveries+1, stored.Observations)

	claims, err := store.ClaimPendingExecutions(context.Background(), eventrule.ExecutionClaimRequest{
		Owner: "scheduler-1",
		Limit: deliveries,
	})
	require.NoError(t, err)
	require.Len(t, claims, 1)
	requireValidClaims(t, claims, "scheduler-1")
}

func testExecutionClaimLifecycle(t *testing.T, factory ExecutionFactory) {
	t.Helper()

	ctx := context.Background()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	_, err := store.CommitEventPlan(ctx, newEventDefinition(), newEventPlan())
	require.NoError(t, err)

	pending, err := store.ClaimPendingExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-1",
		Limit: 1,
	})
	require.NoError(t, err)
	require.Len(t, pending, 1)
	requireValidClaims(t, pending, "scheduler-1")

	first := pending[0]
	require.Equal(t, eventrule.ExecutionStatusRunning, first.Execution.Status)
	require.Equal(t, 1, first.Execution.Attempts)
	require.NoError(t, first.Validate())

	none, err := store.ClaimPendingExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-2",
		Limit: 1,
	})
	require.NoError(t, err)
	require.Empty(t, none)
	requireValidClaims(t, none, "scheduler-2")

	err = store.TransitionClaimedExecution(
		ctx,
		first.Execution.ID,
		first.Token,
		eventrule.DeferredExecutionResult(
			eventrule.ExecutionReasonAttemptFailed,
			"temporarily unavailable",
			time.Minute,
		),
	)
	require.NoError(t, err)

	none, err = store.ClaimRetryExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-2",
		Limit: 1,
	})
	require.NoError(t, err)
	require.Empty(t, none)
	requireValidClaims(t, none, "scheduler-2")

	now = now.Add(time.Minute)
	deferred, err := store.ClaimRetryExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-2",
		Limit: 1,
	})
	require.NoError(t, err)
	require.Len(t, deferred, 1)
	requireValidClaims(t, deferred, "scheduler-2")

	second := deferred[0]
	require.Equal(t, 2, second.Execution.Attempts)
	require.NotEqual(t, first.Token, second.Token)

	err = store.TransitionClaimedExecution(
		ctx,
		second.Execution.ID,
		first.Token,
		eventrule.CompletedExecutionResult(),
	)
	require.ErrorIs(t, err, eventrule.ErrExecutionClaimLost)

	require.NoError(t, store.TransitionClaimedExecution(
		ctx,
		second.Execution.ID,
		second.Token,
		eventrule.CompletedExecutionResult(),
	))
}

func testOrderedAtomicPlanCommit(t *testing.T, factory ExecutionFactory) {
	t.Helper()

	ctx := context.Background()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	definition := newEventDefinition()
	definition.EffectivePolicy.Actions = append(
		definition.EffectivePolicy.Actions,
		eventrule.Action{Name: "archive", Spec: &eventrule.Noop{Reason: "test"}},
	)

	reversed := []eventrule.PlannedExecution{
		{ActionName: "archive", ExecutionPlan: &eventrule.NoopPlan{Reason: "test"}},
		{ActionName: "notify", ExecutionPlan: &eventrule.NoopPlan{Reason: "test"}},
	}
	created, err := store.CommitEventPlan(ctx, definition, reversed)
	require.ErrorContains(t, err, `action name "archive", want "notify"`)
	require.Nil(t, created)

	missing, err := store.ObserveEvent(ctx, definition.Key)
	require.NoError(t, err)
	require.Nil(t, missing)

	planned := []eventrule.PlannedExecution{
		{ActionName: "notify", ExecutionPlan: &eventrule.NoopPlan{Reason: "test"}},
		{ActionName: "archive", ExecutionPlan: &eventrule.NoopPlan{Reason: "test"}},
	}
	created, err = store.CommitEventPlan(ctx, definition, planned)
	require.NoError(t, err)
	require.NotNil(t, created)

	claims, err := store.ClaimPendingExecutions(ctx, eventrule.ExecutionClaimRequest{
		Owner: "scheduler-1",
		Limit: 2,
	})
	require.NoError(t, err)
	require.Len(t, claims, 2)
	requireValidClaims(t, claims, "scheduler-1")
	require.ElementsMatch(t, []string{"notify", "archive"}, []string{
		claims[0].Execution.ActionName,
		claims[1].Execution.ActionName,
	})
}

func testConcurrentClaimFencing(t *testing.T, factory ExecutionFactory) {
	t.Helper()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	_, err := store.CommitEventPlan(context.Background(), newEventDefinition(), newEventPlan())
	require.NoError(t, err)

	const schedulers = 20

	var wg sync.WaitGroup
	type result struct {
		owner  string
		claims []eventrule.ClaimedExecution
	}
	results := make(chan result, schedulers)
	errs := make(chan error, schedulers)
	for range schedulers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			owner := "scheduler-" + uuid.NewString()
			claims, err := store.ClaimPendingExecutions(
				context.Background(),
				eventrule.ExecutionClaimRequest{
					Owner: owner,
					Limit: 1,
				},
			)

			results <- result{owner: owner, claims: claims}
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	claimed := 0
	for result := range results {
		requireValidClaims(t, result.claims, result.owner)
		claimed += len(result.claims)
	}
	for err := range errs {
		require.NoError(t, err)
	}

	require.Equal(t, 1, claimed)
}

func requireValidClaims(
	t *testing.T,
	claims []eventrule.ClaimedExecution,
	owner string,
) {
	t.Helper()

	for i := range claims {
		require.NoError(t, claims[i].Validate(), "claims[%d]", i)
		require.Equal(t, owner, claims[i].Execution.ClaimOwner, "claims[%d]", i)
	}
}

func newEventPlan() []eventrule.PlannedExecution {
	return []eventrule.PlannedExecution{{
		ActionName:    "notify",
		ExecutionPlan: &eventrule.NoopPlan{Reason: "test"},
	}}
}

func newEventDefinition() eventrule.Event {
	return eventrule.Event{
		Key:           eventrule.EventKey{SourceName: "test", SourceKey: uuid.NewString()},
		Type:          "test.event",
		Resource:      eventrule.ResourceIdentity{Kind: eventrule.ResourceKindRack, ID: uuid.New()},
		AppliedRuleID: uuid.New(),
		EffectivePolicy: eventrule.Policy{Actions: []eventrule.Action{
			{Name: "notify", Spec: &eventrule.Noop{Reason: "test"}},
		}},
		Summary: "Test event",
	}
}
