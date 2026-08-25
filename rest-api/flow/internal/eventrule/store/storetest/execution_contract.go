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
	eventrule.EventStore
	eventrule.ExecutionStore
}

// ExecutionFactory constructs an empty store whose authoritative clock reads
// the supplied time.
type ExecutionFactory func(*time.Time) EventExecutionStore

// RunExecutionContract executes the shared durable event and execution-plan
// contract.
func RunExecutionContract(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	t.Run("event lifecycle", func(t *testing.T) { testEventLifecycle(t, factory) })
	t.Run("concurrent event deduplication", func(t *testing.T) {
		testConcurrentEventDeduplication(t, factory)
	})
	t.Run("execution planning and transition", func(t *testing.T) {
		testExecutionLifecycle(t, factory)
	})
	t.Run("ordered atomic plan commit", func(t *testing.T) {
		testOrderedAtomicPlanCommit(t, factory)
	})
}

func testEventLifecycle(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	definition := newEventDefinition()

	missing, err := store.ObserveEvent(ctx, definition.Key)
	require.NoError(t, err)
	require.Nil(t, missing)

	created, err := store.CreateEvent(ctx, definition)
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Equal(t, 1, created.Observations)
	require.Nil(t, created.PlannedAt)

	now = now.Add(time.Second)
	observed, err := store.ObserveEvent(ctx, definition.Key)
	require.NoError(t, err)
	require.Equal(t, created.ID, observed.ID)
	require.Equal(t, 2, observed.Observations)
	require.Equal(t, now, observed.LastObservedAt)

	plan := []eventrule.PlannedExecution{{
		ActionName:    "notify",
		ExecutionPlan: &eventrule.NoopPlan{Reason: "test"},
	}}
	committed, err := store.CommitEventPlan(ctx, created.ID, plan)
	require.NoError(t, err)
	require.Len(t, committed, 1)
	planned, err := store.ObserveEvent(ctx, definition.Key)
	require.NoError(t, err)
	require.Equal(t, now, *planned.PlannedAt)
	_, err = store.CommitEventPlan(ctx, created.ID, plan)
	require.ErrorIs(t, err, eventrule.ErrEventAlreadyPlanned)
}

func testConcurrentEventDeduplication(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	definition := newEventDefinition()
	const deliveries = 20

	var wg sync.WaitGroup
	results := make(chan *eventrule.Event, deliveries)
	errs := make(chan error, deliveries)
	for range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := store.CreateEvent(context.Background(), definition)
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
}

func testExecutionLifecycle(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	event, err := store.CreateEvent(ctx, newEventDefinition())
	require.NoError(t, err)
	require.NotNil(t, event)

	committed, err := store.CommitEventPlan(
		ctx,
		event.ID,
		[]eventrule.PlannedExecution{{
			ActionName:    "notify",
			ExecutionPlan: &eventrule.NoopPlan{Reason: "test"},
		}},
	)
	require.NoError(t, err)
	require.Len(t, committed, 1)
	created := committed[0]
	require.Equal(t, eventrule.ExecutionStatusPending, created.Status)
	require.Zero(t, created.Attempts)

	_, err = store.CommitEventPlan(
		ctx,
		event.ID,
		[]eventrule.PlannedExecution{{
			ActionName:    "notify",
			ExecutionPlan: &eventrule.NoopPlan{Reason: "different plan"},
		}},
	)
	require.ErrorIs(t, err, eventrule.ErrEventAlreadyPlanned)

	now = now.Add(time.Second)
	err = store.TransitionExecution(
		ctx,
		created.ID,
		eventrule.DeferredExecutionResult(
			eventrule.ExecutionReasonAttemptFailed,
			"temporarily unavailable",
			time.Minute,
		),
	)
	require.NoError(t, err)

	now = now.Add(time.Second)
	err = store.TransitionExecution(
		ctx,
		created.ID,
		eventrule.CompletedExecutionResult(),
	)
	require.NoError(t, err)
	err = store.TransitionExecution(
		ctx,
		created.ID,
		eventrule.FailedExecutionResult("late failure"),
	)
	require.Error(t, err)
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
	event, err := store.CreateEvent(ctx, definition)
	require.NoError(t, err)

	reversed := []eventrule.PlannedExecution{
		{ActionName: "archive", ExecutionPlan: &eventrule.NoopPlan{Reason: "test"}},
		{ActionName: "notify", ExecutionPlan: &eventrule.NoopPlan{Reason: "test"}},
	}
	_, err = store.CommitEventPlan(ctx, event.ID, reversed)
	require.ErrorContains(t, err, `action name "archive", want "notify"`)

	planned := []eventrule.PlannedExecution{
		{ActionName: "notify", ExecutionPlan: &eventrule.NoopPlan{Reason: "test"}},
		{ActionName: "archive", ExecutionPlan: &eventrule.NoopPlan{Reason: "test"}},
	}
	executions, err := store.CommitEventPlan(ctx, event.ID, planned)
	require.NoError(t, err)
	require.Equal(t, []string{"notify", "archive"}, []string{
		executions[0].ActionName,
		executions[1].ActionName,
	})
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
