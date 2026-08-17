// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// ExecutionFactory constructs an empty execution store whose
// authoritative clock reads the supplied time.
type ExecutionFactory func(*time.Time) eventrule.ExecutionStore

// RunExecutionContract executes the shared execution store
// contract.
func RunExecutionContract(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	t.Run("create pending execution", func(t *testing.T) {
		testExecutionCreation(t, factory)
	})
	t.Run("reject invalid creation", func(t *testing.T) {
		testExecutionInvalidCreation(t, factory)
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
	t.Run("concurrent delivery deduplication", func(t *testing.T) {
		testExecutionConcurrentDeliveryDeduplication(t, factory)
	})
	t.Run("persist result", func(t *testing.T) {
		testExecutionTransition(t, factory)
	})
	t.Run("unknown execution result", func(t *testing.T) {
		testUnknownExecutionTransition(t, factory)
	})
}

func testExecutionInvalidCreation(
	t *testing.T,
	factory ExecutionFactory,
) {
	t.Helper()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory(&now)

	created, err := store.CreateExecution(
		context.Background(),
		eventrule.ExecutionIdentity{},
		nil,
	)
	require.ErrorContains(t, err, "event id is required")
	require.Nil(t, created)

	identity := newExecutionIdentity()
	created, err = store.CreateExecution(
		context.Background(),
		identity,
		&eventrule.Dedupe{Window: time.Minute},
	)
	require.ErrorContains(t, err, "correlation key is required")
	require.Nil(t, created)

	identity.CorrelationKey = "incident-1"
	created, err = store.CreateExecution(
		context.Background(),
		identity,
		&eventrule.Dedupe{},
	)
	require.ErrorContains(t, err, "dedupe window must be positive")
	require.Nil(t, created)
}

func testExecutionCreation(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	created, err := factory(&now).CreateExecution(
		context.Background(),
		newExecutionIdentity(),
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Equal(t, eventrule.ExecutionStatusPending, created.Status)
	require.Equal(t, now, created.CreatedAt)
	require.Equal(t, now, created.UpdatedAt)
	require.Equal(t, 1, created.Observations)
	require.Equal(t, 1, created.Attempts)
}

func testExecutionTransition(t *testing.T, factory ExecutionFactory) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	created, err := store.CreateExecution(ctx, newExecutionIdentity(), nil)
	require.NoError(t, err)
	require.NotNil(t, created)

	retryAfter := time.Minute
	statusMessage := "downstream temporarily unavailable"
	transitionAt := now.Add(time.Second)
	now = transitionAt
	transitioned, err := store.TransitionExecution(
		ctx,
		created.ID,
		eventrule.DeferredExecutionResult(
			eventrule.ExecutionReasonAttemptFailed,
			statusMessage,
			retryAfter,
		),
	)
	require.NoError(t, err)
	require.NotNil(t, transitioned)
	require.Equal(t, eventrule.ExecutionStatusDeferred, transitioned.Status)
	require.Equal(t, eventrule.ExecutionReasonAttemptFailed, transitioned.Reason)
	require.Equal(t, statusMessage, transitioned.StatusMessage)
	require.Equal(t, 1, transitioned.Attempts)
	require.Equal(t, transitionAt, transitioned.UpdatedAt)
	require.Equal(t, transitionAt.Add(retryAfter), transitioned.NextAttemptAt)

	now = transitionAt.Add(time.Second)
	transitioned, err = store.TransitionExecution(
		ctx,
		created.ID,
		eventrule.CompletedExecutionResult(),
	)
	require.NoError(t, err)
	require.NotNil(t, transitioned)
	require.Equal(t, eventrule.ExecutionStatusCompleted, transitioned.Status)
	require.Equal(t, eventrule.ExecutionReasonNone, transitioned.Reason)
	require.Empty(t, transitioned.StatusMessage)
	require.Equal(t, 2, transitioned.Attempts)
	require.Equal(t, now, transitioned.UpdatedAt)
	require.True(t, transitioned.NextAttemptAt.IsZero())

	transitioned, err = store.TransitionExecution(
		ctx,
		created.ID,
		eventrule.FailedExecutionResult(""),
	)
	require.ErrorContains(t, err, "cannot transition")
	require.Nil(t, transitioned)
}

func testUnknownExecutionTransition(
	t *testing.T,
	factory ExecutionFactory,
) {
	t.Helper()
	now := time.Now()
	transitioned, err := factory(&now).TransitionExecution(
		context.Background(),
		uuid.New(),
		eventrule.CompletedExecutionResult(),
	)
	require.ErrorIs(t, err, eventrule.ErrExecutionNotFound)
	require.Nil(t, transitioned)
}

func testExecutionDeliveryDeduplication(
	t *testing.T,
	factory ExecutionFactory,
) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	identity := newExecutionIdentity()

	created, err := store.CreateExecution(ctx, identity, nil)
	require.NoError(t, err)
	require.NotNil(t, created)

	now = now.Add(time.Second)
	duplicate, err := store.CreateExecution(ctx, identity, nil)
	require.NoError(t, err)
	require.Nil(t, duplicate)
}

func testExecutionSemanticDeduplication(
	t *testing.T,
	factory ExecutionFactory,
) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	identity := newExecutionIdentity()
	identity.CorrelationKey = "incident-1"
	dedupe := &eventrule.Dedupe{Window: time.Minute}

	created, err := store.CreateExecution(ctx, identity, dedupe)
	require.NoError(t, err)
	require.NotNil(t, created)

	identity.EventID = uuid.New()
	now = now.Add(time.Second)
	duplicate, err := store.CreateExecution(ctx, identity, dedupe)
	require.NoError(t, err)
	require.Nil(t, duplicate)
}

func testExecutionSemanticDedupeWindowExpiry(
	t *testing.T,
	factory ExecutionFactory,
) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	identity := newExecutionIdentity()
	identity.CorrelationKey = "incident-1"
	dedupe := &eventrule.Dedupe{Window: time.Minute}

	first, err := store.CreateExecution(ctx, identity, dedupe)
	require.NoError(t, err)
	require.NotNil(t, first)

	identity.EventID = uuid.New()
	now = now.Add(dedupe.Window)
	second, err := store.CreateExecution(ctx, identity, dedupe)
	require.NoError(t, err)
	require.NotNil(t, second)
	require.NotEqual(t, first.ID, second.ID)
}

func testExecutionConcurrentDeliveryDeduplication(
	t *testing.T,
	factory ExecutionFactory,
) {
	t.Helper()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	store := factory(&now)
	identity := newExecutionIdentity()

	const deliveries = 20
	results := make(chan *eventrule.Execution, deliveries)
	errs := make(chan error, deliveries)
	var wg sync.WaitGroup
	for range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := store.CreateExecution(
				context.Background(),
				identity,
				nil,
			)
			results <- created
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	created := 0
	for result := range results {
		if result != nil {
			created++
		}
	}
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, 1, created)
}

func newExecutionIdentity() eventrule.ExecutionIdentity {
	return eventrule.ExecutionIdentity{
		EventID:  uuid.New(),
		RuleID:   uuid.New(),
		ActionID: "action",
	}
}
