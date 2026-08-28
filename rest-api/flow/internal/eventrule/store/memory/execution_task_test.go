// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStore_CreateExecutionTask(t *testing.T) {
	t.Run("validates association", func(t *testing.T) {
		store := New()

		created, err := store.CreateExecutionTask(
			context.Background(),
			eventrule.ExecutionTask{},
		)

		require.ErrorContains(t, err, "execution id is required")
		require.Nil(t, created)
	})

	t.Run("rejects unknown execution", func(t *testing.T) {
		store := New()

		created, err := store.CreateExecutionTask(
			context.Background(),
			eventrule.ExecutionTask{
				ExecutionID: uuid.New(),
				RackID:      uuid.New(),
				TaskID:      uuid.New(),
			},
		)

		require.ErrorIs(t, err, eventrule.ErrExecutionNotFound)
		require.Nil(t, created)
	})

	t.Run("creates and returns existing association", func(t *testing.T) {
		store := New()
		execution := createExecution(t, store)
		requested := eventrule.ExecutionTask{
			ExecutionID: execution.ID,
			RackID:      uuid.New(),
			TaskID:      uuid.New(),
		}

		created, err := store.CreateExecutionTask(context.Background(), requested)
		require.NoError(t, err)
		require.Equal(t, requested, *created)

		created.TaskID = uuid.New()

		loaded, err := store.GetExecutionTask(
			context.Background(),
			requested.ExecutionID,
			requested.RackID,
		)
		require.NoError(t, err)
		require.Equal(t, requested, *loaded)

		duplicate := requested
		duplicate.TaskID = uuid.New()

		existing, err := store.CreateExecutionTask(context.Background(), duplicate)
		require.NoError(t, err)
		require.Equal(t, requested, *existing)
	})
}

func TestStore_GetExecutionTask(t *testing.T) {
	tests := map[string]struct {
		executionID uuid.UUID
		rackID      uuid.UUID
		wantErr     string
	}{
		"missing execution id": {
			rackID:  uuid.New(),
			wantErr: "execution id is required",
		},
		"missing rack id": {
			executionID: uuid.New(),
			wantErr:     "rack id is required",
		},
		"unknown association": {
			executionID: uuid.New(),
			rackID:      uuid.New(),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			association, err := New().GetExecutionTask(
				context.Background(),
				test.executionID,
				test.rackID,
			)

			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				require.Nil(t, association)
				return
			}

			require.NoError(t, err)
			require.Nil(t, association)
		})
	}
}

func createExecution(t *testing.T, store *Store) eventrule.Execution {
	t.Helper()

	definition := eventrule.Event{
		Key: eventrule.EventKey{
			SourceName: "test",
			SourceKey:  uuid.NewString(),
		},
		Type: "test.event",
		Resource: eventrule.ResourceIdentity{
			Kind: eventrule.ResourceKindRack,
			ID:   uuid.New(),
		},
		AppliedRuleID: uuid.New(),
		EffectivePolicy: eventrule.Policy{Actions: []eventrule.Action{
			{Name: "noop", Spec: &eventrule.Noop{}},
		}},
		Summary: "test event",
	}

	event, err := store.CommitEventPlan(
		context.Background(),
		definition,
		[]eventrule.PlannedExecution{
			{
				ActionName:    "noop",
				ExecutionPlan: &eventrule.NoopPlan{},
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, event)

	executions, err := store.Executions()
	require.NoError(t, err)
	require.Len(t, executions, 1)

	return executions[0]
}
