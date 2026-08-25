// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dao

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
)

func TestEventActionExecutionRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	base, err := eventrule.NewExecution(uuid.New(), "notify", &eventrule.NoopPlan{Reason: "test"}, now)
	require.NoError(t, err)

	tests := map[string]eventrule.ExecutionResult{
		"completed": eventrule.CompletedExecutionResult(),
		"skipped":   eventrule.SkippedExecutionResult(eventrule.ExecutionReasonNoTargets),
		"deferred":  eventrule.DeferredExecutionResult(eventrule.ExecutionReasonAttemptFailed, "temporary", time.Minute),
		"failed":    eventrule.FailedExecutionResult("terminal"),
	}
	for name, result := range tests {
		t.Run(name, func(t *testing.T) {
			execution := base.Clone()
			require.NoError(t, execution.TransitionTo(result, now.Add(time.Second)))
			persisted, err := EventActionExecutionTo(&execution)
			require.NoError(t, err)
			roundTripped, err := EventActionExecutionFrom(persisted)
			require.NoError(t, err)
			require.Equal(t, &execution, roundTripped)
		})
	}
}

func TestEventActionExecutionFromRejectsInvalidPersistence(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	execution, err := eventrule.NewExecution(uuid.New(), "notify", &eventrule.NoopPlan{}, now)
	require.NoError(t, err)
	valid, err := EventActionExecutionTo(execution)
	require.NoError(t, err)

	tests := map[string]struct {
		persisted *dbmodel.EventActionExecution
		mutate    func(*dbmodel.EventActionExecution)
		wantNil   bool
		wantErr   string
	}{
		"nil": {wantNil: true},
		"unknown status": {
			persisted: valid,
			mutate:    func(execution *dbmodel.EventActionExecution) { execution.Status = "unknown" },
			wantErr:   "unknown execution status",
		},
		"missing event id": {
			persisted: valid,
			mutate:    func(execution *dbmodel.EventActionExecution) { execution.EventID = uuid.Nil },
			wantErr:   "execution event id is required",
		},
		"action type mismatch": {
			persisted: valid,
			mutate:    func(execution *dbmodel.EventActionExecution) { execution.ActionType = "send_alert" },
			wantErr:   "does not match plan type",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var persisted *dbmodel.EventActionExecution
			if test.persisted != nil {
				copy := *test.persisted
				persisted = &copy
				test.mutate(persisted)
			}
			result, err := EventActionExecutionFrom(persisted)
			if test.wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, test.wantNil, result == nil)
				return
			}
			require.ErrorIs(t, err, eventrule.ErrInvalidPersistedExecution)
			require.ErrorContains(t, err, test.wantErr)
			require.Nil(t, result)
		})
	}
}
