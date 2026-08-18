// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dao

import (
	"testing"
	"time"

	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestEventActionExecutionRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	base := eventrule.Execution{
		ExecutionState: eventrule.ExecutionState{ExecutionStatusDetails: eventrule.ExecutionStatusDetails{Status: eventrule.ExecutionStatusPending}},
		ExecutionIdentity: eventrule.ExecutionIdentity{
			EventID:        uuid.New(),
			RuleID:         uuid.New(),
			ActionID:       "notify",
			CorrelationKey: "incident-1",
		},
		ID:           uuid.New(),
		Observations: 2,
		Attempts:     1,
		CreatedAt:    now,
		UpdatedAt:    now.Add(time.Second),
	}
	tests := map[string]eventrule.Execution{
		"pending":   executionWithStatus(base, eventrule.ExecutionStatusPending),
		"submitted": executionWithStatus(base, eventrule.ExecutionStatusSubmitted),
		"completed": executionWithStatus(base, eventrule.ExecutionStatusCompleted),
		"skipped": func() eventrule.Execution {
			execution := executionWithStatus(base, eventrule.ExecutionStatusSkipped)
			execution.Reason = eventrule.ExecutionReasonNoTargets
			return execution
		}(),
		"deferred": func() eventrule.Execution {
			execution := executionWithStatus(base, eventrule.ExecutionStatusDeferred)
			execution.Reason = eventrule.ExecutionReasonAttemptFailed
			execution.StatusMessage = "temporarily unavailable"
			execution.NextAttemptAt = now.Add(time.Minute)
			return execution
		}(),
		"failed": func() eventrule.Execution {
			execution := executionWithStatus(base, eventrule.ExecutionStatusFailed)
			execution.StatusMessage = "permanent failure"
			return execution
		}(),
	}
	completed := tests["completed"]
	completed.StatusMessage = "action completed"
	tests["completed"] = completed
	for name, execution := range tests {
		t.Run(name, func(t *testing.T) {
			persisted, err := EventActionExecutionTo(&execution)
			require.NoError(t, err)
			roundTripped, err := EventActionExecutionFrom(persisted)
			require.NoError(t, err)
			require.Equal(t, &execution, roundTripped)
		})
	}
}

func TestEventActionExecutionToRejectsInvalidDomain(t *testing.T) {
	tests := map[string]*eventrule.Execution{
		"nil":        nil,
		"invalid id": {ExecutionState: eventrule.ExecutionState{ExecutionStatusDetails: eventrule.ExecutionStatusDetails{Status: eventrule.ExecutionStatusPending}}},
	}
	for name, execution := range tests {
		t.Run(name, func(t *testing.T) {
			persisted, err := EventActionExecutionTo(execution)
			require.Error(t, err)
			require.Nil(t, persisted)
		})
	}
}

func TestEventActionExecutionFrom(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	valid, err := EventActionExecutionTo(&eventrule.Execution{
		ExecutionState: eventrule.ExecutionState{ExecutionStatusDetails: eventrule.ExecutionStatusDetails{Status: eventrule.ExecutionStatusPending}},
		ExecutionIdentity: eventrule.ExecutionIdentity{
			EventID:  uuid.New(),
			RuleID:   uuid.New(),
			ActionID: "notify",
		},
		ID:           uuid.New(),
		Observations: 1, Attempts: 1,
		CreatedAt: now, UpdatedAt: now,
	})
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
		"missing action id": {
			persisted: valid,
			mutate:    func(execution *dbmodel.EventActionExecution) { execution.ActionID = "" },
			wantErr:   "event rule action id is empty",
		},
		"deferred without next attempt": {
			persisted: valid,
			mutate: func(execution *dbmodel.EventActionExecution) {
				execution.Status = string(eventrule.ExecutionStatusDeferred)
				execution.Reason = string(eventrule.ExecutionReasonAttemptFailed)
				execution.StatusMessage = "temporary failure"
			},
			wantErr: "deferred execution requires next attempt time",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var persisted *dbmodel.EventActionExecution
			if test.persisted != nil {
				mutated := *test.persisted
				persisted = &mutated
				test.mutate(persisted)
			}
			execution, err := EventActionExecutionFrom(persisted)
			if test.wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, test.wantNil, execution == nil)
				return
			}
			require.ErrorIs(t, err, eventrule.ErrInvalidPersistedExecution)
			require.ErrorContains(t, err, test.wantErr)
			require.Nil(t, execution)
		})
	}
}

func executionWithStatus(
	execution eventrule.Execution,
	status eventrule.ExecutionStatus,
) eventrule.Execution {
	execution.Status = status
	return execution
}
