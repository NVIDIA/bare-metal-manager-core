// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package executor

import (
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPreparationResult_Validate(t *testing.T) {
	validRequest := newValidExecutionRequest(t)
	tests := map[string]struct {
		preparation PreparationResult
		wantErr     string
	}{
		"request": {
			preparation: PreparationResult{Request: &validRequest},
		},
		"invalid request": {
			preparation: PreparationResult{Request: &ExecutionRequest{}},
			wantErr:     "execution: event action execution id is required",
		},
		"outcome": {
			preparation: PreparationResult{Outcome: &eventrule.ExecutionState{
				Status: eventrule.ExecutionStatusSkipped,
				Reason: eventrule.ExecutionReasonNoTargets,
			}},
		},
		"neither": {
			wantErr: "requires exactly one request or outcome",
		},
		"both": {
			preparation: PreparationResult{
				Request: &ExecutionRequest{},
				Outcome: &eventrule.ExecutionState{
					Status: eventrule.ExecutionStatusSkipped,
					Reason: eventrule.ExecutionReasonNoTargets,
				},
			},
			wantErr: "requires exactly one request or outcome",
		},
		"invalid outcome": {
			preparation: PreparationResult{Outcome: &eventrule.ExecutionState{
				Status: eventrule.ExecutionStatusSkipped,
			}},
			wantErr: "skipped execution requires one of reasons",
		},
		"claimed outcome": {
			preparation: PreparationResult{Outcome: &eventrule.ExecutionState{
				Status: eventrule.ExecutionStatusClaimed,
			}},
			wantErr: "cannot transition execution to claimed status",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.preparation.Validate()
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestExecutionRequest_Validate(t *testing.T) {
	valid := newValidExecutionRequest(t)
	tests := map[string]struct {
		request ExecutionRequest
		mutate  func(*ExecutionRequest)
		wantErr string
	}{
		"valid": {request: valid},
		"invalid execution": {
			request: valid,
			mutate:  func(request *ExecutionRequest) { request.Execution.ID = uuid.Nil },
			wantErr: "execution: event action execution id is required",
		},
		"invalid action": {
			request: valid,
			mutate:  func(request *ExecutionRequest) { request.Action = eventrule.Action{} },
			wantErr: "action: action id is empty",
		},
		"missing target id": {
			request: valid,
			mutate: func(request *ExecutionRequest) {
				request.Targets = []Target{{Kind: eventrule.ResourceKindComponent}}
			},
			wantErr: "target 0: target id is required",
		},
		"invalid target kind": {
			request: valid,
			mutate: func(request *ExecutionRequest) {
				request.Targets = []Target{{Kind: "invalid", ID: uuid.New()}}
			},
			wantErr: `target 0: unknown resource kind "invalid"`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := test.request
			if test.mutate != nil {
				test.mutate(&request)
			}
			err := request.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestTarget_Validate(t *testing.T) {
	tests := map[string]struct {
		target  Target
		wantErr string
	}{
		"component": {
			target: Target{Kind: eventrule.ResourceKindComponent, ID: uuid.New()},
		},
		"rack": {
			target: Target{Kind: eventrule.ResourceKindRack, ID: uuid.New()},
		},
		"invalid kind": {
			target:  Target{Kind: "invalid", ID: uuid.New()},
			wantErr: `unknown resource kind "invalid"`,
		},
		"missing id": {
			target:  Target{Kind: eventrule.ResourceKindComponent},
			wantErr: "target id is required",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.target.Validate()
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func newValidExecutionRequest(t *testing.T) ExecutionRequest {
	t.Helper()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	execution, err := (eventrule.ExecutionClaim{
		EventID:  uuid.New(),
		RuleID:   uuid.New(),
		ActionID: "noop",
		Now:      now,
	}).NewExecution()
	require.NoError(t, err)
	return ExecutionRequest{
		Execution: *execution,
		Action: eventrule.NewAction(
			"noop",
			eventrule.ActionCondition{},
			eventrule.Noop{},
		),
	}
}
