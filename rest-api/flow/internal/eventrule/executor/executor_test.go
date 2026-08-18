// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package executor

import (
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/target"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

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
			wantErr: "execution: execution id is required",
		},
		"invalid action": {
			request: valid,
			mutate:  func(request *ExecutionRequest) { request.Action = eventrule.Action{} },
			wantErr: "action: action id is empty",
		},
		"missing target id": {
			request: valid,
			mutate: func(request *ExecutionRequest) {
				request.Targets = []target.Target{{Kind: eventrule.ResourceKindComponent}}
			},
			wantErr: "target 0: target id is required",
		},
		"invalid target kind": {
			request: valid,
			mutate: func(request *ExecutionRequest) {
				request.Targets = []target.Target{{Kind: "invalid", ID: uuid.New()}}
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

func newValidExecutionRequest(t *testing.T) ExecutionRequest {
	t.Helper()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	execution, err := eventrule.NewExecution(eventrule.ExecutionIdentity{
		EventID:  uuid.New(),
		RuleID:   uuid.New(),
		ActionID: "noop",
	}, now)
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
