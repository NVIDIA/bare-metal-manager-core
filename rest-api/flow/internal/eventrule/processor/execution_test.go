// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"errors"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	"github.com/stretchr/testify/require"
)

func TestProcessor_PerformExecution(t *testing.T) {
	executorErr := errors.New("executor unavailable")
	completed := eventrule.ExecutionState{Status: eventrule.ExecutionStatusCompleted}
	claimed := eventrule.ExecutionState{Status: eventrule.ExecutionStatusClaimed}
	tests := map[string]struct {
		result      executor.PreparationResult
		executor    executor.Executor
		wantOutcome eventrule.ExecutionState
		wantErr     error
		wantMessage string
	}{
		"preparation outcome pass-through": {
			result:      executor.PreparationResult{Outcome: &completed},
			executor:    executorStub{},
			wantOutcome: completed,
		},
		"valid executor outcome": {
			result:      executionResult(),
			executor:    executorStub{outcome: completed},
			wantOutcome: completed,
		},
		"executor error is terminal": {
			result:      executionResult(),
			executor:    executorStub{err: executorErr},
			wantErr:     executorErr,
			wantMessage: "executor execution failed",
		},
		"invalid executor outcome is terminal": {
			result:      executionResult(),
			executor:    executorStub{outcome: claimed},
			wantErr:     ErrTerminal,
			wantMessage: "cannot transition execution to claimed status",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			processor := &Processor{executor: test.executor}
			outcome, err := processor.performExecution(
				context.Background(),
				test.result,
			)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				require.ErrorIs(t, err, ErrTerminal)
				require.ErrorContains(t, err, test.wantMessage)
				require.Equal(t, eventrule.ExecutionState{}, outcome)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantOutcome, outcome)
		})
	}
}

func executionResult() executor.PreparationResult {
	return executor.PreparationResult{Request: &executor.ExecutionRequest{}}
}

type executorStub struct {
	outcome eventrule.ExecutionState
	err     error
}

func (executorStub) Prepare(
	context.Context,
	executor.PrepareRequest,
) (executor.PreparationResult, error) {
	return executor.PreparationResult{}, nil
}

func (e executorStub) Execute(
	context.Context,
	executor.ExecutionRequest,
) (eventrule.ExecutionState, error) {
	return e.outcome, e.err
}
