// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operationrun

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestNewTargetPhaseSummaryFindsLowestNonTerminalPhase(t *testing.T) {
	phase0Completed := &OperationRunTarget{
		PhaseIndex: 0,
		Status:     OperationRunTargetStatusCompleted,
	}
	phase0Failed := &OperationRunTarget{
		PhaseIndex: 0,
		Status:     OperationRunTargetStatusFailed,
	}
	phase1Submitted := &OperationRunTarget{
		PhaseIndex: 1,
		Status:     OperationRunTargetStatusSubmitted,
	}
	phase1Completed := &OperationRunTarget{
		PhaseIndex: 1,
		Status:     OperationRunTargetStatusCompleted,
	}
	phase2Pending := &OperationRunTarget{
		PhaseIndex: 2,
		Status:     OperationRunTargetStatusPending,
	}

	summary := NewTargetPhaseSummary([]*OperationRunTarget{
		nil,
		phase0Completed,
		phase1Submitted,
		phase2Pending,
		phase1Completed,
		phase0Failed,
	})

	require.False(t, summary.IsAllTerminal())
	require.Equal(t, 5, summary.TargetCount)
	require.Equal(t, 1, summary.FailedOrTerminatedTargetCount)
	require.EqualValues(t, 1, summary.CurrentPhaseIndex)
	require.Equal(
		t,
		[]*OperationRunTarget{phase1Submitted, phase1Completed},
		summary.CurrentPhaseTargets,
	)
	require.Equal(
		t,
		[]*OperationRunTarget{phase0Completed, phase0Failed},
		summary.CompletedPhaseTargets,
	)

	currentStats := summary.StatsForSafetyScope(SafetyGateScopeCurrentPhase)
	require.Equal(t, 2, currentStats.SelectedTargets)
	require.Equal(t, 1, currentStats.StatusCounts.Completed)
	require.Equal(t, 0, currentStats.StatusCounts.Failed)

	cumulativeStats := summary.StatsForSafetyScope(SafetyGateScopeCumulativeRun)
	require.Equal(t, 4, cumulativeStats.SelectedTargets)
	require.Equal(t, 2, cumulativeStats.StatusCounts.Completed)
	require.Equal(t, 1, cumulativeStats.StatusCounts.Failed)
}

func TestNewTargetPhaseSummaryReportsAllTerminal(t *testing.T) {
	summary := NewTargetPhaseSummary([]*OperationRunTarget{
		nil,
		{
			PhaseIndex: 0,
			Status:     OperationRunTargetStatusCompleted,
		},
		{
			PhaseIndex: 1,
			Status:     OperationRunTargetStatusFailed,
		},
	})

	require.True(t, summary.IsAllTerminal())
	require.Equal(t, 2, summary.TargetCount)
	require.Equal(t, 1, summary.FailedOrTerminatedTargetCount)
	require.EqualValues(t, -1, summary.CurrentPhaseIndex)
	require.Empty(t, summary.CurrentPhaseTargets)
	require.Empty(t, summary.CompletedPhaseTargets)
}

func TestTargetPhaseSummaryTerminalRunStatus(t *testing.T) {
	tests := []struct {
		name                    string
		summary                 TargetPhaseSummary
		wantStatus              OperationRunStatus
		wantTerminalStatusFound bool
	}{
		{
			name: "still active",
			summary: TargetPhaseSummary{
				TargetCount:       1,
				CurrentPhaseIndex: 1,
			},
		},
		{
			name: "no targets",
			summary: TargetPhaseSummary{
				CurrentPhaseIndex: -1,
			},
		},
		{
			name: "all completed",
			summary: TargetPhaseSummary{
				TargetCount:       2,
				CurrentPhaseIndex: -1,
			},
			wantStatus:              OperationRunStatusCompleted,
			wantTerminalStatusFound: true,
		},
		{
			name: "completed with failures",
			summary: TargetPhaseSummary{
				TargetCount:                   2,
				FailedOrTerminatedTargetCount: 1,
				CurrentPhaseIndex:             -1,
			},
			wantStatus:              OperationRunStatusCompletedWithFailures,
			wantTerminalStatusFound: true,
		},
		{
			name: "all failed",
			summary: TargetPhaseSummary{
				TargetCount:                   2,
				FailedOrTerminatedTargetCount: 2,
				CurrentPhaseIndex:             -1,
			},
			wantStatus:              OperationRunStatusFailed,
			wantTerminalStatusFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStatus, gotOK := tt.summary.TerminalRunStatus()

			require.Equal(t, tt.wantTerminalStatusFound, gotOK)
			require.Equal(t, tt.wantStatus, gotStatus)
		})
	}
}

func TestTargetPhaseSummaryCheckExpectedNextPhase(t *testing.T) {
	tests := []struct {
		name              string
		currentPhaseIndex int32
		expectedPhase     int32
		wantErr           string
	}{
		{
			name:              "all terminal",
			currentPhaseIndex: -1,
			wantErr:           "not waiting at a next phase",
		},
		{
			name:              "initial phase",
			currentPhaseIndex: 0,
			wantErr:           "phase 0 is the initial phase and cannot be advanced",
		},
		{
			name:              "matching phase",
			currentPhaseIndex: 1,
			expectedPhase:     1,
		},
		{
			name:              "zero expectation",
			currentPhaseIndex: 1,
		},
		{
			name:              "negative expectation",
			currentPhaseIndex: 1,
			expectedPhase:     -1,
		},
		{
			name:              "mismatched phase",
			currentPhaseIndex: 2,
			expectedPhase:     1,
			wantErr:           "expected phase 1, current phase is 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := TargetPhaseSummary{
				CurrentPhaseIndex: tt.currentPhaseIndex,
			}

			err := summary.CheckExpectedNextPhase(tt.expectedPhase)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestTargetPhaseSummaryCurrentPhaseNotStarted(t *testing.T) {
	tests := []struct {
		name    string
		targets []*OperationRunTarget
		want    bool
	}{
		{
			name: "empty",
		},
		{
			name: "pending targets",
			targets: []*OperationRunTarget{
				{Status: OperationRunTargetStatusPending},
				{Status: OperationRunTargetStatusPending},
			},
			want: true,
		},
		{
			name: "submitted target",
			targets: []*OperationRunTarget{
				{Status: OperationRunTargetStatusPending},
				{Status: OperationRunTargetStatusSubmitted},
			},
		},
		{
			name: "task assigned",
			targets: []*OperationRunTarget{
				func() *OperationRunTarget {
					taskID := uuid.New()
					return &OperationRunTarget{
						Status: OperationRunTargetStatusPending,
						TaskID: &taskID,
					}
				}(),
			},
		},
		{
			name: "nil target",
			targets: []*OperationRunTarget{
				nil,
				{Status: OperationRunTargetStatusPending},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := TargetPhaseSummary{
				CurrentPhaseTargets: tt.targets,
			}

			require.Equal(t, tt.want, summary.CurrentPhaseNotStarted())
		})
	}
}

func TestEvaluateSafetyGatesReturnsFirstTrippedGate(t *testing.T) {
	summary := TargetPhaseSummary{
		CurrentPhaseTargets: []*OperationRunTarget{
			{
				PhaseIndex: 1,
				Status:     OperationRunTargetStatusFailed,
			},
			{
				PhaseIndex: 1,
				Status:     OperationRunTargetStatusCompleted,
			},
		},
	}

	evaluation := summary.EvaluateSafetyGates(
		[]SafetyGate{
			&FailureCountGate{
				Scope:                 SafetyGateScopeCurrentPhase,
				FailureThresholdCount: 2,
			},
			&FailureRateGate{
				Scope:                   SafetyGateScopeCurrentPhase,
				FailureThresholdPercent: 50,
			},
		},
	)

	require.True(t, evaluation.Tripped)
	require.Equal(
		t,
		"failure_rate safety gate tripped for current_phase: 1/2 targets failed (50%, threshold 50%)",
		evaluation.Message,
	)
}
