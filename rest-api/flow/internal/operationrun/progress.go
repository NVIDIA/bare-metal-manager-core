// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operationrun

import (
	"errors"
	"fmt"
)

// TargetPhaseSummary groups targets by the active rollout phase. The current
// phase is the lowest phase index that still has non-terminal work.
type TargetPhaseSummary struct {
	TargetCount                   int
	FailedOrTerminatedTargetCount int
	CurrentPhaseIndex             int32
	// CurrentPhaseTargets contains all targets in CurrentPhaseIndex, including
	// terminal targets from that phase.
	CurrentPhaseTargets []*OperationRunTarget
	// CompletedPhaseTargets contains all targets in phases before
	// CurrentPhaseIndex.
	CompletedPhaseTargets []*OperationRunTarget
}

// SafetyGateEvaluation reports whether a validated safety gate blocks progress.
type SafetyGateEvaluation struct {
	Tripped bool
	Message string
}

// NewTargetPhaseSummary finds the current rollout phase and the previous phase
// targets used for cumulative safety-gate evaluation.
func NewTargetPhaseSummary(
	targets []*OperationRunTarget,
) TargetPhaseSummary {
	summary := TargetPhaseSummary{CurrentPhaseIndex: -1}

	// First pass: count real targets and find the lowest phase that still has
	// non-terminal work. That phase is the current phase for dispatch and
	// manual phase advancement.
	for _, target := range targets {
		if target == nil {
			continue
		}

		summary.TargetCount++
		if target.Status.IsFailedOrTerminated() {
			summary.FailedOrTerminatedTargetCount++
		}

		if target.Status.IsTerminal() {
			continue
		}

		if summary.CurrentPhaseIndex < 0 ||
			target.PhaseIndex < summary.CurrentPhaseIndex {
			summary.CurrentPhaseIndex = target.PhaseIndex
		}
	}

	if summary.IsAllTerminal() {
		return summary
	}

	// Second pass: now that the current phase is known, split targets into the
	// current phase and already-completed prior phases for safety-gate checks.
	for _, target := range targets {
		if target == nil {
			continue
		}

		if target.PhaseIndex == summary.CurrentPhaseIndex {
			summary.CurrentPhaseTargets = append(
				summary.CurrentPhaseTargets,
				target,
			)
		} else if target.PhaseIndex < summary.CurrentPhaseIndex {
			summary.CompletedPhaseTargets = append(
				summary.CompletedPhaseTargets,
				target,
			)
		}
	}

	return summary
}

// IsAllTerminal reports whether there is no remaining active target work.
func (s TargetPhaseSummary) IsAllTerminal() bool {
	return s.CurrentPhaseIndex < 0
}

// TerminalRunStatus returns the terminal run status implied by an all-terminal
// target set. The boolean is false when the run still has active work or has no
// targets to summarize.
func (s TargetPhaseSummary) TerminalRunStatus() (OperationRunStatus, bool) {
	if !s.IsAllTerminal() || s.TargetCount == 0 {
		return "", false
	}

	if s.FailedOrTerminatedTargetCount == s.TargetCount {
		return OperationRunStatusFailed, true
	}

	if s.FailedOrTerminatedTargetCount > 0 {
		return OperationRunStatusCompletedWithFailures, true
	}

	return OperationRunStatusCompleted, true
}

// CheckExpectedNextPhase verifies that the summary is waiting at a manually
// advanceable phase and that a positive expected phase matches the current
// phase. Phase 0 is the initial phase and starts without an advance gate; only
// phase 1 and later represent crossing a phase boundary.
func (s TargetPhaseSummary) CheckExpectedNextPhase(
	expectedPhaseIndex int32,
) error {
	if s.IsAllTerminal() {
		return errors.New("not waiting at a next phase")
	}

	if s.CurrentPhaseIndex == 0 {
		return errors.New("phase 0 is the initial phase and cannot be advanced")
	}

	if expectedPhaseIndex > 0 && expectedPhaseIndex != s.CurrentPhaseIndex {
		return fmt.Errorf(
			"expected phase %d, current phase is %d",
			expectedPhaseIndex,
			s.CurrentPhaseIndex,
		)
	}

	return nil
}

// CurrentPhaseNotStarted reports whether the current phase still has only
// untouched pending targets.
func (s TargetPhaseSummary) CurrentPhaseNotStarted() bool {
	if len(s.CurrentPhaseTargets) == 0 {
		return false
	}

	for _, target := range s.CurrentPhaseTargets {
		if target == nil ||
			target.Status != OperationRunTargetStatusPending ||
			target.TaskID != nil {
			return false
		}
	}

	return true
}

// StatsForSafetyScope aggregates target outcomes over the safety-gate scope
// selected by the user.
func (s TargetPhaseSummary) StatsForSafetyScope(scope SafetyGateScope) PhaseStats {
	stats := PhaseStats{}
	stats.AddTargets(s.CurrentPhaseTargets)

	if scope == SafetyGateScopeCumulativeRun {
		stats.AddTargets(s.CompletedPhaseTargets)
	}

	return stats
}

// EvaluateSafetyGates checks validated safety gates against the target summary.
func (s TargetPhaseSummary) EvaluateSafetyGates(
	gates []SafetyGate,
) SafetyGateEvaluation {
	for _, gate := range gates {
		stats := s.StatsForSafetyScope(gate.SafetyGateScope())
		if !gate.IsTripped(stats.StatusCounts.Failed, stats.SelectedTargets) {
			continue
		}

		return SafetyGateEvaluation{
			Tripped: true,
			Message: stats.SafetyGateTrippedMessage(gate),
		}
	}

	return SafetyGateEvaluation{}
}
