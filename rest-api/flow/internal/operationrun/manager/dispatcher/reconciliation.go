// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
)

// reconciliationSummary summarizes the target state observed while reconciling
// child task statuses.
type reconciliationSummary struct {
	currentPhase          int32
	currentPhaseTargets   []*operationrun.OperationRunTarget
	completedPhaseTargets []*operationrun.OperationRunTarget
	terminalChangedPhase  int32
	targetCount           int
	failedOrTerminated    int
}

// newReconciliationSummary initializes fields used by the reconciliation
// helpers.
func newReconciliationSummary(targetCapacity int) reconciliationSummary {
	return reconciliationSummary{
		currentPhase:          -1,
		currentPhaseTargets:   make([]*operationrun.OperationRunTarget, 0, targetCapacity),
		completedPhaseTargets: make([]*operationrun.OperationRunTarget, 0, targetCapacity),
		terminalChangedPhase:  -1,
	}
}

// isAllTerminal reports whether reconciliation found no remaining active work.
func (s reconciliationSummary) isAllTerminal() bool {
	return s.currentPhase < 0
}

// previousPhaseTerminalChanged reports whether this dispatch moved the
// immediately preceding phase forward to terminal state.
func (s reconciliationSummary) previousPhaseTerminalChanged() bool {
	return s.terminalChangedPhase >= 0 &&
		s.currentPhase > 0 &&
		s.terminalChangedPhase == s.currentPhase-1
}

func (s *reconciliationSummary) recordTerminalChangedPhase(phase int32) error {
	if s.terminalChangedPhase < 0 {
		s.terminalChangedPhase = phase
		return nil
	}

	if s.terminalChangedPhase == phase {
		return nil
	}

	return fmt.Errorf(
		"terminal target changes span multiple phases: %d and %d",
		s.terminalChangedPhase,
		phase,
	)
}

// reconcileTargets copies child task status back into operation-run targets and
// summarizes the post-reconciliation target state in the same scan.
func (d *Dispatcher) reconcileTargets(
	ctx context.Context,
	targets []*operationrun.OperationRunTarget,
	changed map[uuid.UUID]*operationrun.OperationRunTarget,
) (reconciliationSummary, error) {
	result := newReconciliationSummary(len(targets))

	for _, target := range targets {
		result.targetCount++
		if target.TaskID != nil && !target.Status.IsTerminal() {
			task, err := d.deps.TaskStore.GetTask(ctx, *target.TaskID)
			if err != nil {
				return reconciliationSummary{}, fmt.Errorf(
					"get child task %s: %w",
					*target.TaskID,
					err,
				)
			}

			newStatus := operationrun.OperationRunTargetStatusFromTaskStatus(task.Status)
			if newStatus != target.Status || task.Message != target.Message {
				target.Status = newStatus
				target.Message = task.Message
				changed[target.ID] = target
			}

			if newStatus.IsTerminal() {
				if err := result.recordTerminalChangedPhase(target.PhaseIndex); err != nil {
					return reconciliationSummary{}, err
				}
			}
		}

		if target.Status.IsTerminal() {
			if target.Status.IsFailedOrTerminated() {
				result.failedOrTerminated++
			}
			continue
		}

		if result.currentPhase < 0 || target.PhaseIndex < result.currentPhase {
			result.currentPhase = target.PhaseIndex
		}
	}

	result.recordPhaseTargets(targets)

	return result, nil
}

func (s *reconciliationSummary) recordPhaseTargets(
	targets []*operationrun.OperationRunTarget,
) {
	if s.currentPhase < 0 {
		return
	}

	for _, target := range targets {
		switch {
		case target.PhaseIndex == s.currentPhase:
			s.currentPhaseTargets = append(s.currentPhaseTargets, target)
		case target.PhaseIndex < s.currentPhase:
			s.completedPhaseTargets = append(s.completedPhaseTargets, target)
		}
	}
}
