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
	operationrun.TargetPhaseSummary
	terminalChangedPhase int32
}

// newReconciliationSummary initializes fields used by the reconciliation
// helpers.
func newReconciliationSummary() reconciliationSummary {
	return reconciliationSummary{
		TargetPhaseSummary:   operationrun.TargetPhaseSummary{CurrentPhaseIndex: -1},
		terminalChangedPhase: -1,
	}
}

// previousPhaseTerminalChanged reports whether this dispatch moved the
// immediately preceding phase forward to terminal state.
func (s reconciliationSummary) previousPhaseTerminalChanged() bool {
	return s.terminalChangedPhase >= 0 &&
		s.CurrentPhaseIndex > 0 &&
		s.terminalChangedPhase == s.CurrentPhaseIndex-1
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

// reconcileTargets copies child task status back into operation-run targets,
// then summarizes the post-reconciliation target state.
func (d *Dispatcher) reconcileTargets(
	ctx context.Context,
	targets []*operationrun.OperationRunTarget,
	changed map[uuid.UUID]*operationrun.OperationRunTarget,
) (reconciliationSummary, error) {
	result := newReconciliationSummary()

	for _, target := range targets {
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
				target.SetMessage(task.Message)
				changed[target.ID] = target
			}

			if newStatus.IsTerminal() {
				if err := result.recordTerminalChangedPhase(target.PhaseIndex); err != nil {
					return reconciliationSummary{}, err
				}
			}
		}
	}

	result.TargetPhaseSummary = operationrun.NewTargetPhaseSummary(targets)

	return result, nil
}
