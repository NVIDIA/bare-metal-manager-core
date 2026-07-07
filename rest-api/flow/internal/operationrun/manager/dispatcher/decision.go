// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"
	"time"

	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
)

type dispatchRunAction int

const (
	dispatchRunActionStop dispatchRunAction = iota
	dispatchRunActionClaim
)

// dispatchDecision records the run transition and execution step selected after
// preparation.
type dispatchDecision struct {
	transition     dispatchRunTransition
	action         dispatchRunAction
	options        *operationrun.Options
	op             *operationrun.Operation
	conflictPolicy conflictPolicyRuntime
	targets        []*operationrun.OperationRunTarget
}

func newStopDecision(transition dispatchRunTransition) dispatchDecision {
	return dispatchDecision{
		transition: transition,
		action:     dispatchRunActionStop,
	}
}

func newClaimDecision(
	transition dispatchRunTransition,
	options *operationrun.Options,
	op *operationrun.Operation,
	conflictPolicy conflictPolicyRuntime,
	targets []*operationrun.OperationRunTarget,
) dispatchDecision {
	return dispatchDecision{
		transition:     transition,
		action:         dispatchRunActionClaim,
		options:        options,
		op:             op,
		conflictPolicy: conflictPolicy,
		targets:        targets,
	}
}

type dispatchRunTransitionKind int

const (
	dispatchRunTransitionNone dispatchRunTransitionKind = iota
	dispatchRunTransitionFail
	dispatchRunTransitionComplete
	dispatchRunTransitionCompleteWithFailures
	dispatchRunTransitionPause
	dispatchRunTransitionStart
)

type dispatchRunTransition struct {
	kind    dispatchRunTransitionKind
	reason  operationrun.OperationRunStatusReason
	message string
}

func failRunTransition(message string) dispatchRunTransition {
	return dispatchRunTransition{
		kind:    dispatchRunTransitionFail,
		message: message,
	}
}

func pauseRunTransition(
	reason operationrun.OperationRunStatusReason,
	message string,
) dispatchRunTransition {
	return dispatchRunTransition{
		kind:    dispatchRunTransitionPause,
		reason:  reason,
		message: message,
	}
}

func startRunTransition(message string) dispatchRunTransition {
	return dispatchRunTransition{
		kind:    dispatchRunTransitionStart,
		message: message,
	}
}

func (t dispatchRunTransition) apply(
	run *operationrun.OperationRun,
	now time.Time,
) {
	switch t.kind {
	case dispatchRunTransitionNone:
		return
	case dispatchRunTransitionFail:
		run.Fail(now, t.message)
	case dispatchRunTransitionComplete:
		run.Complete(now, t.message)
	case dispatchRunTransitionCompleteWithFailures:
		run.CompleteWithFailures(now, t.message)
	case dispatchRunTransitionPause:
		run.Pause(t.reason, t.message)
	case dispatchRunTransitionStart:
		run.Start(now)
		if len(t.message) > 0 {
			run.StatusMessage = t.message
		}
	}
}

// decide applies run-level policy gates and records the transition execution
// should apply. A claim-targets decision means execution should inspect the
// current phase for available work.
func (d *Dispatcher) decide(
	prep *preparedDispatch,
	now time.Time,
) (dispatchDecision, error) {
	if prep.prepareErr != nil {
		return newStopDecision(
			failRunTransition(
				fmt.Sprintf("invalid operation run configuration: %v", prep.prepareErr),
			),
		), nil
	}

	if !prep.hasRuntimeConfiguration() {
		return newStopDecision(
			failRunTransition("invalid operation run configuration"),
		), nil
	}

	if prep.summary.targetCount == 0 {
		return newStopDecision(failRunTransition("operation run has no targets")), nil
	}

	if prep.run.Status.IsTerminal() {
		return newStopDecision(dispatchRunTransition{}), nil
	}

	if prep.summary.isAllTerminal() {
		if prep.summary.failedOrTerminated == prep.summary.targetCount {
			return newStopDecision(failRunTransition("operation run failed")), nil
		}

		if prep.summary.failedOrTerminated > 0 {
			return newStopDecision(
				dispatchRunTransition{
					kind:    dispatchRunTransitionCompleteWithFailures,
					message: "operation run completed with failed targets",
				},
			), nil
		}

		return newStopDecision(
			dispatchRunTransition{
				kind:    dispatchRunTransitionComplete,
				message: "operation run completed",
			},
		), nil
	}

	phase := prep.summary.currentPhase
	targets := prep.summary.currentPhaseTargets

	conflictDecision := prep.conflictPolicy.evaluate(targets, now)
	if conflictDecision.pause {
		return newStopDecision(
			pauseRunTransition(conflictDecision.reason, conflictDecision.message),
		), nil
	}

	safetyDecision := prep.safetyPolicy.evaluate(
		targets,
		prep.summary.completedPhaseTargets,
	)
	if safetyDecision.pause {
		return newStopDecision(
			pauseRunTransition(safetyDecision.reason, safetyDecision.message),
		), nil
	}

	phaseDecision := prep.phasePolicy.evaluate(
		targets,
		phase,
		prep.summary.previousPhaseTerminalChanged(),
	)
	if phaseDecision.pause {
		return newStopDecision(
			pauseRunTransition(phaseDecision.reason, phaseDecision.message),
		), nil
	}

	return newClaimDecision(
		startRunTransition(phaseDecision.message),
		prep.options,
		prep.op,
		prep.conflictPolicy,
		targets,
	), nil
}
