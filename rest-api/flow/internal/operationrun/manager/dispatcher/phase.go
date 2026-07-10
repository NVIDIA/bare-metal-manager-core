// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"

	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
)

type phasePolicyRuntime struct {
	autoAdvance bool
}

func newPhasePolicy(options *operationrun.Options) (*phasePolicyRuntime, error) {
	if err := options.PhasePolicy.Validate(); err != nil {
		return nil, fmt.Errorf("phase policy: %w", err)
	}

	return &phasePolicyRuntime{
		autoAdvance: options.PhasePolicy.AdvancePolicy.AutoAdvance,
	}, nil
}

func (p phasePolicyRuntime) evaluate(
	summary operationrun.TargetPhaseSummary,
	previousPhaseTerminalChanged bool,
) pauseDecision {
	if summary.CurrentPhaseIndex == 0 ||
		!previousPhaseTerminalChanged ||
		!summary.CurrentPhaseNotStarted() {
		// No phase boundary was crossed into a fresh phase, so there is
		// nothing for phase policy to pause or report.
		return pauseDecision{
			pause: false,
		}
	}

	if p.autoAdvance {
		return pauseDecision{
			pause:   false,
			message: "advanced to next phase",
		}
	}

	return pauseDecision{
		pause:   true,
		reason:  operationrun.OperationRunStatusReasonPhaseGate,
		message: "waiting for phase advance",
	}
}
