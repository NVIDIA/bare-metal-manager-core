// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"

	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
)

type safetyPolicyRuntime struct {
	gates []operationrun.SafetyGate
}

func newSafetyPolicy(options *operationrun.Options) (*safetyPolicyRuntime, error) {
	gates := make([]operationrun.SafetyGate, 0, len(options.SafetyPolicy.Gates))
	for idx, gate := range options.SafetyPolicy.Gates {
		if gate == nil {
			return nil, fmt.Errorf("safety gate %d is required", idx)
		}

		if err := gate.Validate(); err != nil {
			return nil, fmt.Errorf("safety gate %d: %w", idx, err)
		}

		gates = append(gates, gate)
	}

	return &safetyPolicyRuntime{gates: gates}, nil
}

// evaluate checks the configured safety gates against either the current phase
// or the cumulative run scope.
func (p safetyPolicyRuntime) evaluate(
	current []*operationrun.OperationRunTarget,
	completed []*operationrun.OperationRunTarget,
) pauseDecision {
	for _, gate := range p.gates {
		stats := statsForScope(current, completed, gate.SafetyGateScope())
		if !gate.IsTripped(stats.failed, stats.total) {
			continue
		}

		return pauseDecision{
			pause:   true,
			reason:  operationrun.OperationRunStatusReasonSafetyGate,
			message: safetyGateTrippedMessage(gate, stats),
		}
	}

	return pauseDecision{}
}

func safetyGateTrippedMessage(
	gate operationrun.SafetyGate,
	stats safetyGateStats,
) string {
	scope := gate.SafetyGateScope()
	if scope == "" {
		scope = operationrun.SafetyGateScopeCurrentPhase
	}

	switch typed := gate.(type) {
	case *operationrun.FailureRateGate:
		return fmt.Sprintf(
			"%s safety gate tripped for %s: %d/%d targets failed (%d%%, threshold %d%%)",
			gate.SafetyGateKind(),
			scope,
			stats.failed,
			stats.total,
			failurePercent(stats),
			typed.FailureThresholdPercent,
		)
	case *operationrun.FailureCountGate:
		return fmt.Sprintf(
			"%s safety gate tripped for %s: %d/%d targets failed (threshold %d)",
			gate.SafetyGateKind(),
			scope,
			stats.failed,
			stats.total,
			typed.FailureThresholdCount,
		)
	default:
		return fmt.Sprintf(
			"%s safety gate tripped for %s: %d/%d targets failed",
			gate.SafetyGateKind(),
			scope,
			stats.failed,
			stats.total,
		)
	}
}

func failurePercent(stats safetyGateStats) int {
	if stats.total == 0 {
		return 0
	}
	return stats.failed * 100 / stats.total
}

type safetyGateStats struct {
	failed int
	total  int
}

// statsForScope aggregates target outcomes over the safety-gate scope selected
// by the user.
func statsForScope(
	current []*operationrun.OperationRunTarget,
	completed []*operationrun.OperationRunTarget,
	scope operationrun.SafetyGateScope,
) safetyGateStats {
	stats := safetyGateStats{}
	stats.add(current)
	if scope != operationrun.SafetyGateScopeCumulativeRun {
		return stats
	}

	stats.add(completed)
	return stats
}

func (s *safetyGateStats) add(targets []*operationrun.OperationRunTarget) {
	for _, target := range targets {
		s.total++
		if target.Status == operationrun.OperationRunTargetStatusFailed {
			s.failed++
		}
	}
}
