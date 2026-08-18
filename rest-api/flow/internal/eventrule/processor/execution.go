// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/target"
	"github.com/google/uuid"
)

// initialRetryDelay prevents a transient creator-attempt failure from becoming
// immediately due. The scheduler owns delay policy after the first attempt.
// It is global because per-rule retry customization is not required and would
// unnecessarily expand the persisted rule contract.
const initialRetryDelay = 5 * time.Second

// executionPersistTimeout bounds result persistence after detaching it from
// the attempt context so cancellation cannot leave the execution pending.
const executionPersistTimeout = 5 * time.Second

func (p *Processor) processAction(
	ctx context.Context,
	prepared preparedEvent,
	action eventrule.Action,
) error {
	// Check action eligibility before creating durable state.
	if !action.Condition.AppliesTo(prepared.Envelope, prepared.Resource) {
		return nil
	}

	// Atomically create or deduplicate the execution. A nil execution is a
	// deduplication result and must not be dispatched.
	execution, err := p.executions.CreateExecution(
		ctx,
		eventrule.ExecutionIdentity{
			EventID:        prepared.Envelope.ID,
			RuleID:         prepared.Rule.ID,
			ActionID:       action.ID,
			CorrelationKey: prepared.Envelope.CorrelationKey,
		},
		prepared.Rule.Dedupe.Clone(),
	)
	if err != nil || execution == nil {
		return err
	}

	// Resolve targets or persist the resulting target-resolution result.
	targets, result := p.resolveTargets(ctx, prepared, action)
	if result != nil {
		return p.persistExecution(ctx, execution.ID, *result)
	}

	// Execute the action and persist the resulting state.
	return p.executeAction(ctx, execution, action, targets)
}

func (p *Processor) resolveTargets(
	ctx context.Context,
	prepared preparedEvent,
	action eventrule.Action,
) ([]target.Target, *eventrule.ExecutionResult) {
	strategy := action.Spec.TargetResolutionStrategy()
	if !strategy.RequiresResolution() {
		return nil, nil
	}

	targets, err := p.targets.Resolve(
		ctx,
		target.ResolveRequest{
			Envelope: prepared.Envelope,
			Resource: prepared.Resource,
			Strategy: strategy,
		},
	)
	if err != nil {
		if isTerminalTargetError(err) {
			result := eventrule.FailedExecutionResult(err.Error())
			return nil, &result
		}

		result := eventrule.DeferredExecutionResult(
			eventrule.ExecutionReasonAttemptFailed,
			err.Error(),
			initialRetryDelay,
		)
		return nil, &result
	}

	if len(targets) == 0 {
		result := eventrule.SkippedExecutionResult(
			eventrule.ExecutionReasonNoTargets,
		)
		return nil, &result
	}

	return targets, nil
}

func (p *Processor) executeAction(
	ctx context.Context,
	execution *eventrule.Execution,
	action eventrule.Action,
	targets []target.Target,
) error {
	result, err := p.executor.Execute(ctx, executor.ExecutionRequest{
		Execution: *execution,
		Action:    action,
		Targets:   targets,
	})
	if err != nil {
		if ctx.Err() != nil ||
			errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			result = eventrule.DeferredExecutionResult(
				eventrule.ExecutionReasonAttemptInterrupted,
				fmt.Sprintf("executor execution interrupted: %v", err),
				initialRetryDelay,
			)
		} else {
			result = eventrule.FailedExecutionResult(
				fmt.Sprintf("executor execution failed: %v", err),
			)
		}
	} else if err := result.Validate(); err != nil {
		result = eventrule.FailedExecutionResult(
			fmt.Sprintf("invalid executor result: %v", err),
		)
	}

	return p.persistExecution(ctx, execution.ID, result)
}

func (p *Processor) persistExecution(
	ctx context.Context,
	executionID uuid.UUID,
	result eventrule.ExecutionResult,
) error {
	persistCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		executionPersistTimeout,
	)
	defer cancel()

	_, err := p.executions.TransitionExecution(
		persistCtx,
		executionID,
		result,
	)
	return err
}
