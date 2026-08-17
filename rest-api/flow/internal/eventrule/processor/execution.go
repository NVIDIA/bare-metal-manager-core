// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	"github.com/google/uuid"
)

func (p *Processor) processAction(
	ctx context.Context,
	prepared preparedEvent,
	action eventrule.Action,
) error {
	// Check action eligibility and construct a validated execution claim.
	claim, err := p.precheckExecution(prepared, action)
	if err != nil || claim == nil {
		return err
	}

	// Atomically claim the action's delivery and optional semantic-dedupe
	// identity. A nil preparation request is an accepted duplicate.
	prepareReq, err := p.claimExecution(ctx, *claim, prepared, action)
	if err != nil || prepareReq == nil {
		return err
	}

	// Prepare the action-specific request or outcome.
	result, err := p.prepareExecution(ctx, *prepareReq)
	if err != nil {
		return err
	}

	// Execute a prepared request, or carry forward a preparation outcome.
	outcome, err := p.performExecution(ctx, result)
	if err != nil {
		return err
	}

	// Persist the resulting execution state.
	return p.persistExecution(ctx, prepareReq.Execution.ID, outcome)
}

func (p *Processor) precheckExecution(
	prepared preparedEvent,
	action eventrule.Action,
) (*eventrule.ExecutionClaim, error) {
	if !action.Condition.AppliesTo(
		prepared.Envelope,
		prepared.Enriched.ResolvedResource,
	) {
		return nil, nil
	}

	claim, err := eventrule.NewExecutionClaim(
		prepared.Envelope,
		*prepared.Rule,
		action.ID,
		p.now(),
	)
	if err != nil {
		return nil, terminalError(err)
	}

	return &claim, nil
}

func (p *Processor) claimExecution(
	ctx context.Context,
	claim eventrule.ExecutionClaim,
	prepared preparedEvent,
	action eventrule.Action,
) (*executor.PrepareRequest, error) {
	execution, err := p.executions.Claim(ctx, claim)
	if err != nil || execution == nil {
		return nil, err
	}

	return &executor.PrepareRequest{
		Execution: *execution,
		Envelope:  prepared.Envelope,
		Resource:  prepared.Enriched.ResolvedResource,
		Action:    action,
	}, nil
}

func (p *Processor) prepareExecution(
	ctx context.Context,
	prepareReq executor.PrepareRequest,
) (executor.PreparationResult, error) {
	result, err := p.executor.Prepare(ctx, prepareReq)
	if err != nil {
		return executor.PreparationResult{}, terminalError(
			fmt.Errorf("executor preparation failed: %w", err),
		)
	}

	// Defensively validate the result at the executor boundary even though
	// implementations are required to return a valid result with a nil error.
	if err := result.Validate(); err != nil {
		return executor.PreparationResult{}, terminalError(err)
	}

	return result, nil
}

func (p *Processor) performExecution(
	ctx context.Context,
	result executor.PreparationResult,
) (eventrule.ExecutionState, error) {
	// A preparation outcome already represents the resulting state, so no
	// action execution is needed.
	if result.Outcome != nil {
		return *result.Outcome, nil
	}

	outcome, err := p.executor.Execute(ctx, *result.Request)
	if err != nil {
		return eventrule.ExecutionState{}, terminalError(
			fmt.Errorf("executor execution failed: %w", err),
		)
	}

	// Defensively validate the outcome at the executor boundary even though
	// implementations are required to return a valid outcome with a nil error.
	if err := outcome.ValidateTransition(); err != nil {
		return eventrule.ExecutionState{}, terminalError(err)
	}

	return outcome, nil
}

func (p *Processor) persistExecution(
	ctx context.Context,
	executionID uuid.UUID,
	outcome eventrule.ExecutionState,
) error {
	_, err := p.executions.Transition(ctx, executionID, outcome, p.now().UTC())
	return err
}
