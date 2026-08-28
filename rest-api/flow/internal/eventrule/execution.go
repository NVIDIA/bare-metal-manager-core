// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ExecutionKey identifies one action execution within a durable event.
type ExecutionKey struct {
	EventID    uuid.UUID
	ActionName string
}

// Validate checks the execution planning identity.
func (k ExecutionKey) Validate() error {
	if k.EventID == uuid.Nil {
		return fmt.Errorf("execution event id is required")
	}

	return ValidateIdentifier("event rule action name", k.ActionName)
}

// Execution records one immutable action plan and its mutable processing
// state.
type Execution struct {
	ExecutionState
	ID         uuid.UUID
	EventID    uuid.UUID
	ActionName string
	Plan       ExecutionPlan
	// Attempts counts attempts that consume the retry budget. Claiming an
	// execution allocates an attempt; an interrupted attempt is refunded when
	// the execution is deferred.
	Attempts   int
	ClaimToken uuid.UUID
	ClaimOwner string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Clone returns an independent execution snapshot.
func (e Execution) Clone() Execution {
	cloned := e
	cloned.Plan = CloneExecutionPlan(e.Plan)

	return cloned
}

// Claim allocates the next attempt and moves an eligible execution to running.
func (e *Execution) Claim(owner string, token uuid.UUID, now time.Time) error {
	if e == nil {
		return fmt.Errorf("execution is nil")
	}

	if !e.Status.CanBeClaimed() {
		return fmt.Errorf("execution %s cannot be claimed from %q", e.ID, e.Status)
	}

	if err := ValidateExecutionClaimOwner(owner); err != nil {
		return err
	}
	if token == uuid.Nil {
		return fmt.Errorf("execution claim token is required")
	}

	if now.IsZero() {
		return fmt.Errorf("execution claim time is required")
	}
	if now.Before(e.CreatedAt) {
		return fmt.Errorf("execution claim time cannot precede creation time")
	}
	if now.Before(e.UpdatedAt) {
		return fmt.Errorf("execution claim time cannot precede update time")
	}

	e.ExecutionState = ExecutionState{
		ExecutionStatusDetails: ExecutionStatusDetails{Status: ExecutionStatusRunning},
	}
	e.Attempts++
	e.ClaimToken = token
	e.ClaimOwner = owner
	e.UpdatedAt = now

	return nil
}

// TransitionClaimedTo validates and applies the active attempt's result when
// token still owns the execution.
func (e *Execution) TransitionClaimedTo(
	token uuid.UUID,
	result ExecutionResult,
	now time.Time,
) error {
	if e == nil {
		return fmt.Errorf("execution is nil")
	}

	if token == uuid.Nil {
		return fmt.Errorf("execution claim token is required")
	}
	if e.ClaimToken != token {
		return fmt.Errorf("%w: execution %s", ErrExecutionClaimLost, e.ID)
	}

	if err := result.Validate(); err != nil {
		return err
	}
	if !e.Status.CanTransitionTo(result.Status) {
		return fmt.Errorf(
			"execution %s cannot transition from %q to %q",
			e.ID,
			e.Status,
			result.Status,
		)
	}

	if now.IsZero() {
		return fmt.Errorf("execution transition time is required")
	}
	if now.Before(e.CreatedAt) {
		return fmt.Errorf("execution transition time cannot precede creation time")
	}
	if now.Before(e.UpdatedAt) {
		return fmt.Errorf("execution transition time cannot precede update time")
	}

	if result.Status == ExecutionStatusDeferred &&
		result.Reason == ExecutionReasonAttemptInterrupted {
		e.Attempts--
	}

	e.ExecutionState = result.stateAt(now)
	e.ClaimToken = uuid.Nil
	e.ClaimOwner = ""
	e.UpdatedAt = now

	return nil
}

// Validate checks the durable execution aggregate.
func (e *Execution) Validate() error {
	if e == nil {
		return fmt.Errorf("execution is nil")
	}

	if e.ID == uuid.Nil {
		return fmt.Errorf("execution id is required")
	}
	if err := e.Key().Validate(); err != nil {
		return err
	}
	if err := ValidateExecutionPlan(e.Plan); err != nil {
		return fmt.Errorf("execution plan: %w", err)
	}
	if err := e.ExecutionState.Validate(); err != nil {
		return err
	}

	if e.Attempts < 0 {
		return fmt.Errorf("execution attempts cannot be negative")
	}
	if (e.Status == ExecutionStatusPending || e.Status == ExecutionStatusSkipped) &&
		e.Attempts != 0 {
		return fmt.Errorf("%s execution cannot have attempts", e.Status)
	}
	if e.Status != ExecutionStatusPending &&
		e.Status != ExecutionStatusSkipped &&
		e.Attempts == 0 &&
		!(e.Status == ExecutionStatusDeferred &&
			e.Reason == ExecutionReasonAttemptInterrupted) {
		return fmt.Errorf("%s execution requires an attempt", e.Status)
	}

	if e.Status == ExecutionStatusRunning {
		if e.ClaimToken == uuid.Nil {
			return fmt.Errorf("running execution requires claim token")
		}
		if err := ValidateExecutionClaimOwner(e.ClaimOwner); err != nil {
			return err
		}
	} else {
		if e.ClaimToken != uuid.Nil {
			return fmt.Errorf("%s execution cannot have claim token", e.Status)
		}
		if e.ClaimOwner != "" {
			return fmt.Errorf("%s execution cannot have claim owner", e.Status)
		}
	}

	if e.CreatedAt.IsZero() {
		return fmt.Errorf("execution creation time is required")
	}
	if e.UpdatedAt.IsZero() {
		return fmt.Errorf("execution updated time is required")
	}
	if e.UpdatedAt.Before(e.CreatedAt) {
		return fmt.Errorf("execution updated time cannot precede creation time")
	}

	return nil
}

// NewExecution constructs an execution using the store-provided creation time.
// The plan determines the execution's initial status.
func NewExecution(
	eventID uuid.UUID,
	actionName string,
	plan ExecutionPlan,
	now time.Time,
) (*Execution, error) {
	key := ExecutionKey{EventID: eventID, ActionName: actionName}
	if err := key.Validate(); err != nil {
		return nil, err
	}

	if err := ValidateExecutionPlan(plan); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, fmt.Errorf("execution creation time is required")
	}

	return &Execution{
		ExecutionState: ExecutionState{
			ExecutionStatusDetails: plan.initialStatus(),
		},
		ID:         uuid.New(),
		EventID:    eventID,
		ActionName: actionName,
		Plan:       CloneExecutionPlan(plan),
		Attempts:   0,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

// Key returns the execution's idempotent planning identity.
func (e Execution) Key() ExecutionKey {
	return ExecutionKey{EventID: e.EventID, ActionName: e.ActionName}
}

// ExecutionTask records one rack-partitioned task created for an execution.
// An execution may have at most one associated task per rack.
type ExecutionTask struct {
	ExecutionID uuid.UUID
	RackID      uuid.UUID
	TaskID      uuid.UUID
}

// Validate checks the execution, rack, and task identities.
func (a ExecutionTask) Validate() error {
	if a.ExecutionID == uuid.Nil {
		return fmt.Errorf("execution id is required")
	}

	if a.RackID == uuid.Nil {
		return fmt.Errorf("rack id is required")
	}

	if a.TaskID == uuid.Nil {
		return fmt.Errorf("task id is required")
	}

	return nil
}
