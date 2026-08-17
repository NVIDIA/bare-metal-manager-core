// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// ErrRetryScheduled indicates that an existing execution is not yet eligible
// to resume.
var ErrRetryScheduled = errors.New("event action retry is scheduled")

// ExecutionStatus identifies one action execution state.
type ExecutionStatus string

const (
	ExecutionStatusClaimed   ExecutionStatus = "claimed"
	ExecutionStatusSkipped   ExecutionStatus = "skipped"
	ExecutionStatusDeferred  ExecutionStatus = "deferred"
	ExecutionStatusSubmitted ExecutionStatus = "submitted"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
)

// CanTransitionTo reports whether an execution with this status may transition
// to the target status.
func (s ExecutionStatus) CanTransitionTo(target ExecutionStatus) bool {
	if s != ExecutionStatusClaimed {
		return false
	}
	return target == ExecutionStatusSubmitted ||
		target == ExecutionStatusCompleted ||
		target == ExecutionStatusSkipped ||
		target == ExecutionStatusDeferred ||
		target == ExecutionStatusFailed
}

// ExecutionReason identifies the stable reason for an informational execution
// outcome without expanding the status state machine.
type ExecutionReason string

const (
	ExecutionReasonNone          ExecutionReason = ""
	ExecutionReasonNoTargets     ExecutionReason = "no_targets"
	ExecutionReasonAttemptFailed ExecutionReason = "attempt_failed"
)

type executionStateContract struct {
	reasons               []ExecutionReason
	requiresNextAttemptAt bool
}

// ExecutionState contains the status-dependent state of an execution.
type ExecutionState struct {
	Status        ExecutionStatus
	Reason        ExecutionReason
	StatusMessage string
	NextAttemptAt time.Time
}

// Validate checks that the execution state is internally consistent.
func (s ExecutionState) Validate() error {
	contract, ok := executionStateContracts[s.Status]
	if !ok {
		return fmt.Errorf("unknown execution status %q", s.Status)
	}
	return contract.validate(s)
}

// ValidateTransition checks that the execution state is a valid transition
// target. Claimed state is established by Claim and cannot be requested through
// Transition.
func (s ExecutionState) ValidateTransition() error {
	if s.Status == ExecutionStatusClaimed {
		return fmt.Errorf("cannot transition execution to claimed status")
	}
	return s.Validate()
}

// RetryDue reports whether a deferred execution is eligible to be claimed at
// the given time.
func (s ExecutionState) RetryDue(now time.Time) bool {
	return s.Status == ExecutionStatusDeferred &&
		!s.NextAttemptAt.IsZero() &&
		!now.Before(s.NextAttemptAt)
}

var executionStateContracts = map[ExecutionStatus]executionStateContract{
	ExecutionStatusClaimed: {},
	ExecutionStatusSkipped: {
		reasons: []ExecutionReason{ExecutionReasonNoTargets},
	},
	ExecutionStatusDeferred: {
		reasons:               []ExecutionReason{ExecutionReasonAttemptFailed},
		requiresNextAttemptAt: true,
	},
	ExecutionStatusSubmitted: {},
	ExecutionStatusCompleted: {},
	ExecutionStatusFailed:    {},
}

func (c executionStateContract) validate(state ExecutionState) error {
	if len(c.reasons) == 0 {
		if state.Reason != ExecutionReasonNone {
			return fmt.Errorf(
				"%s execution cannot have reason %q",
				state.Status,
				state.Reason,
			)
		}
	} else if !slices.Contains(c.reasons, state.Reason) {
		return fmt.Errorf(
			"%s execution requires one of reasons %q",
			state.Status,
			c.reasons,
		)
	}
	if c.requiresNextAttemptAt {
		if state.NextAttemptAt.IsZero() {
			return fmt.Errorf("%s execution requires next attempt time", state.Status)
		}
	} else {
		if !state.NextAttemptAt.IsZero() {
			return fmt.Errorf("%s execution cannot have next attempt time", state.Status)
		}
	}

	return validateOptionalString("execution status message", state.StatusMessage)
}

// Execution records the durable processing state for one rule action.
type Execution struct {
	ExecutionState
	ID             uuid.UUID
	EventID        uuid.UUID
	RuleID         uuid.UUID
	ActionID       string
	CorrelationKey string
	Observations   int
	Attempts       int
	FirstClaimedAt time.Time
	UpdatedAt      time.Time
}

// IsOwned reports whether the current execution attempt is owned for
// processing.
//
// TODO: Treating every claimed execution as owned is sufficient for the current
// single-process in-memory store, which does not need to distinguish competing
// workers. When the database-backed store is introduced, extend ownership with
// a claim token and lease expiration, and apply the same fencing semantics to
// the in-memory store so both implementations satisfy one store contract.
func (e Execution) IsOwned() bool {
	return e.Status == ExecutionStatusClaimed
}

func (e *Execution) recordObservation(now time.Time) {
	e.Observations++
	e.UpdatedAt = now
}

// TryDeduplicate reports whether an observation is within the deduplication
// window and records it when it is.
func (e *Execution) TryDeduplicate(dedupe *Dedupe, observedAt time.Time) bool {
	if dedupe == nil ||
		!dedupe.WithinWindow(e.FirstClaimedAt, observedAt) {
		return false
	}

	e.recordObservation(observedAt)

	return true
}

// TryClaim records another observation and attempts to acquire an existing
// execution. It returns the execution only when a due deferred execution is
// reclaimed, and returns an error when the receiver is nil. ErrRetryScheduled
// indicates that a deferred execution is not yet due.
func (e *Execution) TryClaim(now time.Time) (*Execution, error) {
	if e == nil {
		return nil, fmt.Errorf("event action execution is nil")
	}

	e.recordObservation(now)

	if !e.IsOwned() && e.ExecutionState.RetryDue(now) {
		e.ExecutionState = ExecutionState{Status: ExecutionStatusClaimed}
		e.Attempts++
		return e, nil
	}

	if e.Status == ExecutionStatusDeferred {
		return nil, fmt.Errorf("%w for %s", ErrRetryScheduled, e.NextAttemptAt)
	}

	return nil, nil
}

// TransitionTo validates and applies an execution state transition at the
// given time.
func (e *Execution) TransitionTo(state ExecutionState, now time.Time) error {
	if e == nil {
		return fmt.Errorf("event action execution is nil")
	}
	if !e.IsOwned() {
		return fmt.Errorf("execution %s is not owned", e.ID)
	}
	if err := state.ValidateTransition(); err != nil {
		return err
	}
	if !e.Status.CanTransitionTo(state.Status) {
		return fmt.Errorf(
			"execution %s cannot transition from %q to %q",
			e.ID,
			e.Status,
			state.Status,
		)
	}
	if now.IsZero() {
		return fmt.Errorf("execution transition time is required")
	}
	if now.Before(e.FirstClaimedAt) {
		return fmt.Errorf("execution transition time cannot precede first claimed time")
	}

	e.ExecutionState = state
	e.UpdatedAt = now
	return nil
}

// Validate checks the durable execution aggregate.
func (e *Execution) Validate() error {
	if e == nil {
		return fmt.Errorf("event action execution is nil")
	}
	if e.ID == uuid.Nil {
		return fmt.Errorf("event action execution id is required")
	}
	if e.EventID == uuid.Nil {
		return fmt.Errorf("event id is required")
	}
	if e.RuleID == uuid.Nil {
		return fmt.Errorf("event rule id is required")
	}
	if err := validateRequiredString("event rule action id", e.ActionID); err != nil {
		return err
	}
	if e.Observations <= 0 {
		return fmt.Errorf("execution observations must be positive")
	}
	if e.Attempts <= 0 {
		return fmt.Errorf("execution attempts must be positive")
	}
	if e.FirstClaimedAt.IsZero() {
		return fmt.Errorf("execution first claimed time is required")
	}
	if e.UpdatedAt.IsZero() {
		return fmt.Errorf("execution updated time is required")
	}
	if e.UpdatedAt.Before(e.FirstClaimedAt) {
		return fmt.Errorf("execution updated time cannot precede first claimed time")
	}

	return e.ExecutionState.Validate()
}

// ExecutionClaim identifies one delivery and optional semantic dedupe claim.
type ExecutionClaim struct {
	EventID        uuid.UUID
	RuleID         uuid.UUID
	ActionID       string
	CorrelationKey string
	Dedupe         *Dedupe
	Now            time.Time
}

// ExecutionDeliveryKey identifies one rule action for one delivered event.
type ExecutionDeliveryKey struct {
	EventID  uuid.UUID
	RuleID   uuid.UUID
	ActionID string
}

// ExecutionSemanticKey identifies one correlated rule action independently of
// an individual event delivery.
type ExecutionSemanticKey struct {
	RuleID         uuid.UUID
	ActionID       string
	CorrelationKey string
}

// DeliveryKey returns the delivery identity represented by the claim.
func (c ExecutionClaim) DeliveryKey() ExecutionDeliveryKey {
	return ExecutionDeliveryKey{
		EventID:  c.EventID,
		RuleID:   c.RuleID,
		ActionID: c.ActionID,
	}
}

// SemanticKey returns the semantic deduplication identity represented by the
// claim.
func (c ExecutionClaim) SemanticKey() ExecutionSemanticKey {
	return ExecutionSemanticKey{
		RuleID:         c.RuleID,
		ActionID:       c.ActionID,
		CorrelationKey: c.CorrelationKey,
	}
}

// NewExecution validates the claim and constructs its initial execution.
func (c ExecutionClaim) NewExecution() (*Execution, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c.NewExecutionUnchecked(), nil
}

// NewExecutionUnchecked constructs the initial execution without validating
// the claim. Callers must validate the claim before calling this method.
func (c ExecutionClaim) NewExecutionUnchecked() *Execution {
	return &Execution{
		ExecutionState: ExecutionState{
			Status: ExecutionStatusClaimed,
		},
		ID:             uuid.New(),
		EventID:        c.EventID,
		RuleID:         c.RuleID,
		ActionID:       c.ActionID,
		CorrelationKey: c.CorrelationKey,
		Observations:   1,
		Attempts:       1,
		FirstClaimedAt: c.Now,
		UpdatedAt:      c.Now,
	}
}

// Validate checks the delivery identity and optional semantic-deduplication
// fields of an execution claim.
func (c ExecutionClaim) Validate() error {
	if c.EventID == uuid.Nil {
		return fmt.Errorf("event id is required")
	}
	if c.RuleID == uuid.Nil {
		return fmt.Errorf("event rule id is required")
	}
	if err := validateRequiredString("event rule action id", c.ActionID); err != nil {
		return err
	}
	if c.Now.IsZero() {
		return fmt.Errorf("execution claim time is required")
	}
	if c.Dedupe != nil {
		if err := c.Dedupe.Validate(); err != nil {
			return fmt.Errorf("execution claim dedupe: %w", err)
		}
	}
	if c.Dedupe != nil && c.CorrelationKey == "" {
		return fmt.Errorf(
			"correlation key is required by rule %s dedupe policy",
			c.RuleID,
		)
	}
	return nil
}

// NewExecutionClaim derives the delivery and optional semantic-deduplication
// identity for one rule action.
func NewExecutionClaim(
	envelope Envelope,
	rule Rule,
	actionID string,
	now time.Time,
) (ExecutionClaim, error) {
	claim := ExecutionClaim{
		EventID:        envelope.ID,
		RuleID:         rule.ID,
		ActionID:       actionID,
		CorrelationKey: envelope.CorrelationKey,
		Dedupe:         rule.Dedupe.Clone(),
		Now:            now,
	}

	if err := claim.Validate(); err != nil {
		return ExecutionClaim{}, err
	}

	return claim, nil
}
