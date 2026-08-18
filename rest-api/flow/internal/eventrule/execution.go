// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// ExecutionStatus identifies one execution state.
type ExecutionStatus string

const (
	ExecutionStatusPending   ExecutionStatus = "pending"
	ExecutionStatusSkipped   ExecutionStatus = "skipped"
	ExecutionStatusDeferred  ExecutionStatus = "deferred"
	ExecutionStatusSubmitted ExecutionStatus = "submitted"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
)

// CanTransitionTo reports whether an execution with this status may accept an
// attempt result. Pending is used by the creator's first attempt; deferred is
// used by scheduler-owned retries.
func (s ExecutionStatus) CanTransitionTo(target ExecutionStatus) bool {
	if s != ExecutionStatusPending && s != ExecutionStatusDeferred {
		return false
	}
	return target == ExecutionStatusSubmitted ||
		target == ExecutionStatusCompleted ||
		target == ExecutionStatusSkipped ||
		target == ExecutionStatusDeferred ||
		target == ExecutionStatusFailed
}

// RequiresRetryScheduling reports whether the status requires the store to
// calculate a next-attempt time.
func (s ExecutionStatus) RequiresRetryScheduling() bool {
	return s == ExecutionStatusDeferred
}

// ExecutionReason identifies the stable reason for an informational execution
// result without expanding the status state machine.
type ExecutionReason string

const (
	ExecutionReasonNone               ExecutionReason = ""
	ExecutionReasonNoTargets          ExecutionReason = "no_targets"
	ExecutionReasonAttemptFailed      ExecutionReason = "attempt_failed"
	ExecutionReasonAttemptInterrupted ExecutionReason = "attempt_interrupted"
)

// ExecutionStatusDetails contains the status fields shared by durable state
// and attempt results.
type ExecutionStatusDetails struct {
	Status        ExecutionStatus
	Reason        ExecutionReason
	StatusMessage string
}

// Validate checks that the status, reason, and message are internally
// consistent.
func (d ExecutionStatusDetails) Validate() error {
	reasons, ok := executionStatusReasons[d.Status]
	if !ok {
		return fmt.Errorf("unknown execution status %q", d.Status)
	}

	if len(reasons) == 0 {
		if d.Reason != ExecutionReasonNone {
			return fmt.Errorf(
				"%s execution cannot have reason %q",
				d.Status,
				d.Reason,
			)
		}
	} else if !slices.Contains(reasons, d.Reason) {
		return fmt.Errorf(
			"%s execution requires one of reasons %q",
			d.Status,
			reasons,
		)
	}

	return validateOptionalString("execution status message", d.StatusMessage)
}

// ExecutionState contains the status-dependent state of an execution.
type ExecutionState struct {
	ExecutionStatusDetails
	NextAttemptAt time.Time
}

// Validate checks that the execution state is internally consistent.
func (s ExecutionState) Validate() error {
	if err := s.ExecutionStatusDetails.Validate(); err != nil {
		return err
	}

	if s.Status.RequiresRetryScheduling() {
		if s.NextAttemptAt.IsZero() {
			return fmt.Errorf("%s execution requires next attempt time", s.Status)
		}
	} else {
		if !s.NextAttemptAt.IsZero() {
			return fmt.Errorf("%s execution cannot have next attempt time", s.Status)
		}
	}

	return nil
}

// RetryDue reports whether a deferred execution is eligible for the scheduler
// to dispatch at the given time.
func (s ExecutionState) RetryDue(now time.Time) bool {
	return s.Status.RequiresRetryScheduling() &&
		!s.NextAttemptAt.IsZero() &&
		!now.Before(s.NextAttemptAt)
}

var executionStatusReasons = map[ExecutionStatus][]ExecutionReason{
	ExecutionStatusPending: nil,
	ExecutionStatusSkipped: {
		ExecutionReasonNoTargets,
	},
	ExecutionStatusDeferred: {
		ExecutionReasonAttemptFailed,
		ExecutionReasonAttemptInterrupted,
	},
	ExecutionStatusSubmitted: nil,
	ExecutionStatusCompleted: nil,
	ExecutionStatusFailed:    nil,
}

// ExecutionResult describes the result of one dispatch attempt. Deferred
// results carry a relative delay so the store can derive NextAttemptAt from
// its authoritative clock. A zero delay makes the retry immediately eligible.
type ExecutionResult struct {
	ExecutionStatusDetails
	RetryAfter time.Duration
}

// SubmittedExecutionResult creates a submitted dispatch result.
func SubmittedExecutionResult() ExecutionResult {
	return ExecutionResult{
		ExecutionStatusDetails: ExecutionStatusDetails{
			Status: ExecutionStatusSubmitted,
		},
	}
}

// CompletedExecutionResult creates a completed dispatch result.
func CompletedExecutionResult() ExecutionResult {
	return ExecutionResult{
		ExecutionStatusDetails: ExecutionStatusDetails{
			Status: ExecutionStatusCompleted,
		},
	}
}

// SkippedExecutionResult creates a skipped dispatch result.
func SkippedExecutionResult(reason ExecutionReason) ExecutionResult {
	return ExecutionResult{
		ExecutionStatusDetails: ExecutionStatusDetails{
			Status: ExecutionStatusSkipped,
			Reason: reason,
		},
	}
}

// DeferredExecutionResult creates a deferred dispatch result.
func DeferredExecutionResult(
	reason ExecutionReason,
	statusMessage string,
	retryAfter time.Duration,
) ExecutionResult {
	return ExecutionResult{
		ExecutionStatusDetails: ExecutionStatusDetails{
			Status:        ExecutionStatusDeferred,
			Reason:        reason,
			StatusMessage: statusMessage,
		},
		RetryAfter: retryAfter,
	}
}

// FailedExecutionResult creates a failed dispatch result.
func FailedExecutionResult(statusMessage string) ExecutionResult {
	return ExecutionResult{
		ExecutionStatusDetails: ExecutionStatusDetails{
			Status:        ExecutionStatusFailed,
			StatusMessage: statusMessage,
		},
	}
}

// Validate checks that the dispatch result is internally consistent.
func (r ExecutionResult) Validate() error {
	if r.Status == ExecutionStatusPending {
		return fmt.Errorf("pending is not an execution result")
	}

	if err := r.ExecutionStatusDetails.Validate(); err != nil {
		return err
	}

	if r.Status.RequiresRetryScheduling() {
		if r.RetryAfter < 0 {
			return fmt.Errorf("deferred execution retry delay cannot be negative")
		}
	} else {
		if r.RetryAfter != 0 {
			return fmt.Errorf("%s execution cannot have retry delay", r.Status)
		}
	}

	return nil
}

func (r ExecutionResult) stateAt(now time.Time) ExecutionState {
	state := ExecutionState{
		ExecutionStatusDetails: r.ExecutionStatusDetails,
	}
	if r.Status.RequiresRetryScheduling() {
		state.NextAttemptAt = now.Add(r.RetryAfter)
	}
	return state
}

// ExecutionIdentity contains the source fields used to derive an
// execution's delivery and semantic-deduplication keys.
type ExecutionIdentity struct {
	EventID        uuid.UUID
	RuleID         uuid.UUID
	ActionID       string
	CorrelationKey string
}

// Validate checks the execution identity.
func (i ExecutionIdentity) Validate() error {
	if i.EventID == uuid.Nil {
		return fmt.Errorf("event id is required")
	}
	if i.RuleID == uuid.Nil {
		return fmt.Errorf("event rule id is required")
	}
	if err := validateRequiredString("event rule action id", i.ActionID); err != nil {
		return err
	}
	return validateOptionalString("event correlation_key", i.CorrelationKey)
}

// ExecutionDeliveryKey identifies one rule action for one delivered event.
type ExecutionDeliveryKey struct {
	EventID  uuid.UUID
	RuleID   uuid.UUID
	ActionID string
}

// ExecutionSemanticKey identifies one correlated rule action
// independently of an individual event delivery.
type ExecutionSemanticKey struct {
	RuleID         uuid.UUID
	ActionID       string
	CorrelationKey string
}

// DeliveryKey returns the delivery identity.
func (i ExecutionIdentity) DeliveryKey() ExecutionDeliveryKey {
	return ExecutionDeliveryKey{
		EventID:  i.EventID,
		RuleID:   i.RuleID,
		ActionID: i.ActionID,
	}
}

// SemanticKey returns the semantic-deduplication identity.
func (i ExecutionIdentity) SemanticKey() ExecutionSemanticKey {
	return ExecutionSemanticKey{
		RuleID:         i.RuleID,
		ActionID:       i.ActionID,
		CorrelationKey: i.CorrelationKey,
	}
}

// Execution records the durable processing state for one rule action.
type Execution struct {
	ExecutionState
	ExecutionIdentity
	ID           uuid.UUID
	Observations int
	Attempts     int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (e *Execution) recordObservation(now time.Time) {
	e.Observations++
	if now.After(e.UpdatedAt) {
		e.UpdatedAt = now
	}
}

// TryDeduplicate reports whether an observation is within the deduplication
// window and records it when it is.
func (e *Execution) TryDeduplicate(dedupe *Dedupe, observedAt time.Time) bool {
	if dedupe == nil || !dedupe.WithinWindow(e.CreatedAt, observedAt) {
		return false
	}

	e.recordObservation(observedAt)
	return true
}

// TransitionTo validates and applies an attempt result at the given time. A
// transition from deferred records the scheduler retry that produced the new
// result. Dispatch ownership is intentionally separate from domain status;
// the future scheduler store adds lease fencing around this transition.
func (e *Execution) TransitionTo(result ExecutionResult, now time.Time) error {
	if e == nil {
		return fmt.Errorf("execution is nil")
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

	if e.Status == ExecutionStatusDeferred {
		e.Attempts++
	}
	e.ExecutionState = result.stateAt(now)
	if now.After(e.UpdatedAt) {
		e.UpdatedAt = now
	}
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
	if err := e.ExecutionIdentity.Validate(); err != nil {
		return err
	}
	if e.Observations <= 0 {
		return fmt.Errorf("execution observations must be positive")
	}
	if e.Attempts <= 0 {
		return fmt.Errorf("execution attempts must be positive")
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

	return e.ExecutionState.Validate()
}

// NewExecution constructs a pending execution using the store-provided
// creation time.
func NewExecution(
	identity ExecutionIdentity,
	now time.Time,
) (*Execution, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, fmt.Errorf("execution creation time is required")
	}

	return &Execution{
		ExecutionState: ExecutionState{
			ExecutionStatusDetails: ExecutionStatusDetails{
				Status: ExecutionStatusPending,
			},
		},
		ExecutionIdentity: identity,
		ID:                uuid.New(),
		Observations:      1,
		Attempts:          1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}, nil
}
