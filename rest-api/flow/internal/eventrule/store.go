// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/google/uuid"
)

// ErrRuleNotFound identifies an unsuccessful rule lookup.
var ErrRuleNotFound = errors.New("event rule not found")

// ErrInvalidPersistedRule identifies persisted rule data that cannot be
// decoded into a valid domain rule. Retrying without repairing the stored data
// cannot succeed.
var ErrInvalidPersistedRule = errors.New("invalid persisted event rule")

// ErrInvalidPersistedEvent identifies persisted event data that cannot be
// decoded into a valid durable event.
var ErrInvalidPersistedEvent = errors.New("invalid persisted event")

// ErrInvalidPersistedExecution identifies persisted execution data that
// cannot be decoded into a valid domain execution.
var ErrInvalidPersistedExecution = errors.New("invalid persisted event execution")

// ErrExecutionNotFound identifies an unsuccessful execution lookup.
var ErrExecutionNotFound = errors.New("execution not found")

// ErrEventNotFound identifies an unsuccessful durable event lookup.
var ErrEventNotFound = errors.New("event not found")

// ErrExecutionAlreadyExists identifies an execution identity that existed
// before its event plan was committed.
var ErrExecutionAlreadyExists = errors.New("execution already exists")

// ErrExecutionClaimLost identifies a fenced update from a worker that no
// longer owns the execution attempt.
var ErrExecutionClaimLost = errors.New("execution claim lost")

const maxExecutionClaimOwnerRunes = 128

// ValidateExecutionClaimOwner checks that a claim owner is a bounded, nonempty
// identity.
func ValidateExecutionClaimOwner(owner string) error {
	if err := validateRequiredString("execution claim owner", owner); err != nil {
		return err
	}
	if utf8.RuneCountInString(owner) > maxExecutionClaimOwnerRunes {
		return fmt.Errorf(
			"execution claim owner exceeds %d characters",
			maxExecutionClaimOwnerRunes,
		)
	}

	return nil
}

// ExecutionClaimRequest bounds one atomic scheduler-store selection.
type ExecutionClaimRequest struct {
	Owner string
	Limit int
}

// Validate checks the owner and claim limit.
func (r ExecutionClaimRequest) Validate() error {
	if err := ValidateExecutionClaimOwner(r.Owner); err != nil {
		return err
	}
	if r.Limit <= 0 {
		return fmt.Errorf("execution claim limit must be positive")
	}

	return nil
}

// ClaimedExecution contains one running execution and its ownership fence.
// Token is not a downstream idempotency key.
type ClaimedExecution struct {
	Execution Execution
	Token     uuid.UUID
}

// Validate checks the running execution and ownership fence.
func (c ClaimedExecution) Validate() error {
	if err := c.Execution.Validate(); err != nil {
		return fmt.Errorf("execution: %w", err)
	}

	if c.Execution.Status != ExecutionStatusRunning {
		return fmt.Errorf(
			"claimed execution %s has status %q, want %q",
			c.Execution.ID,
			c.Execution.Status,
			ExecutionStatusRunning,
		)
	}
	if c.Token == uuid.Nil {
		return fmt.Errorf("execution claim token is required")
	}
	if c.Execution.ClaimToken != c.Token {
		return fmt.Errorf("execution claim token does not match running execution")
	}

	return nil
}

// RuleFilter limits rules returned by a store.
type RuleFilter struct {
	EventType *Type
	Origin    *RuleOrigin
	Enabled   *bool
}

// Matches reports whether a rule satisfies every configured filter field.
func (f RuleFilter) Matches(rule *Rule) bool {
	if rule == nil {
		return false
	}

	if f.EventType != nil && rule.EventType != *f.EventType {
		return false
	}
	if f.Origin != nil && rule.Origin != *f.Origin {
		return false
	}
	if f.Enabled != nil && rule.Enabled != *f.Enabled {
		return false
	}

	return true
}

// RuleReader is the common read capability for built-in and persisted rules.
type RuleReader interface {
	GetByID(context.Context, uuid.UUID) (*Rule, error)
	List(context.Context, RuleFilter) ([]*Rule, error)
}

// BuiltInRuleReader adds unique event-type lookup for built-in rules.
type BuiltInRuleReader interface {
	RuleReader
	GetByEventType(context.Context, Type) (*Rule, error)
}

// RuleStore manages persisted rule lifecycle operations. Callers must validate
// domain values before passing them to mutation methods. Implementations remain
// responsible for enforcing aggregate and persistence invariants before writes.
// Mutations targeting an unknown rule ID must return ErrRuleNotFound.
type RuleStore interface {
	RuleReader
	// Create persists a manager-constructed rule and returns the stored rule,
	// including any persistence-generated timestamps.
	Create(context.Context, *Rule) (*Rule, error)
	UpdateMetadata(context.Context, uuid.UUID, RuleMetadata) error
	ReplaceActions(context.Context, uuid.UUID, []Action) error
	// Delete atomically deletes a persisted rule and all of its bindings.
	// Implementations own the transaction that enforces this invariant.
	Delete(context.Context, uuid.UUID) error
	SetEnabled(context.Context, uuid.UUID, bool) error
}

// BindingStore manages persisted rule bindings and scope lookup.
type BindingStore interface {
	Bind(context.Context, Binding) error
	// Unbind returns ErrRuleNotFound when the binding ID does not exist.
	Unbind(context.Context, uuid.UUID) error
	// GetForScope returns the binding for an event type and scope. When no
	// binding exists, implementations must return (nil, nil).
	GetForScope(context.Context, Type, Scope) (*Binding, error)
}

// EventPlanStore owns the source-event duplicate fast path and atomic event-plan
// commit. Implementations own all persistence timestamps.
type EventPlanStore interface {
	// ObserveEvent records an existing event observation and returns (nil, nil)
	// when no event is persisted.
	ObserveEvent(context.Context, EventKey) (*Event, error)
	// CommitEventPlan is all-or-nothing: it persists the event and one execution
	// per planned action in the same transaction. A concurrent duplicate records
	// another observation and returns (nil, nil). Any error persists nothing.
	CommitEventPlan(
		ctx context.Context,
		event Event,
		planned []PlannedExecution,
	) (*Event, error)
}

// ExecutionStore owns scheduler claims and fenced attempt outcomes.
// Implementations own all persistence and retry timestamps.
type ExecutionStore interface {
	// ClaimPendingExecutions atomically selects at most request.Limit pending
	// rows, moves them to running, allocates attempts, and assigns request.Owner
	// and fencing tokens.
	ClaimPendingExecutions(
		ctx context.Context,
		request ExecutionClaimRequest,
	) ([]ClaimedExecution, error)
	// ClaimRetryExecutions atomically selects at most request.Limit due retry
	// rows, moves them to running, allocates attempts, and assigns request.Owner
	// and fencing tokens.
	ClaimRetryExecutions(
		ctx context.Context,
		request ExecutionClaimRequest,
	) ([]ClaimedExecution, error)
	// TransitionClaimedExecution persists an attempt outcome only while token
	// owns the running execution.
	TransitionClaimedExecution(
		ctx context.Context,
		executionID uuid.UUID,
		token uuid.UUID,
		result ExecutionResult,
	) error
}

// ExecutionTaskStore persists the normalized one-to-many relationship between
// executions and their rack-partitioned downstream tasks.
type ExecutionTaskStore interface {
	// GetExecutionTask returns the task associated with one execution and rack.
	// A missing association returns (nil, nil).
	GetExecutionTask(
		ctx context.Context,
		executionID uuid.UUID,
		rackID uuid.UUID,
	) (*ExecutionTask, error)
	// CreateExecutionTask atomically creates an association or returns the
	// existing association for the same execution and rack.
	CreateExecutionTask(
		ctx context.Context,
		association ExecutionTask,
	) (*ExecutionTask, error)
}
