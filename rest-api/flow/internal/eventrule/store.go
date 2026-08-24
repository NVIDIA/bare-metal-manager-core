// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"context"
	"errors"

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

// ErrEventAlreadyPlanned identifies an attempt to replace a committed event
// plan.
var ErrEventAlreadyPlanned = errors.New("event already planned")

// ErrExecutionAlreadyExists identifies an execution identity that existed
// before its event plan was committed.
var ErrExecutionAlreadyExists = errors.New("execution already exists")

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

// EventStore owns source-event deduplication and observation accounting.
// ObserveEvent returns (nil, nil) when the source event has not been persisted.
// CreateEvent returns the newly inserted event. A concurrent duplicate is
// recorded as another observation and returns (nil, nil).
type EventStore interface {
	ObserveEvent(context.Context, EventKey) (*Event, error)
	CreateEvent(context.Context, Event) (*Event, error)
}

// ExecutionStore atomically commits an event's complete ordered plan and
// persists attempt results. CommitEventPlan creates every execution and marks
// the event planned in one transaction. It returns executions in the same
// order as planned and rejects replacement of a committed or partial plan.
// TransitionExecution returns ErrExecutionNotFound for an unknown
// execution ID. Implementations own planning, transition, and retry-scheduling
// timestamps.
type ExecutionStore interface {
	// CommitEventPlan is all-or-nothing: on success it persists one execution
	// per planned action, in the supplied order, and marks the event planned in
	// the same transaction. It returns those executions in the same order. On
	// error it persists no execution and leaves the event unplanned.
	CommitEventPlan(
		ctx context.Context,
		eventID uuid.UUID,
		planned []PlannedExecution,
	) ([]Execution, error)
	TransitionExecution(
		ctx context.Context,
		executionID uuid.UUID,
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
