// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrRuleNotFound identifies an unsuccessful rule lookup.
var ErrRuleNotFound = errors.New("event rule not found")

// ErrInvalidPersistedRule identifies persisted rule data that cannot be
// decoded into a valid domain rule. Retrying without repairing the stored data
// cannot succeed.
var ErrInvalidPersistedRule = errors.New("invalid persisted event rule")

// ErrInvalidPersistedExecution identifies persisted execution data that
// cannot be decoded into a valid domain execution.
var ErrInvalidPersistedExecution = errors.New("invalid persisted event action execution")

// ErrExecutionNotFound identifies an unsuccessful execution lookup.
var ErrExecutionNotFound = errors.New("event action execution not found")

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
	SetDedupe(context.Context, uuid.UUID, *Dedupe) error
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

// ExecutionStore owns idempotent claims and action state transitions.
// Claim atomically creates or resumes an execution. It returns a non-nil
// execution only when the caller owns processing. It returns (nil, nil) when
// an existing execution makes the claim an accepted no-op. When an existing
// retryable execution is not yet eligible to resume, Claim returns an error
// wrapping ErrRetryScheduled unless persisting the claim's observation or
// state fails; that persistence error takes precedence and is returned alone.
// Other non-nil errors report claim failures.
// Transition validates and atomically persists an execution state transition,
// returning the canonical stored execution. Transition must return an error
// wrapping ErrExecutionNotFound when the execution ID does not exist.
type ExecutionStore interface {
	Claim(context.Context, ExecutionClaim) (*Execution, error)
	Transition(context.Context, uuid.UUID, ExecutionState, time.Time) (*Execution, error)
}
