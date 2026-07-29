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

// RuleStore manages persisted rule lifecycle operations.
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
	Unbind(context.Context, uuid.UUID) error
	// GetForScope returns the binding for an event type and scope. When no
	// binding exists, implementations must return (nil, nil).
	GetForScope(context.Context, Type, Scope) (*Binding, error)
}
