// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"fmt"

	"github.com/google/uuid"
)

// ScopeType identifies an event-rule binding scope.
type ScopeType string

const (
	ScopeTypeSite ScopeType = "site"
	ScopeTypeRack ScopeType = "rack"
)

// Scope identifies either the site-wide scope or one rack.
type Scope struct {
	Type ScopeType
	ID   uuid.UUID
}

// HasID reports whether the scope carries a resource identifier.
func (s Scope) HasID() bool {
	return s.ID != uuid.Nil
}

// Validate checks the scope type and identifier contract.
func (s Scope) Validate() error {
	switch s.Type {
	case ScopeTypeSite:
		if s.HasID() {
			return fmt.Errorf("site scope must not have an id")
		}
	case ScopeTypeRack:
		if !s.HasID() {
			return fmt.Errorf("rack scope requires an id")
		}
	default:
		return fmt.Errorf("unknown event rule scope type %q", s.Type)
	}
	return nil
}

// Binding associates a persisted rule with an event-rule scope.
type Binding struct {
	ID        uuid.UUID
	RuleID    uuid.UUID
	EventType Type
	Scope     Scope
}

// Validate checks binding identity, event type, and scope.
func (b Binding) Validate() error {
	if b.ID == uuid.Nil {
		return fmt.Errorf("event rule binding id is required")
	}
	if b.RuleID == uuid.Nil {
		return fmt.Errorf("event rule binding rule id is required")
	}
	if err := b.EventType.Validate(); err != nil {
		return fmt.Errorf("event rule binding event type: %w", err)
	}
	return b.Scope.Validate()
}
