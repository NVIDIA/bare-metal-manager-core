// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

const maxRuleNameLength = 128

// RuleOrigin identifies whether a rule is persisted or defined by code.
type RuleOrigin string

const (
	RuleOriginPersisted RuleOrigin = "persisted"
	RuleOriginBuiltIn   RuleOrigin = "built_in"
)

// Validate checks that the rule origin is supported.
func (o RuleOrigin) Validate() error {
	switch o {
	case RuleOriginPersisted, RuleOriginBuiltIn:
		return nil
	default:
		return fmt.Errorf("unknown rule origin %q", o)
	}
}

// Rule is the in-memory domain type for a persisted or built-in event policy.
type Rule struct {
	ID          uuid.UUID
	Origin      RuleOrigin
	Name        string
	Description string
	Enabled     bool
	EventType   Type
	Policy
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RuleMetadata contains the independently mutable descriptive fields of a rule.
type RuleMetadata struct {
	Name        string
	Description string
}

// RuleCreate contains the caller-provided fields for a persisted rule.
type RuleCreate struct {
	Metadata  RuleMetadata
	EventType Type
	Policy    Policy
}

// Validate checks fields supplied when creating a persisted rule.
func (c RuleCreate) Validate() error {
	if err := c.Metadata.Validate(); err != nil {
		return err
	}

	if err := c.EventType.Validate(); err != nil {
		return err
	}

	return c.Policy.Validate()
}

// Validate checks mutable rule metadata.
func (m RuleMetadata) Validate() error {
	if err := validateRequiredString("event rule name", m.Name); err != nil {
		return err
	}
	if len(m.Name) > maxRuleNameLength {
		return fmt.Errorf("event rule name exceeds %d characters", maxRuleNameLength)
	}
	return validateOptionalString("event rule description", m.Description)
}

// Clone returns an independent copy of the rule and its mutable policy data.
func (r Rule) Clone() Rule {
	cloned := r
	cloned.Policy = r.Policy.Clone()
	return cloned
}

// Validate checks rule metadata and policy.
func (r *Rule) Validate() error {
	if r == nil {
		return fmt.Errorf("event rule is nil")
	}
	if r.ID == uuid.Nil {
		return fmt.Errorf("event rule id is required")
	}
	if err := r.Origin.Validate(); err != nil {
		return err
	}
	if r.Origin == RuleOriginBuiltIn && !r.Enabled {
		return fmt.Errorf("built-in event rule must be enabled")
	}
	if err := (RuleMetadata{Name: r.Name, Description: r.Description}).Validate(); err != nil {
		return err
	}
	if err := r.EventType.Validate(); err != nil {
		return err
	}
	return r.Policy.Validate()
}
