// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"fmt"
	"time"
)

// Policy defines how a selected event rule deduplicates and responds to an
// event. EventType remains on the owning rule because it controls selection.
type Policy struct {
	Dedupe  *Dedupe
	Actions []Action
}

// Dedupe configures semantic deduplication by envelope correlation key.
type Dedupe struct {
	Window time.Duration
}

// Clone returns an independent copy of the deduplication policy.
func (d *Dedupe) Clone() *Dedupe {
	if d == nil {
		return nil
	}
	cloned := *d
	return &cloned
}

// WithinWindow reports whether an observation falls within the deduplication
// window anchored at the action execution's creation time.
func (d *Dedupe) WithinWindow(createdAt, observedAt time.Time) bool {
	if d == nil {
		return false
	}
	return !observedAt.Before(createdAt) &&
		observedAt.Sub(createdAt) < d.Window
}

// Clone returns an independent copy of the policy and its mutable data.
func (p Policy) Clone() Policy {
	cloned := p
	cloned.Dedupe = p.Dedupe.Clone()
	cloned.Actions = CloneActions(p.Actions)
	return cloned
}

// Validate checks the deduplication policy.
func (d Dedupe) Validate() error {
	if d.Window <= 0 {
		return fmt.Errorf("dedupe window must be positive")
	}

	return nil
}

// Validate checks deduplication configuration, actions, and action identity.
func (p Policy) Validate() error {
	if p.Dedupe != nil {
		if err := p.Dedupe.Validate(); err != nil {
			return fmt.Errorf("dedupe: %w", err)
		}
	}

	return ValidateActions(p.Actions)
}
