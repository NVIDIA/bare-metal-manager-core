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

func (d Dedupe) validate() error {
	if d.Window <= 0 {
		return fmt.Errorf("dedupe window must be positive")
	}

	return nil
}

// Validate checks deduplication configuration, actions, and action identity.
func (p Policy) Validate() error {
	if p.Dedupe != nil {
		if err := p.Dedupe.validate(); err != nil {
			return fmt.Errorf("dedupe: %w", err)
		}
	}

	if len(p.Actions) == 0 {
		return fmt.Errorf("actions are required")
	}

	actionIDs := make(map[string]struct{}, len(p.Actions))
	for i := range p.Actions {
		action := &p.Actions[i]
		if err := action.Validate(); err != nil {
			return fmt.Errorf("actions[%d]: %w", i, err)
		}

		if _, ok := actionIDs[action.ID]; ok {
			return fmt.Errorf("actions[%d]: duplicate action id %q", i, action.ID)
		}

		actionIDs[action.ID] = struct{}{}
	}

	return nil
}
