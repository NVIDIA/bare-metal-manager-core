// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"fmt"
)

// Policy defines how a selected event rule responds to an event. EventType
// remains on the owning rule because it controls selection.
type Policy struct {
	Actions []Action
}

// Clone returns an independent copy of the policy and its mutable data.
func (p Policy) Clone() Policy {
	cloned := p
	cloned.Actions = CloneActions(p.Actions)
	return cloned
}

// Validate checks actions and action-name uniqueness.
func (p Policy) Validate() error {
	if len(p.Actions) == 0 {
		return fmt.Errorf("actions are required")
	}

	return ValidateActions(p.Actions)
}
