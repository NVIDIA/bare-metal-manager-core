// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	taskcommon "github.com/NVIDIA/infra-controller-rest/flow/internal/task/common"
	identifier "github.com/NVIDIA/infra-controller-rest/flow/pkg/common/Identifier"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

// Wrapper wraps the operation type and its serialized information.
type Wrapper struct {
	Type taskcommon.TaskType
	Code string          // Operation code string (e.g., "power_on", "upgrade")
	Info json.RawMessage // Serialized operation details
}

// TargetSpec contains either rack targets or component targets, but not both.
// This enforces single-type targeting at the type level.
type TargetSpec struct {
	Racks      []RackTarget      // Set if targeting racks (mutually exclusive with Components)
	Components []ComponentTarget // Set if targeting components (mutually exclusive with Racks)
}

// IsRackTargeting returns true if this spec targets racks.
func (ts *TargetSpec) IsRackTargeting() bool {
	return len(ts.Racks) > 0
}

// IsComponentTargeting returns true if this spec targets components.
func (ts *TargetSpec) IsComponentTargeting() bool {
	return len(ts.Components) > 0
}

// Validate validates the target specification
func (ts *TargetSpec) Validate() error {
	if ts == nil {
		return fmt.Errorf("target spec is nil")
	}

	if ts.IsRackTargeting() {
		if ts.IsComponentTargeting() {
			return fmt.Errorf("target_spec cannot have both racks and components set")
		}

		for _, rt := range ts.Racks {
			if err := rt.Validate(); err != nil {
				return fmt.Errorf("invalid rack target: %w", err)
			}
		}
	} else {
		if !ts.IsComponentTargeting() {
			return fmt.Errorf("target_spec must have either racks or components set")
		}

		for _, ct := range ts.Components {
			if err := ct.Validate(); err != nil {
				return fmt.Errorf("invalid component target: %w", err)
			}
		}
	}

	return nil
}

// RackTarget identifies a rack with optional component type filtering.
// To target specific components, use the component-level APIs instead.
type RackTarget struct {
	Identifier     identifier.Identifier       // Rack identifier (ID or Name, at least one must be set)
	ComponentTypes []devicetypes.ComponentType // Optional: filter by type; empty = ALL component types in rack
}

func (rt *RackTarget) Validate() error {
	if rt == nil {
		return fmt.Errorf("rack target is nil")
	}

	if !rt.Identifier.ValidateAtLeastOne() {
		return fmt.Errorf("rack target must have either id or name set")
	}

	for _, ctype := range rt.ComponentTypes {
		if ctype == devicetypes.ComponentTypeUnknown {
			return fmt.Errorf("unknown component type")
		}
	}

	return nil
}

// ComponentTarget identifies a specific component.
// Either UUID or External must be set, but not both.
type ComponentTarget struct {
	UUID     uuid.UUID    // Flow internal UUID (one of UUID or External must be set)
	External *ExternalRef // External system reference (one of UUID or External must be set)
}

func (ct *ComponentTarget) TargetIdentifier() string {
	if ct.UUID != uuid.Nil {
		return fmt.Sprintf("uuid=%s", ct.UUID)
	}
	if ct.External != nil {
		return fmt.Sprintf("external_id=%s", ct.External.ID)
	}
	return "unknown"
}

func (ct *ComponentTarget) Validate() error {
	if ct == nil {
		return fmt.Errorf("component target is nil")
	}

	if ct.UUID != uuid.Nil {
		if ct.External != nil {
			return fmt.Errorf("component target cannot have both uuid and external set")
		}
	} else {
		if err := ct.External.Validate(); err != nil {
			return fmt.Errorf("invalid external ref: %w", err)
		}
	}

	return nil
}

// ExternalRef identifies a component by its external system ID.
// The component type determines which external system to query
type ExternalRef struct {
	Type devicetypes.ComponentType // Component type determines the source system
	ID   string                    // Component ID from the component manager service
}

func (er *ExternalRef) Validate() error {
	if er == nil {
		return fmt.Errorf("external ref is nil")
	}

	if er.Type == devicetypes.ComponentTypeUnknown {
		return fmt.Errorf("external ref must have a valid component type")
	}

	if er.ID == "" {
		return fmt.Errorf("external ref must have an id")
	}

	return nil
}

// ConflictStrategy controls how a task behaves when a conflict is detected.
type ConflictStrategy int

const (
	// ConflictStrategyReject immediately rejects the task when a conflict is detected (default).
	ConflictStrategyReject ConflictStrategy = iota
	// ConflictStrategyQueue queues the task until the conflicting task completes.
	ConflictStrategyQueue
)

// Request represents the specification of an operation submitted by the user.
// The Task Manager resolves the TargetSpec, splits by rack, and creates one
// Task per rack.
type Request struct {
	Operation   Wrapper
	TargetSpec  TargetSpec // Either racks or components, not both
	Description string

	// ConflictStrategy controls how the task behaves when a conflict is
	// detected. Default (ConflictStrategyReject) rejects on conflict.
	ConflictStrategy ConflictStrategy

	// QueueTimeout is how long to wait in queue before auto-expiry. Zero
	// means use the server default. The server may enforce a maximum.
	// Only relevant when ConflictStrategy is ConflictStrategyQueue.
	QueueTimeout time.Duration

	// Optional: override rule resolution with a specific rule
	RuleID *uuid.UUID

	// RequiredRackID, when non-zero, causes SubmitTask to return an error
	// (and create no tasks) if the resolved targets do not belong exclusively
	// to this rack. Use this for component-targeting requests where the scope
	// was originally written against a specific rack, to guard against the
	// case where all listed components have since been moved to a different
	// single rack or span multiple racks.
	//
	// This field only handles the single-rack enforcement case. If a future
	// caller needs to constrain resolution to a known set of multiple racks,
	// this would need to become []uuid.UUID (or a separate AllowedRackIDs
	// field). Do not add that generalization until there is a concrete caller.
	RequiredRackID uuid.UUID
}

func (r *Request) Validate() error {
	if r == nil {
		return fmt.Errorf("request is nil")
	}

	if !r.Operation.Type.IsValid() {
		return fmt.Errorf("unknown task type")
	}

	if err := r.TargetSpec.Validate(); err != nil {
		return fmt.Errorf("invalid target spec: %w", err)
	}

	return nil
}
