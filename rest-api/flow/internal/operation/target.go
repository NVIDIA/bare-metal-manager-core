// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operation

import (
	"fmt"

	"github.com/google/uuid"

	identifier "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/Identifier"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

// -----------------------------------------------------------------------------
// Input targets
// -----------------------------------------------------------------------------

// The types in this section describe caller-facing target intent. They may
// contain names, external component IDs, or type filters that still need to be
// resolved against inventory before an operation can execute.

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

// Validate validates the target specification.
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
// The component type determines which external system to query.
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

// -----------------------------------------------------------------------------
// Execution targets
// -----------------------------------------------------------------------------

// The types in this section describe resolved execution units. They should only
// contain inventory UUIDs that have already been resolved and qualified.

// RackExecutionTarget is the resolved, rack-scoped execution unit used by
// planners and dispatchers. TargetSpec is the user-facing unresolved input;
// RackExecutionTarget is the normalized form after identifiers, component
// targets, and logical scopes have been resolved to today's rack execution
// boundary. Keep the broader ExecutionTarget name available for a future
// wrapper if operation execution expands beyond rack-scoped units.
//
// ComponentsByType is the concrete component set to operate on. It is resolved
// from caller-facing filters before planning so exclusions can subtract actual
// components instead of interpreting unresolved filter expressions.
type RackExecutionTarget struct {
	RackID           uuid.UUID
	ComponentsByType ComponentsByType
}
