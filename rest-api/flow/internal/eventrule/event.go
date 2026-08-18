// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"encoding/json"
	"fmt"
	"time"

	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	"github.com/google/uuid"
)

// Type identifies a domain event family.
type Type string

// Validate checks that the event type is a dotted, lowercase identifier path.
func (t Type) Validate() error {
	return validateIdentifierPath("event type", string(t))
}

// ResourceKind identifies the kind of resource an event concerns.
type ResourceKind string

const (
	ResourceKindComponent ResourceKind = "component"
	ResourceKindRack      ResourceKind = "rack"
)

// Validate checks that the resource kind is supported.
func (k ResourceKind) Validate() error {
	switch k {
	case ResourceKindComponent, ResourceKindRack:
		return nil
	default:
		return fmt.Errorf("unknown resource kind %q", k)
	}
}

// Severity identifies event or alert severity.
type Severity string

const (
	SeverityUnspecified Severity = ""
	SeverityInfo        Severity = "info"
	SeverityWarning     Severity = "warning"
	SeverityCritical    Severity = "critical"
)

// ParseSeverity converts a string into a validated Severity.
func ParseSeverity(value string) (Severity, error) {
	severity := Severity(value)
	if err := severity.Validate(); err != nil {
		return SeverityUnspecified, err
	}

	return severity, nil
}

// IsUnspecified reports whether no severity was supplied for the event.
func (s Severity) IsUnspecified() bool {
	return s == SeverityUnspecified
}

// Validate checks that severity is supported.
func (s Severity) Validate() error {
	switch s {
	case SeverityUnspecified, SeverityInfo, SeverityWarning, SeverityCritical:
		return nil
	default:
		return fmt.Errorf("unknown severity %q", s)
	}
}

// Envelope is the normalized in-memory domain type consumed by event rules.
// Transport and persistence representations convert into Envelope at their
// boundaries.
type Envelope struct {
	ID             uuid.UUID       // Stable identity for one event across delivery retries.
	Type           Type            // Identifies the event family and payload schema.
	Producer       string          // Identifies the collector or source system.
	Severity       Severity        // Describes the event's normalized severity.
	Resource       Resource        // Identifies the resource the event concerns.
	Payload        json.RawMessage // Contains opaque event-type-specific JSON.
	ObservedAt     time.Time       // Records when the source event was observed.
	CorrelationKey string          // Groups repeated observations for semantic deduplication.
}

// Validate checks the normalized envelope contract.
func (e *Envelope) Validate() error {
	if e == nil {
		return fmt.Errorf("event envelope is nil")
	}
	if e.ID == uuid.Nil {
		return fmt.Errorf("event id is required")
	}
	if err := e.Type.Validate(); err != nil {
		return err
	}
	if err := validateOptionalString("event producer", e.Producer); err != nil {
		return err
	}
	if err := e.Severity.Validate(); err != nil {
		return err
	}
	if err := e.Resource.Validate(); err != nil {
		return err
	}
	if len(e.Payload) > 0 && !json.Valid(e.Payload) {
		return fmt.Errorf("event payload must be valid JSON")
	}
	if err := validateOptionalString("event correlation_key", e.CorrelationKey); err != nil {
		return err
	}

	return nil
}

// Resource identifies the resource an event is about.
type Resource struct {
	Kind              ResourceKind
	ExternalID        string
	ID                uuid.UUID
	ComponentTypeHint flowtypes.ComponentType
}

// Validate checks the caller-supplied resource reference.
func (r Resource) Validate() error {
	if err := r.Kind.Validate(); err != nil {
		return err
	}

	if err := validateOptionalString("resource external_id", r.ExternalID); err != nil {
		return err
	}

	if r.ComponentTypeHint != "" {
		if r.Kind != ResourceKindComponent {
			return fmt.Errorf("resource component_type_hint requires component kind")
		}

		if err := r.ComponentTypeHint.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// ResolvedResource contains the canonical inventory identity and attributes
// established during event enrichment.
type ResolvedResource struct {
	Kind          ResourceKind
	ID            uuid.UUID
	RackID        uuid.UUID
	ComponentType flowtypes.ComponentType
}

// Validate checks the canonical identity and attributes established during
// enrichment.
func (r ResolvedResource) Validate() error {
	if err := r.Kind.Validate(); err != nil {
		return err
	}
	if r.ID == uuid.Nil {
		return fmt.Errorf("resolved resource id is required")
	}
	if r.RackID == uuid.Nil {
		return fmt.Errorf("resolved resource rack id is required")
	}
	if r.Kind == ResourceKindComponent {
		if err := r.ComponentType.Validate(); err != nil {
			return fmt.Errorf("resolved resource component type: %w", err)
		}
	} else {
		if r.ID != r.RackID {
			return fmt.Errorf("resolved rack resource id must equal rack id")
		}
	}
	return nil
}
