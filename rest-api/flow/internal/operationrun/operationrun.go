// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package operationrun defines the domain model and normalization helpers for
// operation runs. Storage lives in the store subpackage; protobuf and DAO
// conversions live under internal/converter.
package operationrun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	dbquery "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/query"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
)

// OperationRunStatus is the durable lifecycle state for an operation run.
type OperationRunStatus string

const (
	OperationRunStatusPending   OperationRunStatus = "pending"
	OperationRunStatusRunning   OperationRunStatus = "running"
	OperationRunStatusPaused    OperationRunStatus = "paused"
	OperationRunStatusCompleted OperationRunStatus = "completed"
	OperationRunStatusCancelled OperationRunStatus = "cancelled"
	OperationRunStatusFailed    OperationRunStatus = "failed"
)

// IsTerminal reports whether no further dispatcher work should be attempted.
func (s OperationRunStatus) IsTerminal() bool {
	return s == OperationRunStatusCompleted ||
		s == OperationRunStatusCancelled ||
		s == OperationRunStatusFailed
}

// OperationRunStatusReason records why a run is in its current non-terminal
// state. It is especially important for paused runs: ResumeOperationRun uses
// the reason to distinguish phase gates from operator, safety, and conflict
// pauses.
type OperationRunStatusReason string

const (
	OperationRunStatusReasonNone                 OperationRunStatusReason = "none"
	OperationRunStatusReasonOperatorPaused       OperationRunStatusReason = "operator_paused"
	OperationRunStatusReasonPhaseGate            OperationRunStatusReason = "phase_gate"
	OperationRunStatusReasonSafetyGate           OperationRunStatusReason = "safety_gate"
	OperationRunStatusReasonConflictRetryTimeout OperationRunStatusReason = "conflict_retry_timeout"
)

// OperationRunTargetStatus is the durable lifecycle state for a rack execution
// target belonging to an operation run.
type OperationRunTargetStatus string

const (
	OperationRunTargetStatusPending    OperationRunTargetStatus = "pending"
	OperationRunTargetStatusBlocked    OperationRunTargetStatus = "blocked"
	OperationRunTargetStatusSubmitted  OperationRunTargetStatus = "submitted"
	OperationRunTargetStatusCompleted  OperationRunTargetStatus = "completed"
	OperationRunTargetStatusFailed     OperationRunTargetStatus = "failed"
	OperationRunTargetStatusTerminated OperationRunTargetStatus = "terminated"
	OperationRunTargetStatusSkipped    OperationRunTargetStatus = "skipped"
)

// IsTerminal reports whether this target has no remaining work.
func (s OperationRunTargetStatus) IsTerminal() bool {
	return s == OperationRunTargetStatusCompleted ||
		s == OperationRunTargetStatusFailed ||
		s == OperationRunTargetStatusTerminated ||
		s == OperationRunTargetStatusSkipped
}

// IsActive reports whether this target currently has a child task consuming
// rollout concurrency.
func (s OperationRunTargetStatus) IsActive() bool {
	return s == OperationRunTargetStatusSubmitted
}

// ComponentFilterKind discriminates the two variants of ComponentFilter.
type ComponentFilterKind string

const (
	// ComponentFilterKindTypes filters by component type.
	ComponentFilterKindTypes ComponentFilterKind = "types"
	// ComponentFilterKindComponents targets specific components by UUID.
	ComponentFilterKindComponents ComponentFilterKind = "components"
)

// ComponentFilter is the discriminated union stored in target component-filter
// JSON. Exactly one of Types or Components must be non-nil when Kind is set.
type ComponentFilter struct {
	Kind ComponentFilterKind `json:"kind"`
	// Types lists the component type strings when Kind == "types".
	Types []string `json:"types,omitempty"`
	// Components lists the component UUIDs when Kind == "components".
	Components []uuid.UUID `json:"components,omitempty"`
}

func (cf *ComponentFilter) validate() error {
	switch cf.Kind {
	case ComponentFilterKindTypes:
		if len(cf.Types) == 0 {
			return fmt.Errorf(
				"component filter kind %q requires at least one type",
				cf.Kind,
			)
		}
		if len(cf.Components) > 0 {
			return fmt.Errorf(
				"component filter kind %q must not have components set",
				cf.Kind,
			)
		}
	case ComponentFilterKindComponents:
		if len(cf.Components) == 0 {
			return fmt.Errorf(
				"component filter kind %q requires at least one component",
				cf.Kind,
			)
		}
		if len(cf.Types) > 0 {
			return fmt.Errorf(
				"component filter kind %q must not have types set", cf.Kind,
			)
		}
	default:
		return fmt.Errorf("unknown component filter kind: %q", cf.Kind)
	}

	return nil
}

// UnmarshalComponentFilter parses target component-filter JSON. Nil, empty,
// and JSON null all mean "no filter", so the target applies to all components
// in the rack.
func UnmarshalComponentFilter(raw json.RawMessage) (*ComponentFilter, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}

	var cf ComponentFilter
	if err := json.Unmarshal(trimmed, &cf); err != nil {
		return nil, err
	}

	if err := cf.validate(); err != nil {
		return nil, err
	}

	return &cf, nil
}

// OperationRun is the internal service representation of an operation run.
// Create ignores server-owned lifecycle and timestamp fields and always starts
// the persisted run in pending/none state.
type OperationRun struct {
	ID                uuid.UUID
	Name              string
	Description       string
	Status            OperationRunStatus
	StatusReason      OperationRunStatusReason
	StatusMessage     string
	Selector          json.RawMessage
	Options           json.RawMessage
	OperationTemplate json.RawMessage
	OperationType     taskcommon.TaskType
	OperationCode     string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	StartedAt         *time.Time
	FinishedAt        *time.Time
}

// OperationRunTarget is the internal service representation of one rack
// execution target in an operation run.
type OperationRunTarget struct {
	ID              uuid.UUID
	OperationRunID  uuid.UUID
	RackID          uuid.UUID
	SequenceIndex   int32
	PhaseIndex      int32
	ComponentFilter json.RawMessage
	TaskID          *uuid.UUID
	Status          OperationRunTargetStatus
	Message         string
	RetryAfter      *time.Time
	RetryState      json.RawMessage
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// StateFilter matches operation runs by status, reason, or both. When both are
// set they are AND-ed together; multiple StateFilters compose with OR.
type StateFilter struct {
	Status OperationRunStatus
	Reason OperationRunStatusReason
}

// IsZero reports whether the filter has no status or reason predicate.
func (f StateFilter) IsZero() bool {
	return f.Status == "" && f.Reason == ""
}

// OperationKindFilter matches operation runs by operation type and, optionally,
// operation code. Multiple OperationKindFilters compose with OR.
type OperationKindFilter struct {
	Type taskcommon.TaskType
	Code string
}

// ListOptions filters operation-run list queries.
type ListOptions struct {
	// Name, when non-nil, restricts results by operation-run name.
	Name *dbquery.StringQueryInfo
	// States, when non-empty, restricts results by state predicates.
	States []StateFilter
	// OperationKinds, when non-empty, restricts results by operation type/code.
	OperationKinds []OperationKindFilter
	// Pagination, when non-nil, applies offset/limit to the result set.
	Pagination *dbquery.Pagination
}

// TargetPhaseScope selects which materialized phase rows are returned by a
// target list query. The zero value is the current phase.
type TargetPhaseScope int

const (
	// TargetPhaseScopeCurrentPhase returns the latest materialized phase.
	TargetPhaseScopeCurrentPhase TargetPhaseScope = iota
	// TargetPhaseScopeCompletedPhases returns materialized phases before the
	// current phase.
	TargetPhaseScopeCompletedPhases
	// TargetPhaseScopeCurrentAndCompletedPhases returns every materialized
	// phase through the current phase.
	TargetPhaseScopeCurrentAndCompletedPhases
)

// TargetListOptions filters operation-run target list queries.
type TargetListOptions struct {
	// Status, when non-empty, restricts results to targets in that state.
	Status OperationRunTargetStatus
	// PhaseScope selects which materialized phase rows to return.
	PhaseScope TargetPhaseScope
	// Pagination, when non-nil, applies offset/limit to the result set.
	Pagination *dbquery.Pagination
}
