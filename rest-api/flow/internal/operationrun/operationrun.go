// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package operationrun defines the domain model and normalization helpers for
// operation runs. Management, planning, and storage live under the manager
// subpackages; protobuf and DAO conversions live under internal/converter.
package operationrun

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	dbquery "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/query"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operation"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
)

// OperationRunStatus is the durable lifecycle state for an operation run.
type OperationRunStatus string

const (
	OperationRunStatusPending   OperationRunStatus = "pending"
	OperationRunStatusRunning   OperationRunStatus = "running"
	OperationRunStatusPaused    OperationRunStatus = "paused"
	OperationRunStatusCompleted OperationRunStatus = "completed"
	// OperationRunStatusCompletedWithFailures reports a terminal run that
	// reached the end of its target set but had one or more failed or
	// terminated targets.
	OperationRunStatusCompletedWithFailures OperationRunStatus = "completed_with_failures"
	OperationRunStatusCancelled             OperationRunStatus = "cancelled"
	OperationRunStatusFailed                OperationRunStatus = "failed"
)

// IsTerminal reports whether no further dispatcher work should be attempted.
func (s OperationRunStatus) IsTerminal() bool {
	return s == OperationRunStatusCompleted ||
		s == OperationRunStatusCompletedWithFailures ||
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
	OperationRunTargetStatusClaimed    OperationRunTargetStatus = "claimed"
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

// IsFailedOrTerminated reports whether this target failed or terminated.
func (s OperationRunTargetStatus) IsFailedOrTerminated() bool {
	return s == OperationRunTargetStatusFailed ||
		s == OperationRunTargetStatusTerminated
}

// IsActive reports whether this target currently has a child task consuming
// rollout concurrency.
func (s OperationRunTargetStatus) IsActive() bool {
	return s == OperationRunTargetStatusSubmitted
}

// OperationRunTargetStatusFromTaskStatus maps a child task status to its
// operation-run target status.
func OperationRunTargetStatusFromTaskStatus(
	status taskcommon.TaskStatus,
) OperationRunTargetStatus {
	switch status {
	case taskcommon.TaskStatusCompleted:
		return OperationRunTargetStatusCompleted
	case taskcommon.TaskStatusFailed:
		return OperationRunTargetStatusFailed
	case taskcommon.TaskStatusTerminated:
		return OperationRunTargetStatusTerminated
	default:
		return OperationRunTargetStatusSubmitted
	}
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

// Start marks the run as running. StartedAt records the first transition from
// pending to running and is not refreshed by later dispatcher passes.
func (r *OperationRun) Start(now time.Time) {
	if r.Status == OperationRunStatusPending && r.StartedAt == nil {
		r.StartedAt = timePtr(now)
	}

	r.Status = OperationRunStatusRunning
	r.StatusReason = OperationRunStatusReasonNone
}

// Pause marks the run as paused for a non-terminal reason.
func (r *OperationRun) Pause(
	reason OperationRunStatusReason,
	message string,
) {
	r.Status = OperationRunStatusPaused
	r.StatusReason = reason
	r.StatusMessage = message
}

// Fail marks the run as failed and records its terminal timestamp.
func (r *OperationRun) Fail(now time.Time, message string) {
	r.Status = OperationRunStatusFailed
	r.StatusReason = OperationRunStatusReasonNone
	r.StatusMessage = message
	r.FinishedAt = timePtr(now)
}

// Complete marks the run as completed and records its terminal timestamp.
func (r *OperationRun) Complete(now time.Time, message string) {
	r.Status = OperationRunStatusCompleted
	r.StatusReason = OperationRunStatusReasonNone
	r.StatusMessage = message
	r.FinishedAt = timePtr(now)
}

// CompleteWithFailures marks the run as terminal after completing its target
// set with at least one failed or terminated target.
func (r *OperationRun) CompleteWithFailures(now time.Time, message string) {
	r.Status = OperationRunStatusCompletedWithFailures
	r.StatusReason = OperationRunStatusReasonNone
	r.StatusMessage = message
	r.FinishedAt = timePtr(now)
}

// DecodedSelector decodes and validates the stored selector configuration.
func (r *OperationRun) DecodedSelector() (Selector, error) {
	var selector Selector
	if err := UnmarshalConfig(r.Selector, &selector); err != nil {
		return nil, fmt.Errorf("unmarshal operation run selector: %w", err)
	}
	if err := selector.Validate(); err != nil {
		return nil, fmt.Errorf("validate operation run selector: %w", err)
	}

	return selector, nil
}

// DecodedOptions decodes and validates the stored options configuration.
func (r *OperationRun) DecodedOptions() (*Options, error) {
	var options Options
	if err := UnmarshalConfig(r.Options, &options); err != nil {
		return nil, fmt.Errorf("unmarshal operation run options: %w", err)
	}
	if err := options.Validate(); err != nil {
		return nil, fmt.Errorf("validate operation run options: %w", err)
	}

	return &options, nil
}

// DecodedOperation decodes and validates the stored operation template.
func (r *OperationRun) DecodedOperation() (*Operation, error) {
	var operation Operation
	if err := UnmarshalConfig(r.OperationTemplate, &operation); err != nil {
		return nil, fmt.Errorf("unmarshal operation run template: %w", err)
	}
	if err := operation.Validate(); err != nil {
		return nil, fmt.Errorf("validate operation run template: %w", err)
	}

	return &operation, nil
}

// OperationRunTarget is the internal service representation of one rack
// execution target in an operation run.
type OperationRunTarget struct {
	ID               uuid.UUID
	OperationRunID   uuid.UUID
	RackID           uuid.UUID
	SequenceIndex    int32
	PhaseIndex       int32
	ComponentsByType operation.ComponentsByType
	TaskID           *uuid.UUID
	Status           OperationRunTargetStatus
	Message          string
	RetryAfter       *time.Time
	RetryState       json.RawMessage
	CreatedAt        time.Time
	UpdatedAt        time.Time
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
	// TargetPhaseScopeAllMaterializedTargets returns every materialized target
	// row for internal planning use cases such as prior-run exclusions.
	TargetPhaseScopeAllMaterializedTargets
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

func timePtr(t time.Time) *time.Time {
	return &t
}
