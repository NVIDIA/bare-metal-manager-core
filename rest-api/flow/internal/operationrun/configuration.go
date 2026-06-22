// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operationrun

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operation"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
)

// -----------------------------------------------------------------------------
// Selectors
// -----------------------------------------------------------------------------

// SelectorKind identifies the strategy used to choose operation-run targets
// from the resolved candidate scope.
type SelectorKind string

const (
	SelectorKindPercentage SelectorKind = "percentage"
)

// Selector is implemented by concrete target selector configurations. The kind
// discriminator lets selectors round-trip through JSONB while keeping
// dispatcher code type-directed.
type Selector interface {
	SelectorKind() SelectorKind
}

// PercentageSelector selects a deterministic percentage of candidate targets.
type PercentageSelector struct {
	Percentage int32  `json:"percentage"`
	Seed       string `json:"seed"`
}

func (*PercentageSelector) SelectorKind() SelectorKind {
	return SelectorKindPercentage
}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

// Options contains dispatcher-facing controls that apply to every operation in
// a run.
type Options struct {
	MaxConcurrentTargets int32          `json:"max_concurrent_targets"`
	SafetyPolicy         SafetyPolicy   `json:"safety_policy"`
	ConflictPolicy       ConflictPolicy `json:"conflict_policy"`
	OrderingPolicy       OrderingPolicy `json:"ordering_policy"`
	PhasePolicy          PhasePolicy    `json:"phase_policy"`
}

// -----------------------------------------------------------------------------
// Safety Gates
// -----------------------------------------------------------------------------

// SafetyPolicy contains gates that stop or pause a run when any gate is
// tripped.
type SafetyPolicy struct {
	Gates []SafetyGate `json:"gates"`
}

// SafetyGateKind identifies the metric a safety gate evaluates.
type SafetyGateKind string

const (
	SafetyGateKindFailureRate  SafetyGateKind = "failure_rate"
	SafetyGateKindFailureCount SafetyGateKind = "failure_count"
)

// SafetyGate is implemented by concrete safety-gate configurations.
// Each payload decides which phase/run stats it needs through its fields.
type SafetyGate interface {
	SafetyGateKind() SafetyGateKind
}

// SafetyGateScope decides whether a gate evaluates only the active phase or
// all phases processed so far.
type SafetyGateScope string

const (
	SafetyGateScopeCurrentPhase  SafetyGateScope = "current_phase"
	SafetyGateScopeCumulativeRun SafetyGateScope = "cumulative_run"
)

// FailureRateGate trips when failures exceed the configured percentage of
// targets in its scope.
type FailureRateGate struct {
	Scope                   SafetyGateScope `json:"scope"`
	FailureThresholdPercent int32           `json:"failure_threshold_percent"`
}

func (*FailureRateGate) SafetyGateKind() SafetyGateKind {
	return SafetyGateKindFailureRate
}

// FailureCountGate trips when failures reach the configured count in its
// scope.
type FailureCountGate struct {
	Scope                 SafetyGateScope `json:"scope"`
	FailureThresholdCount int32           `json:"failure_threshold_count"`
}

func (*FailureCountGate) SafetyGateKind() SafetyGateKind {
	return SafetyGateKindFailureCount
}

// -----------------------------------------------------------------------------
// Conflict Policy
// -----------------------------------------------------------------------------

// ConflictPolicyKind identifies how the dispatcher handles target conflicts.
type ConflictPolicyKind string

const (
	ConflictPolicyKindRetry ConflictPolicyKind = "retry"
)

// ConflictPolicy is the common policy boundary for target-conflict handling.
// Payload holds the concrete strategy today; the wrapper leaves room for
// policy-wide metadata later without changing Options.
type ConflictPolicy struct {
	Payload ConflictPolicyPayload `json:"payload"`
}

// ConflictPolicyPayload is implemented by concrete conflict-handling policies.
// Policies own retry/backoff configuration rather than scattering those fields
// on OperationRun.
type ConflictPolicyPayload interface {
	ConflictPolicyKind() ConflictPolicyKind
}

// ConflictRetryPolicy retries blocked targets until RetryTimeout elapses.
type ConflictRetryPolicy struct {
	RetryTimeout      time.Duration `json:"retry_timeout"`
	InitialRetryDelay time.Duration `json:"initial_retry_delay"`
	MaxRetryDelay     time.Duration `json:"max_retry_delay"`
}

func (*ConflictRetryPolicy) ConflictPolicyKind() ConflictPolicyKind {
	return ConflictPolicyKindRetry
}

func (p *ConflictRetryPolicy) Validate() error {
	if p == nil {
		return fmt.Errorf("conflict retry policy is required")
	}
	if p.RetryTimeout <= 0 {
		return fmt.Errorf("retry_timeout must be greater than 0")
	}
	if p.InitialRetryDelay <= 0 {
		return fmt.Errorf("initial_retry_delay must be greater than 0")
	}
	if p.MaxRetryDelay <= 0 {
		return fmt.Errorf("max_retry_delay must be greater than 0")
	}
	if p.MaxRetryDelay < p.InitialRetryDelay {
		return fmt.Errorf("max_retry_delay must be greater than or equal to initial_retry_delay")
	}

	return nil
}

// -----------------------------------------------------------------------------
// Ordering Policy
// -----------------------------------------------------------------------------

// OrderingPolicyKind identifies how selected targets are ordered before phases
// are formed.
type OrderingPolicyKind string

const (
	OrderingPolicyKindRandom           OrderingPolicyKind = "random"
	OrderingPolicyKindPhysicalLocation OrderingPolicyKind = "physical_location"
)

// OrderingPolicy is the common policy boundary for selected-target ordering.
// Payload holds the concrete strategy today; the wrapper leaves room for
// policy-wide metadata later without changing Options.
type OrderingPolicy struct {
	Payload OrderingPolicyPayload `json:"payload"`
}

// OrderingPolicyPayload is implemented by concrete target-ordering strategies.
type OrderingPolicyPayload interface {
	OrderingPolicyKind() OrderingPolicyKind
}

// RandomOrdering shuffles targets using a persisted seed so retries and
// restarts can reproduce the same order.
type RandomOrdering struct {
	Seed string `json:"seed"`
}

func (*RandomOrdering) OrderingPolicyKind() OrderingPolicyKind {
	return OrderingPolicyKindRandom
}

// PhysicalLocationOrderingStrategy describes rack-location-aware ordering
// modes. The first dispatcher implementation may reject this policy, but the
// internal shape is reserved so the model can grow without another refactor.
type PhysicalLocationOrderingStrategy string

const (
	PhysicalLocationOrderingStrategyRowByRow            PhysicalLocationOrderingStrategy = "row_by_row"
	PhysicalLocationOrderingStrategyOnePerRowRoundRobin PhysicalLocationOrderingStrategy = "one_per_row_round_robin"
)

// PhysicalLocationOrdering orders targets using physical location metadata.
type PhysicalLocationOrdering struct {
	Strategy PhysicalLocationOrderingStrategy `json:"strategy"`
}

func (*PhysicalLocationOrdering) OrderingPolicyKind() OrderingPolicyKind {
	return OrderingPolicyKindPhysicalLocation
}

// -----------------------------------------------------------------------------
// Phase Policy
// -----------------------------------------------------------------------------

// PhasePlanKind identifies how a run is split into phases.
type PhasePlanKind string

const (
	PhasePlanKindEqual      PhasePlanKind = "equal"
	PhasePlanKindPercentage PhasePlanKind = "percentage"
	PhasePlanKindCount      PhasePlanKind = "count"
)

// PhasePlan is implemented by concrete phase-splitting configurations.
type PhasePlan interface {
	PhasePlanKind() PhasePlanKind
}

// PhasePolicy combines a phase plan with the rule for advancing between
// phases.
type PhasePolicy struct {
	Plan          PhasePlan          `json:"plan"`
	AdvancePolicy PhaseAdvancePolicy `json:"advance_policy"`
}

// EqualPhases splits selected targets into PhaseCount roughly equal phases.
type EqualPhases struct {
	PhaseCount int32 `json:"phase_count"`
}

func (*EqualPhases) PhasePlanKind() PhasePlanKind {
	return PhasePlanKindEqual
}

// PercentagePhases defines explicit phase sizes as percentages of selected
// targets.
type PercentagePhases struct {
	Phases []PercentagePhase `json:"phases"`
}

func (*PercentagePhases) PhasePlanKind() PhasePlanKind {
	return PhasePlanKindPercentage
}

// PercentagePhase describes one explicit percentage-based phase.
type PercentagePhase struct {
	Percentage int32 `json:"percentage"`
}

// CountPhases defines explicit phase sizes by target count. The final phase
// covers any remaining targets not covered by the configured counts.
type CountPhases struct {
	Phases []CountPhase `json:"phases"`
}

func (*CountPhases) PhasePlanKind() PhasePlanKind {
	return PhasePlanKindCount
}

// CountPhase describes one explicit count-based phase.
type CountPhase struct {
	Count int32 `json:"count"`
}

// PhaseAdvancePolicy controls whether a successful phase advances
// automatically or waits for ResumeOperationRun.
type PhaseAdvancePolicy struct {
	AutoAdvance bool `json:"auto_advance"`
}

// -----------------------------------------------------------------------------
// Operation Template
// -----------------------------------------------------------------------------

// InclusiveScopeComposition controls how target_spec and prior-run target
// sources combine when both are inclusive.
type InclusiveScopeComposition string

const (
	InclusiveScopeCompositionIntersect InclusiveScopeComposition = "intersect"
	InclusiveScopeCompositionUnion     InclusiveScopeComposition = "union"
)

// Operation stores the shared operation-run operation template. Payload holds
// the concrete task operation info, while the surrounding fields capture
// operation-run-only scheduling and scoping metadata.
type Operation struct {
	Type         common.TaskType       `json:"type"`
	Code         string                `json:"code,omitempty"`
	TargetSpec   *operation.TargetSpec `json:"target_spec,omitempty"`
	Description  string                `json:"description,omitempty"`
	QueueOptions *QueueOptions         `json:"queue_options,omitempty"`
	TargetScope  OperationTargetScope  `json:"target_scope"`
	Payload      operations.Operation  `json:"payload"`
}

// OperationTargetScope controls how the embedded operation target_spec and
// previous operation-run targets contribute to the candidate scope.
type OperationTargetScope struct {
	ExcludeTargetSpec          bool                      `json:"exclude_target_spec"`
	OperationRunIDs            []uuid.UUID               `json:"operation_run_ids,omitempty"`
	ExcludeOperationRunTargets bool                      `json:"exclude_operation_run_targets"`
	InclusiveScopeComposition  InclusiveScopeComposition `json:"inclusive_scope_composition"`
}

// QueueOptions stores operation-level task conflict behavior using the same
// conflict strategy type as regular operation submissions.
type QueueOptions struct {
	ConflictStrategy    operation.ConflictStrategy `json:"conflict_strategy"`
	QueueTimeoutSeconds int32                      `json:"queue_timeout_seconds,omitempty"`
}
