// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"fmt"
	"slices"

	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
)

// ActionCondition determines whether one action applies to an envelope.
// Values within a field use OR semantics; different fields use AND semantics.
type ActionCondition struct {
	Severities     []Severity
	ComponentTypes []flowtypes.ComponentType
}

// Clone returns an independent copy of the condition.
func (c ActionCondition) Clone() ActionCondition {
	cloned := c
	cloned.Severities = slices.Clone(c.Severities)
	cloned.ComponentTypes = slices.Clone(c.ComponentTypes)
	return cloned
}

func (c ActionCondition) validate() error {
	if err := validateOptionalSlice("severities", c.Severities); err != nil {
		return err
	}

	for i, severity := range c.Severities {
		if severity.IsUnspecified() {
			return fmt.Errorf("severities[%d] cannot be unspecified", i)
		}

		if err := severity.Validate(); err != nil {
			return fmt.Errorf("severities[%d]: %w", i, err)
		}
	}

	if err := validateOptionalSlice("component_types", c.ComponentTypes); err != nil {
		return err
	}

	for i, componentType := range c.ComponentTypes {
		if err := componentType.Validate(); err != nil {
			return fmt.Errorf("component_types[%d]: %w", i, err)
		}
	}

	return nil
}

// AppliesTo reports whether the condition accepts the envelope and its
// canonically resolved resource.
func (c ActionCondition) AppliesTo(envelope Envelope, resource ResolvedResource) bool {
	if c.Severities != nil &&
		!slices.Contains(c.Severities, envelope.Severity) {
		return false
	}

	if c.ComponentTypes != nil {
		if resource.Kind != ResourceKindComponent {
			return false
		}
		if !slices.Contains(c.ComponentTypes, resource.ComponentType) {
			return false
		}
	}

	return true
}

// ActionType identifies an event-rule action.
type ActionType string

const (
	ActionTypeSubmitTask ActionType = "submit_task"
	ActionTypeSendAlert  ActionType = "send_alert"
	ActionTypeNoop       ActionType = "noop"
)

// ConflictStrategy describes task-conflict behavior.
type ConflictStrategy string

const (
	ConflictStrategyQueue  ConflictStrategy = "queue"
	ConflictStrategyReject ConflictStrategy = "reject"
)

func (s ConflictStrategy) validate() error {
	switch s {
	case ConflictStrategyQueue, ConflictStrategyReject:
		return nil
	default:
		return fmt.Errorf("unknown conflict strategy %q", s)
	}
}

// ActionSpec is the closed set of typed responses supported by an action.
// The unexported validation method prevents implementations outside this
// package while exposing its type and target-resolution behavior.
type ActionSpec interface {
	Type() ActionType
	TargetResolutionStrategy() TargetStrategy
	validate() error
}

// Action describes one independently selected and deduplicated response.
type Action struct {
	ID        string
	Condition ActionCondition
	Spec      ActionSpec
}

// Clone returns an independent copy of the action's mutable data.
func (a Action) Clone() Action {
	cloned := a
	cloned.Condition = a.Condition.Clone()
	return cloned
}

// NewAction returns an action containing the supplied typed specification.
func NewAction(id string, condition ActionCondition, spec ActionSpec) Action {
	return Action{ID: id, Condition: condition, Spec: spec}
}

// Validate checks action identity, condition, and typed specification.
func (a Action) Validate() error {
	if err := validateIdentifier("action id", a.ID); err != nil {
		return err
	}

	if err := a.Condition.validate(); err != nil {
		return fmt.Errorf("condition: %w", err)
	}

	if a.Spec == nil {
		return fmt.Errorf("action spec is required")
	}

	return a.Spec.validate()
}

// ValidateActions checks an action collection and its identity constraints.
func ValidateActions(actions []Action) error {
	if len(actions) == 0 {
		return fmt.Errorf("actions are required")
	}

	actionIDs := make(map[string]struct{}, len(actions))
	for i, action := range actions {
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

// CloneActions returns an independent copy of an action collection.
func CloneActions(actions []Action) []Action {
	if actions == nil {
		return nil
	}

	cloned := make([]Action, len(actions))
	for i := range actions {
		cloned[i] = actions[i].Clone()
	}
	return cloned
}

// TargetStrategy identifies whether and how an action resolves concrete
// operation targets.
type TargetStrategy string

const (
	TargetStrategyNone               TargetStrategy = "none"
	TargetStrategyComponent          TargetStrategy = "component"
	TargetStrategyRack               TargetStrategy = "rack"
	TargetStrategyAffectedComponents TargetStrategy = "affected_components"
)

// Validate checks that the target strategy is supported by the domain.
func (s TargetStrategy) Validate() error {
	switch s {
	case TargetStrategyNone,
		TargetStrategyComponent,
		TargetStrategyRack,
		TargetStrategyAffectedComponents:
		return nil
	default:
		return fmt.Errorf("unknown target strategy %q", s)
	}
}

// RequiresResolution reports whether concrete targets must be resolved for
// the strategy.
func (s TargetStrategy) RequiresResolution() bool {
	return s != TargetStrategyNone
}

// SubmitTask describes a task submission requested by an event rule.
type SubmitTask struct {
	OperationType    taskcommon.TaskType
	OperationCode    taskcommon.OperationCode
	TargetStrategy   TargetStrategy
	ConflictStrategy ConflictStrategy
	Description      string
}

// Type returns the submit_task action discriminator.
func (s SubmitTask) Type() ActionType {
	return ActionTypeSubmitTask
}

// TargetResolutionStrategy returns the task's target strategy.
func (s SubmitTask) TargetResolutionStrategy() TargetStrategy {
	return s.TargetStrategy
}

func (s SubmitTask) validate() error {
	if !s.OperationType.IsValid() {
		return fmt.Errorf("operation_type %q is invalid", s.OperationType)
	}

	if err := s.OperationCode.ValidateFor(s.OperationType); err != nil {
		return err
	}

	if err := s.TargetStrategy.Validate(); err != nil {
		return err
	}
	if !s.TargetStrategy.RequiresResolution() {
		return fmt.Errorf("submit task target strategy must require resolution")
	}

	if err := s.ConflictStrategy.validate(); err != nil {
		return err
	}

	return validateOptionalString("description", s.Description)
}

// SendAlert describes an alert emitted by an event rule.
type SendAlert struct {
	Severity Severity
	Message  string
}

// Type returns the send_alert action discriminator.
func (s SendAlert) Type() ActionType {
	return ActionTypeSendAlert
}

// TargetResolutionStrategy reports that alerts do not resolve targets.
func (SendAlert) TargetResolutionStrategy() TargetStrategy {
	return TargetStrategyNone
}

func (s SendAlert) validate() error {
	if err := s.Severity.Validate(); err != nil {
		return err
	}
	if s.Severity.IsUnspecified() {
		return fmt.Errorf("alert severity cannot be unspecified")
	}

	return validateOptionalString("alert message", s.Message)
}

// Noop describes an intentionally empty action.
type Noop struct {
	Reason string
}

// Type returns the noop action discriminator.
func (Noop) Type() ActionType {
	return ActionTypeNoop
}

// TargetResolutionStrategy reports that no-op actions do not resolve targets.
func (Noop) TargetResolutionStrategy() TargetStrategy {
	return TargetStrategyNone
}

func (n Noop) validate() error {
	return validateOptionalString("noop reason", n.Reason)
}
