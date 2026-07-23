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

// AppliesTo reports whether the condition accepts the envelope.
func (c ActionCondition) AppliesTo(envelope Envelope) bool {
	if c.Severities != nil &&
		!slices.Contains(c.Severities, envelope.Severity) {
		return false
	}

	if c.ComponentTypes != nil &&
		!slices.Contains(c.ComponentTypes, envelope.Resource.ComponentType) {
		return false
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
// package while allowing processors to identify a specification with Type.
type ActionSpec interface {
	Type() ActionType
	validate() error
}

// Action describes one independently selected and deduplicated response.
type Action struct {
	ID        string
	Condition ActionCondition
	Spec      ActionSpec
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

// TargetStrategy identifies how a target-bearing action resolves concrete
// operation targets.
type TargetStrategy string

const (
	TargetStrategyComponent          TargetStrategy = "component"
	TargetStrategyRack               TargetStrategy = "rack"
	TargetStrategyAffectedComponents TargetStrategy = "affected_components"
)

// Validate checks that the target strategy is supported by the schema.
func (s TargetStrategy) Validate() error {
	switch s {
	case TargetStrategyComponent, TargetStrategyRack, TargetStrategyAffectedComponents:
		return nil
	default:
		return fmt.Errorf("unknown target strategy %q", s)
	}
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

func (s SendAlert) validate() error {
	if err := s.Severity.Validate(); err != nil {
		return err
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

func (n Noop) validate() error {
	return validateOptionalString("noop reason", n.Reason)
}
