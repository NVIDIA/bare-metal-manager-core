// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package executor defines the action-execution boundary used by the event
// processor and implemented by concrete action dispatchers.
package executor

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
)

// Target identifies one canonical target for an action.
type Target struct {
	Kind eventrule.ResourceKind
	ID   uuid.UUID
}

// Validate checks that the target has a supported kind and canonical identity.
func (t Target) Validate() error {
	if err := t.Kind.Validate(); err != nil {
		return err
	}
	if t.ID == uuid.Nil {
		return fmt.Errorf("target id is required")
	}
	return nil
}

// PrepareRequest contains the normalized inputs needed to prepare one action
// execution.
type PrepareRequest struct {
	Execution eventrule.Execution
	Envelope  eventrule.Envelope
	Resource  eventrule.ResolvedResource
	Action    eventrule.Action
}

// TargetRequest contains the event and task information needed to resolve
// concrete targets.
type TargetRequest struct {
	EventType eventrule.Type
	Payload   json.RawMessage
	Resource  eventrule.ResolvedResource
	Task      eventrule.SubmitTask
}

// TargetResolver resolves concrete targets for a task action.
type TargetResolver interface {
	ResolveTargets(context.Context, TargetRequest) ([]Target, error)
}

// ExecutionRequest contains an execution and its prepared action inputs.
type ExecutionRequest struct {
	Execution eventrule.Execution
	Action    eventrule.Action
	Targets   []Target
}

// Validate checks the execution and action inputs.
func (r ExecutionRequest) Validate() error {
	if err := r.Execution.Validate(); err != nil {
		return fmt.Errorf("execution: %w", err)
	}
	if err := r.Action.Validate(); err != nil {
		return fmt.Errorf("action: %w", err)
	}
	for i, target := range r.Targets {
		if err := target.Validate(); err != nil {
			return fmt.Errorf("target %d: %w", i, err)
		}
	}
	return nil
}

// PreparationResult contains either a request ready for execution or an outcome
// that completes preparation without execution. Exactly one field is non-nil.
type PreparationResult struct {
	Request *ExecutionRequest
	Outcome *eventrule.ExecutionState
}

// Validate checks that preparation produced exactly one next step.
func (p PreparationResult) Validate() error {
	if (p.Request == nil) == (p.Outcome == nil) {
		return fmt.Errorf("executor preparation requires exactly one request or outcome")
	}

	if p.Outcome != nil {
		return p.Outcome.ValidateTransition()
	}

	return p.Request.Validate()
}

// Executor owns action-specific preparation and execution outcome decisions.
type Executor interface {
	// Prepare returns a valid result and a nil error. Operational results,
	// including skipped, deferred, and failed states, are represented by
	// PreparationResult. A non-nil error means that no valid result was
	// produced and indicates an executor contract failure.
	Prepare(context.Context, PrepareRequest) (PreparationResult, error)
	// Execute may be called multiple times for the same Execution.ID after a
	// deferred outcome. Implementations that produce external side effects must
	// use Execution.ID, or stable keys derived from it for partitioned work, to
	// make repeated calls idempotent and reconcile an ambiguous prior result
	// before submitting again. Attempts and rotating ownership tokens must not
	// be used as downstream idempotency identities. Execute returns a valid
	// outcome and a nil error. Operational failures are represented by deferred
	// or failed outcomes. A non-nil error means that no valid outcome was
	// produced and indicates an executor contract failure.
	Execute(context.Context, ExecutionRequest) (eventrule.ExecutionState, error)
}
