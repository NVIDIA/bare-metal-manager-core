// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package executor defines the action-execution boundary used by event workers
// and the future retry scheduler.
package executor

import (
	"context"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/target"
)

// ExecutionRequest contains the execution, action, and resolved targets
// needed for one dispatch attempt.
type ExecutionRequest struct {
	Execution eventrule.Execution
	Action    eventrule.Action
	Targets   []target.Target
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

// Executor performs action side effects and produces execution results.
type Executor interface {
	// Execute may be called multiple times for the same Execution.ID after a
	// deferred result. Implementations that produce external side effects must
	// use Execution.ID, or stable keys derived from it for partitioned work, to
	// make repeated calls idempotent and reconcile an ambiguous prior result
	// before submitting again. Attempts and rotating lease tokens must not
	// be used as downstream idempotency identities. Execute returns a valid
	// result and a nil error. Operational failures are represented by deferred
	// or failed results. A context cancellation or deadline error means the
	// attempt was interrupted and is deferred by the dispatcher. Any other
	// non-nil error means that no valid result was produced and indicates an
	// executor contract failure.
	Execute(context.Context, ExecutionRequest) (eventrule.ExecutionResult, error)
}
