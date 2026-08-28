// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"errors"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/target"
	inventoryresolver "github.com/NVIDIA/infra-controller/rest-api/flow/internal/inventory/resolver"
)

// Processor orchestrates event enrichment, rule selection, and processing.
type Processor struct {
	inventory  *inventoryresolver.Resolver
	rules      RuleResolver
	events     eventrule.EventStore
	executions eventrule.ExecutionStore
	targets    *target.Registry
	executors  ExecutorRegistry
}

// New constructs an event processor.
func New(config Config) (*Processor, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Processor{
		inventory:  inventoryresolver.New(config.Inventory),
		rules:      config.Rules,
		events:     config.Events,
		executions: config.Executions,
		targets:    config.Targets,
		executors:  config.Executors,
	}, nil
}

// Process deduplicates an envelope into a durable event. Only the caller that
// creates the event plans and dispatches it; duplicates record an observation
// and stop.
func (p *Processor) Process(ctx context.Context, envelope eventrule.Envelope) error {
	prepared, err := p.prepare(ctx, envelope)
	if err != nil || prepared == nil {
		return err
	}

	executions, err := p.plan(ctx, prepared)
	if err != nil {
		return err
	}

	var executionErrors []error
	for i := range executions {
		if executions[i].Status != eventrule.ExecutionStatusPending {
			continue
		}

		if err := p.dispatch(ctx, &executions[i]); err != nil {
			executionErrors = append(
				executionErrors,
				fmt.Errorf("action %q: %w", executions[i].ActionName, err),
			)
		}
	}
	return errors.Join(executionErrors...)
}
