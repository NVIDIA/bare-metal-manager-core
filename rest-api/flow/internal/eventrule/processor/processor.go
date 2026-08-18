// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"errors"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/target"
	inventoryresolver "github.com/NVIDIA/infra-controller/rest-api/flow/internal/inventory/resolver"
)

// Processor orchestrates event enrichment, rule selection, and processing.
type Processor struct {
	inventory  *inventoryresolver.Resolver
	rules      RuleResolver
	executions eventrule.ExecutionStore
	targets    target.Resolver
	executor   executor.Executor
}

// New constructs an event processor.
func New(config Config) (*Processor, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Processor{
		inventory:  inventoryresolver.New(config.Inventory),
		rules:      config.Rules,
		executions: config.Executions,
		targets:    config.Targets,
		executor:   config.Executor,
	}, nil
}

// Process validates, prepares, and processes every eligible action.
func (p *Processor) Process(ctx context.Context, envelope eventrule.Envelope) error {
	prepared, err := p.prepare(ctx, envelope)
	if err != nil || prepared.Rule == nil {
		return err
	}

	var actionErrors []error
	for _, action := range prepared.Rule.Actions {
		if err := p.processAction(ctx, prepared, action); err != nil {
			actionErrors = append(actionErrors, fmt.Errorf("action %q: %w", action.ID, err))
		}
	}

	return errors.Join(actionErrors...)
}
