// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/target"
	inventoryresolver "github.com/NVIDIA/infra-controller/rest-api/flow/internal/inventory/resolver"
)

// ExecutorRegistry resolves the executor for an action type.
type ExecutorRegistry interface {
	Executor(eventrule.ActionType) (executor.Executor, error)
}

// Config contains the dependencies for a Processor.
type Config struct {
	Inventory  inventoryresolver.InventoryReader
	Rules      RuleResolver
	Events     eventrule.EventStore
	Executions eventrule.ExecutionStore
	Targets    *target.Registry
	Executors  ExecutorRegistry
}

// Validate checks that all required processor dependencies are present.
func (c Config) Validate() error {
	if c.Inventory == nil {
		return fmt.Errorf("inventory reader is required")
	}
	if c.Rules == nil {
		return fmt.Errorf("rule resolver is required")
	}
	if c.Executions == nil {
		return fmt.Errorf("execution store is required")
	}
	if c.Events == nil {
		return fmt.Errorf("event store is required")
	}
	if c.Targets == nil {
		return fmt.Errorf("target resolver registry is required")
	}
	if c.Executors == nil {
		return fmt.Errorf("executor registry is required")
	}
	return nil
}
