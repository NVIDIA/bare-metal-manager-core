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

// Config contains the dependencies for a Processor.
type Config struct {
	Inventory  inventoryresolver.InventoryReader
	Rules      RuleResolver
	Executions eventrule.ExecutionStore
	Targets    target.Resolver
	Executor   executor.Executor
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
	if c.Targets == nil {
		return fmt.Errorf("target resolver is required")
	}
	if c.Executor == nil {
		return fmt.Errorf("action executor is required")
	}
	return nil
}
