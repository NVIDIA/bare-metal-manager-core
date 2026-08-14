// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"fmt"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	inventoryresolver "github.com/NVIDIA/infra-controller/rest-api/flow/internal/inventory/resolver"
)

// Config contains the dependencies and runtime settings for a Processor.
type Config struct {
	Inventory  inventoryresolver.InventoryReader
	Rules      RuleResolver
	Executions eventrule.ExecutionStore
	Executor   executor.Executor

	Clock func() time.Time
}

// Validate checks that all required processor dependencies and runtime
// settings are valid.
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
	if c.Executor == nil {
		return fmt.Errorf("action executor is required")
	}

	return nil
}

func (c Config) clock() func() time.Time {
	if c.Clock != nil {
		return c.Clock
	}
	return time.Now
}
