// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"fmt"

	eventexecutor "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	inventoryresolver "github.com/NVIDIA/infra-controller/rest-api/flow/internal/inventory/resolver"
)

// Config contains the external capabilities used to assemble an event-rule
// manager. Internal registries and the processor are constructed by New.
type Config struct {
	Store       StoreConfig
	Inventory   inventoryresolver.InventoryReader
	TaskManager eventexecutor.TaskManager
	AlertSender eventexecutor.AlertSender
}

// Validate checks that the manager can assemble a complete internal runtime.
func (c Config) Validate() error {
	if err := c.Store.Validate(); err != nil {
		return err
	}

	if c.Inventory == nil {
		return fmt.Errorf("inventory reader is required")
	}

	if c.TaskManager == nil {
		return fmt.Errorf("task manager is required")
	}

	return nil
}
