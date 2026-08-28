// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/store/memory"
)

// StoreBackend identifies a manager-owned persistence implementation.
type StoreBackend string

const (
	// StoreBackendMemory keeps event-rule state in the service process.
	StoreBackendMemory StoreBackend = "memory"
)

// StoreConfig selects the persistence implementation constructed by Manager.
// TODO(database-store): Add database-backed settings with the durable store
// implementation.
type StoreConfig struct {
	Backend StoreBackend
}

// Validate checks that the selected persistence implementation is supported.
func (c StoreConfig) Validate() error {
	switch c.Backend {
	case StoreBackendMemory:
		return nil
	default:
		return fmt.Errorf("unsupported event-rule store backend %q", c.Backend)
	}
}

type eventRuleStore interface {
	eventrule.RuleStore
	eventrule.BindingStore
	eventrule.EventPlanStore
	eventrule.ExecutionStore
	eventrule.ExecutionTaskStore
}

func newStore(config StoreConfig) (eventRuleStore, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	switch config.Backend {
	case StoreBackendMemory:
		return memory.New(), nil
	default:
		return nil, fmt.Errorf("unsupported event-rule store backend %q", config.Backend)
	}
}
