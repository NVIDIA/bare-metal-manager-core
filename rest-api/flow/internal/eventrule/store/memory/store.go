// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package memory implements event-rule stores in memory.
package memory

import (
	"sync"
	"time"

	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
)

// Store implements rule, binding, and execution persistence in memory.
type Store struct {
	mu                   sync.RWMutex
	rules                map[uuid.UUID]dbmodel.EventRule
	bindings             map[uuid.UUID]dbmodel.EventRuleBinding
	executions           map[uuid.UUID]*memoryExecution
	executionsByDelivery map[eventrule.ExecutionDeliveryKey]uuid.UUID
	executionsBySemantic map[eventrule.ExecutionSemanticKey][]uuid.UUID
	now                  func() time.Time
}

// New constructs an empty in-memory store.
func New() *Store {
	return NewWithClock(time.Now)
}

// NewWithClock constructs an empty in-memory store with an injected
// authoritative clock.
func NewWithClock(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		rules:                make(map[uuid.UUID]dbmodel.EventRule),
		bindings:             make(map[uuid.UUID]dbmodel.EventRuleBinding),
		executions:           make(map[uuid.UUID]*memoryExecution),
		executionsByDelivery: make(map[eventrule.ExecutionDeliveryKey]uuid.UUID),
		executionsBySemantic: make(map[eventrule.ExecutionSemanticKey][]uuid.UUID),
		now:                  now,
	}
}

var (
	_ eventrule.RuleStore      = (*Store)(nil)
	_ eventrule.BindingStore   = (*Store)(nil)
	_ eventrule.ExecutionStore = (*Store)(nil)
)
