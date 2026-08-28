// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
)

type executionTaskKey struct {
	executionID uuid.UUID
	rackID      uuid.UUID
}

// GetExecutionTask returns the task associated with one execution and rack. A
// missing association returns (nil, nil).
func (s *Store) GetExecutionTask(
	_ context.Context,
	executionID uuid.UUID,
	rackID uuid.UUID,
) (*eventrule.ExecutionTask, error) {
	if executionID == uuid.Nil {
		return nil, fmt.Errorf("execution id is required")
	}

	if rackID == uuid.Nil {
		return nil, fmt.Errorf("rack id is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	association, exists := s.executionTasks[executionTaskKey{
		executionID: executionID,
		rackID:      rackID,
	}]
	if !exists {
		return nil, nil
	}

	return &association, nil
}

// CreateExecutionTask atomically inserts an execution-task association or
// returns the existing association for the same execution and rack.
func (s *Store) CreateExecutionTask(
	_ context.Context,
	association eventrule.ExecutionTask,
) (*eventrule.ExecutionTask, error) {
	if err := association.Validate(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.execution(association.ExecutionID); err != nil {
		return nil, err
	}

	key := executionTaskKey{
		executionID: association.ExecutionID,
		rackID:      association.RackID,
	}
	if existing, exists := s.executionTasks[key]; exists {
		return &existing, nil
	}

	s.executionTasks[key] = association

	created := association

	return &created, nil
}
