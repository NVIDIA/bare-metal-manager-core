// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	converterdao "github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/dao"
	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
)

type memoryExecution struct {
	persisted dbmodel.EventActionExecution
}

// CreateExecution atomically creates or deduplicates a pending action
// execution.
func (s *Store) CreateExecution(
	_ context.Context,
	identity eventrule.ExecutionIdentity,
) (*eventrule.Execution, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()

	if id, exists := s.executionsByKey[identity.Key()]; exists {
		return nil, s.recordDuplicate(id, now)
	}

	return s.newExecution(identity, now)
}

// TransitionExecution atomically persists an attempt result.
func (s *Store) TransitionExecution(
	_ context.Context,
	id uuid.UUID,
	result eventrule.ExecutionResult,
) (*eventrule.Execution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()

	execution, err := s.execution(id)
	if err != nil {
		return nil, err
	}
	if err := execution.TransitionTo(result, now); err != nil {
		return nil, err
	}
	if err := s.setExecution(execution); err != nil {
		return nil, err
	}

	return execution, nil
}

// Executions returns stable execution snapshots for diagnostics and
// tests.
func (s *Store) Executions() ([]eventrule.Execution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	executions := make([]eventrule.Execution, 0, len(s.executions))
	for id := range s.executions {
		execution, err := s.execution(id)
		if err != nil {
			return nil, err
		}
		executions = append(executions, *execution)
	}

	slices.SortFunc(executions, func(a, b eventrule.Execution) int {
		return cmp.Compare(a.ID.String(), b.ID.String())
	})

	return executions, nil
}

func (s *Store) execution(id uuid.UUID) (*eventrule.Execution, error) {
	record := s.executions[id]
	if record == nil {
		return nil, fmt.Errorf("%w: %s", eventrule.ErrExecutionNotFound, id)
	}

	return converterdao.EventActionExecutionFrom(&record.persisted)
}

func (s *Store) setExecution(execution *eventrule.Execution) error {
	record := s.executions[execution.ID]
	if record == nil {
		return fmt.Errorf("%w: %s", eventrule.ErrExecutionNotFound, execution.ID)
	}

	persisted, err := converterdao.EventActionExecutionTo(execution)
	if err != nil {
		return err
	}
	record.persisted = *persisted

	return nil
}

func (s *Store) recordDuplicate(id uuid.UUID, observedAt time.Time) error {
	execution, err := s.execution(id)
	if err != nil {
		return err
	}

	execution.Observations++
	if observedAt.After(execution.UpdatedAt) {
		execution.UpdatedAt = observedAt
	}
	return s.setExecution(execution)
}

func (s *Store) newExecution(
	identity eventrule.ExecutionIdentity,
	now time.Time,
) (*eventrule.Execution, error) {
	execution, err := eventrule.NewExecution(identity, now)
	if err != nil {
		return nil, err
	}
	persisted, err := converterdao.EventActionExecutionTo(execution)
	if err != nil {
		return nil, err
	}

	record := &memoryExecution{persisted: *persisted}
	s.executions[execution.ID] = record
	s.executionsByKey[identity.Key()] = execution.ID

	return s.execution(execution.ID)
}
