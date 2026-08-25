// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	converterdao "github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/dao"
	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
)

type memoryExecution struct {
	persisted dbmodel.EventActionExecution
}

// CommitEventPlan atomically inserts every immutable action plan and marks the
// event planned.
func (s *Store) CommitEventPlan(
	_ context.Context,
	eventID uuid.UUID,
	planned []eventrule.PlannedExecution,
) ([]eventrule.Execution, error) {
	if eventID == uuid.Nil {
		return nil, fmt.Errorf("execution event id is required")
	}
	seen := make(map[string]struct{}, len(planned))
	for i, item := range planned {
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("planned executions[%d]: %w", i, err)
		}
		if _, exists := seen[item.ActionName]; exists {
			return nil, fmt.Errorf(
				"planned executions[%d]: duplicate action name %q",
				i,
				item.ActionName,
			)
		}
		seen[item.ActionName] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	event, err := s.event(eventID)
	if err != nil {
		return nil, err
	}
	if event.PlannedAt != nil {
		return nil, fmt.Errorf("%w: %s", eventrule.ErrEventAlreadyPlanned, eventID)
	}
	if len(planned) != len(event.EffectivePolicy.Actions) {
		return nil, fmt.Errorf(
			"event plan has %d executions for %d applicable actions",
			len(planned),
			len(event.EffectivePolicy.Actions),
		)
	}
	for i, action := range event.EffectivePolicy.Actions {
		if planned[i].ActionName != action.Name {
			return nil, fmt.Errorf(
				"planned executions[%d] has action name %q, want %q",
				i,
				planned[i].ActionName,
				action.Name,
			)
		}
		if planned[i].ExecutionPlan.Type() != action.Spec.Type() {
			return nil, fmt.Errorf(
				"planned executions[%d] has type %q, want %q",
				i,
				planned[i].ExecutionPlan.Type(),
				action.Spec.Type(),
			)
		}
	}

	now := s.now().UTC()
	if now.Before(event.CreatedAt) {
		return nil, fmt.Errorf("event planned time cannot precede creation time")
	}

	records := make([]dbmodel.EventActionExecution, len(planned))
	for i, item := range planned {
		key := eventrule.ExecutionKey{EventID: eventID, ActionName: item.ActionName}
		if _, exists := s.executionsByKey[key]; exists {
			return nil, fmt.Errorf(
				"%w: event %s action %q",
				eventrule.ErrExecutionAlreadyExists,
				eventID,
				item.ActionName,
			)
		}
		execution, err := eventrule.NewExecution(
			eventID,
			item.ActionName,
			item.ExecutionPlan,
			now,
		)
		if err != nil {
			return nil, fmt.Errorf("create action %q execution: %w", item.ActionName, err)
		}
		persisted, err := converterdao.EventActionExecutionTo(execution)
		if err != nil {
			return nil, fmt.Errorf("convert action %q execution: %w", item.ActionName, err)
		}
		records[i] = *persisted
	}

	event.PlannedAt = &now
	persistedEvent, err := converterdao.EventTo(event)
	if err != nil {
		return nil, err
	}
	executions := make([]eventrule.Execution, len(records))
	for i := range records {
		execution, err := converterdao.EventActionExecutionFrom(&records[i])
		if err != nil {
			return nil, err
		}
		executions[i] = *execution
	}

	// All validation and conversion completes before changing store state so
	// the following writes model one database transaction.
	for i := range records {
		record := records[i]
		s.executions[record.ID] = &memoryExecution{persisted: record}
		s.executionsByKey[eventrule.ExecutionKey{
			EventID:    record.EventID,
			ActionName: record.ActionName,
		}] = record.ID
	}
	s.events[eventID] = *persistedEvent

	return executions, nil
}

// TransitionExecution atomically persists an attempt result.
func (s *Store) TransitionExecution(
	_ context.Context,
	id uuid.UUID,
	result eventrule.ExecutionResult,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()

	execution, err := s.execution(id)
	if err != nil {
		return err
	}
	if err := execution.TransitionTo(result, now); err != nil {
		return err
	}
	if err := s.setExecution(execution); err != nil {
		return err
	}

	return nil
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
