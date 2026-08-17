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

// Claim atomically creates, suppresses, or resumes an action execution.
func (s *Store) Claim(
	_ context.Context,
	claim eventrule.ExecutionClaim,
) (*eventrule.Execution, error) {
	if err := claim.Validate(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if id, exists := s.executionsByDelivery[claim.DeliveryKey()]; exists {
		return s.claimExisting(id, claim)
	}

	deduplicated, err := s.dedupeExecution(claim)
	if err != nil || deduplicated {
		return nil, err
	}

	return s.newExecution(claim)
}

// Transition atomically moves an owned execution to the requested state.
func (s *Store) Transition(
	_ context.Context,
	id uuid.UUID,
	state eventrule.ExecutionState,
	now time.Time,
) (*eventrule.Execution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	execution, err := s.execution(id)
	if err != nil {
		return nil, err
	}

	if err := execution.TransitionTo(state, now.UTC()); err != nil {
		return nil, err
	}

	if err := s.setExecution(execution); err != nil {
		return nil, err
	}

	return execution, nil
}

// Executions returns stable execution snapshots for diagnostics and tests.
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

func (s *Store) claimExisting(
	id uuid.UUID,
	claim eventrule.ExecutionClaim,
) (*eventrule.Execution, error) {
	execution, err := s.execution(id)
	if err != nil {
		return nil, err
	}

	result, claimErr := execution.TryClaim(claim.Now)
	if err := s.setExecution(execution); err != nil {
		return nil, err
	}

	return result, claimErr
}

func (s *Store) dedupeExecution(claim eventrule.ExecutionClaim) (bool, error) {
	if claim.Dedupe == nil {
		return false, nil
	}

	executionIDs := s.executionsBySemantic[claim.SemanticKey()]
	for _, id := range executionIDs {
		execution, err := s.execution(id)
		if err != nil {
			return false, err
		}

		if !execution.TryDeduplicate(claim.Dedupe, claim.Now) {
			continue
		}

		if err := s.setExecution(execution); err != nil {
			return false, err
		}

		return true, nil
	}

	return false, nil
}

func (s *Store) newExecution(
	claim eventrule.ExecutionClaim,
) (*eventrule.Execution, error) {
	execution := claim.NewExecutionUnchecked()
	persisted, err := converterdao.EventActionExecutionTo(execution)
	if err != nil {
		return nil, err
	}

	record := &memoryExecution{persisted: *persisted}
	s.executions[execution.ID] = record
	s.executionsByDelivery[claim.DeliveryKey()] = execution.ID

	if claim.Dedupe != nil {
		semanticKey := claim.SemanticKey()
		s.executionsBySemantic[semanticKey] = append(
			s.executionsBySemantic[semanticKey],
			execution.ID,
		)
	}

	return s.execution(execution.ID)
}
