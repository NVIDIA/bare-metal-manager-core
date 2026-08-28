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

type executionClaimKind uint8

const (
	pendingExecutionClaim executionClaimKind = iota
	retryExecutionClaim
)

// CommitEventPlan atomically inserts the event and every immutable action plan.
// A concurrent duplicate records another observation and returns (nil, nil).
func (s *Store) CommitEventPlan(
	ctx context.Context,
	definition eventrule.Event,
	planned []eventrule.PlannedExecution,
) (*eventrule.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := definition.ValidateDefinition(); err != nil {
		return nil, err
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

	if err := validateEventPlan(definition, planned); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()
	if _, exists := s.eventsByKey[definition.Key]; exists {
		if _, err := s.observeEvent(definition.Key, now); err != nil {
			return nil, err
		}

		return nil, nil
	}

	event, err := eventrule.NewEvent(definition, now)
	if err != nil {
		return nil, err
	}

	records := make([]dbmodel.EventActionExecution, len(planned))
	for i, item := range planned {
		key := eventrule.ExecutionKey{EventID: event.ID, ActionName: item.ActionName}
		if _, exists := s.executionsByKey[key]; exists {
			return nil, fmt.Errorf(
				"%w: event %s action %q",
				eventrule.ErrExecutionAlreadyExists,
				event.ID,
				item.ActionName,
			)
		}

		execution, err := eventrule.NewExecution(
			event.ID,
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

	persistedEvent, err := converterdao.EventTo(event)
	if err != nil {
		return nil, err
	}

	// All validation and conversion completes before changing store state so
	// the following writes model one database transaction.
	s.events[event.ID] = *persistedEvent
	s.eventsByKey[event.Key] = event.ID
	for i := range records {
		record := records[i]
		s.executions[record.ID] = &memoryExecution{persisted: record}
		s.executionsByKey[eventrule.ExecutionKey{
			EventID:    record.EventID,
			ActionName: record.ActionName,
		}] = record.ID
	}

	return s.event(event.ID)
}

func validateEventPlan(
	event eventrule.Event,
	planned []eventrule.PlannedExecution,
) error {
	if len(planned) != len(event.EffectivePolicy.Actions) {
		return fmt.Errorf(
			"event plan has %d executions for %d applicable actions",
			len(planned),
			len(event.EffectivePolicy.Actions),
		)
	}

	for i, action := range event.EffectivePolicy.Actions {
		if planned[i].ActionName != action.Name {
			return fmt.Errorf(
				"planned executions[%d] has action name %q, want %q",
				i,
				planned[i].ActionName,
				action.Name,
			)
		}

		if planned[i].ExecutionPlan.Type() != action.Spec.Type() {
			return fmt.Errorf(
				"planned executions[%d] has type %q, want %q",
				i,
				planned[i].ExecutionPlan.Type(),
				action.Spec.Type(),
			)
		}
	}

	return nil
}

// ClaimPendingExecutions atomically allocates pending attempts.
func (s *Store) ClaimPendingExecutions(
	ctx context.Context,
	request eventrule.ExecutionClaimRequest,
) ([]eventrule.ClaimedExecution, error) {
	return s.claimExecutions(ctx, request, pendingExecutionClaim)
}

// ClaimRetryExecutions atomically allocates due deferred attempts.
func (s *Store) ClaimRetryExecutions(
	ctx context.Context,
	request eventrule.ExecutionClaimRequest,
) ([]eventrule.ClaimedExecution, error) {
	return s.claimExecutions(ctx, request, retryExecutionClaim)
}

func (s *Store) claimExecutions(
	ctx context.Context,
	request eventrule.ExecutionClaimRequest,
	kind executionClaimKind,
) ([]eventrule.ClaimedExecution, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()
	eligible := make([]eventrule.Execution, 0, len(s.executions))
	for id := range s.executions {
		execution, err := s.execution(id)
		if err != nil {
			return nil, err
		}

		if executionEligible(*execution, kind, now) {
			eligible = append(eligible, *execution)
		}
	}

	slices.SortFunc(eligible, func(a, b eventrule.Execution) int {
		if kind == retryExecutionClaim {
			if order := a.NextAttemptAt.Compare(b.NextAttemptAt); order != 0 {
				return order
			}
		} else if order := a.CreatedAt.Compare(b.CreatedAt); order != 0 {
			return order
		}

		return cmp.Compare(a.ID.String(), b.ID.String())
	})

	if len(eligible) > request.Limit {
		eligible = eligible[:request.Limit]
	}

	type update struct {
		id        uuid.UUID
		persisted dbmodel.EventActionExecution
		claim     eventrule.ClaimedExecution
	}
	updates := make([]update, len(eligible))
	for i := range eligible {
		execution := eligible[i].Clone()
		token := uuid.New()

		if err := execution.Claim(request.Owner, token, now); err != nil {
			return nil, err
		}

		persisted, err := converterdao.EventActionExecutionTo(&execution)
		if err != nil {
			return nil, err
		}

		updates[i] = update{
			id:        execution.ID,
			persisted: *persisted,
			claim: eventrule.ClaimedExecution{
				Execution: execution,
				Token:     token,
			},
		}
	}

	claims := make([]eventrule.ClaimedExecution, len(updates))
	for i, update := range updates {
		s.executions[update.id].persisted = update.persisted
		claims[i] = update.claim
	}

	return claims, nil
}

func executionEligible(
	execution eventrule.Execution,
	kind executionClaimKind,
	now time.Time,
) bool {
	switch kind {
	case pendingExecutionClaim:
		return execution.Status == eventrule.ExecutionStatusPending
	case retryExecutionClaim:
		return execution.RetryDue(now)
	default:
		return false
	}
}

// TransitionClaimedExecution atomically persists an owned attempt result.
func (s *Store) TransitionClaimedExecution(
	ctx context.Context,
	id uuid.UUID,
	token uuid.UUID,
	result eventrule.ExecutionResult,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	execution, err := s.execution(id)
	if err != nil {
		return err
	}

	if err := execution.TransitionClaimedTo(token, result, s.now().UTC()); err != nil {
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
