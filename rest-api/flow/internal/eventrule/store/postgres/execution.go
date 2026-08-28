// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	converterdao "github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/dao"
	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type executionClaimKind uint8

const (
	pendingExecutionClaim executionClaimKind = iota
	retryExecutionClaim
)

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
	if err := request.Validate(); err != nil {
		return nil, err
	}

	var claims []eventrule.ClaimedExecution
	err := s.runInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		now, err := s.timestamp(ctx, tx)
		if err != nil {
			return err
		}

		var records []dbmodel.EventActionExecution
		query := tx.NewSelect().
			Model(&records).
			Limit(request.Limit).
			For("UPDATE SKIP LOCKED")

		switch kind {
		case pendingExecutionClaim:
			query = query.
				Where("eae.status = ?", string(eventrule.ExecutionStatusPending)).
				OrderExpr("eae.created_at ASC, eae.id ASC")
		case retryExecutionClaim:
			query = query.
				Where("eae.status = ?", string(eventrule.ExecutionStatusDeferred)).
				Where("eae.next_attempt_at <= ?", now).
				OrderExpr("eae.next_attempt_at ASC, eae.id ASC")
		default:
			return fmt.Errorf("unknown execution claim kind %d", kind)
		}

		if err := query.Scan(ctx); err != nil {
			return err
		}

		claims = make([]eventrule.ClaimedExecution, len(records))
		for i := range records {
			execution, err := converterdao.EventActionExecutionFrom(&records[i])
			if err != nil {
				return err
			}

			token := uuid.New()
			if err := execution.Claim(request.Owner, token, now); err != nil {
				return err
			}

			if err := updateExecution(ctx, tx, execution); err != nil {
				return err
			}

			claims[i] = eventrule.ClaimedExecution{
				Execution: execution.Clone(),
				Token:     token,
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// TransitionClaimedExecution persists an attempt result only while token owns
// the locked running execution.
func (s *Store) TransitionClaimedExecution(
	ctx context.Context,
	id uuid.UUID,
	token uuid.UUID,
	result eventrule.ExecutionResult,
) error {
	if id == uuid.Nil {
		return fmt.Errorf("execution id is required")
	}
	if token == uuid.Nil {
		return fmt.Errorf("execution claim token is required")
	}
	if err := result.Validate(); err != nil {
		return err
	}

	return s.runInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		var record dbmodel.EventActionExecution
		err := tx.NewSelect().
			Model(&record).
			Where("eae.id = ?", id).
			For("UPDATE").
			Scan(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", eventrule.ErrExecutionNotFound, id)
		}
		if err != nil {
			return err
		}

		execution, err := converterdao.EventActionExecutionFrom(&record)
		if err != nil {
			return err
		}

		now, err := s.timestamp(ctx, tx)
		if err != nil {
			return err
		}

		if err := execution.TransitionClaimedTo(token, result, now); err != nil {
			return err
		}

		return updateExecution(ctx, tx, execution)
	})
}

func updateExecution(
	ctx context.Context,
	db bun.IDB,
	execution *eventrule.Execution,
) error {
	record, err := converterdao.EventActionExecutionTo(execution)
	if err != nil {
		return err
	}

	result, err := db.NewUpdate().
		Model(record).
		Column(
			"status",
			"reason",
			"attempts",
			"claim_token",
			"claim_owner",
			"status_message",
			"updated_at",
			"next_attempt_at",
		).
		WherePK().
		Exec(ctx)
	if err != nil {
		return err
	}

	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("%w: %s", eventrule.ErrExecutionNotFound, execution.ID)
	}

	return nil
}

// Events returns stable event snapshots for diagnostics and integration tests
// without recording another observation.
func (s *Store) Events(ctx context.Context) ([]eventrule.Event, error) {
	var records []dbmodel.Event
	if err := s.pg.DB.NewSelect().
		Model(&records).
		OrderExpr("e.id ASC").
		Scan(ctx); err != nil {
		return nil, err
	}

	events := make([]eventrule.Event, len(records))
	for i := range records {
		event, err := converterdao.EventFrom(&records[i])
		if err != nil {
			return nil, err
		}

		events[i] = event.Clone()
	}

	return events, nil
}

// Executions returns stable execution snapshots for diagnostics and
// integration tests.
func (s *Store) Executions(ctx context.Context) ([]eventrule.Execution, error) {
	var records []dbmodel.EventActionExecution
	if err := s.pg.DB.NewSelect().
		Model(&records).
		OrderExpr("eae.id ASC").
		Scan(ctx); err != nil {
		return nil, err
	}

	executions := make([]eventrule.Execution, len(records))
	for i := range records {
		execution, err := converterdao.EventActionExecutionFrom(&records[i])
		if err != nil {
			return nil, err
		}

		executions[i] = execution.Clone()
	}

	return executions, nil
}
