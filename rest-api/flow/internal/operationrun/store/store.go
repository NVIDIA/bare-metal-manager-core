// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package store persists operation runs and their materialized rack targets.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/dao"
	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
)

const currentPhaseIndexSubquery = `(
	SELECT MAX(phase_index)
	FROM operation_run_target
	WHERE operation_run_id = ?
)`

// Store is the persistence layer for operation runs and their frozen rack
// execution targets.
type Store interface {
	// Create inserts one operation_run row in the initial pending state.
	Create(ctx context.Context, run *operationrun.OperationRun) (uuid.UUID, error)

	// Get returns the operation run with the given ID, or an error if not found.
	Get(ctx context.Context, id uuid.UUID) (*operationrun.OperationRun, error)

	// List returns operation runs matching opts, along with the total count
	// before pagination is applied. Selector and operation template are not
	// populated because list responses use the lightweight summary shape.
	List(
		ctx context.Context,
		opts operationrun.ListOptions,
	) ([]*operationrun.OperationRun, int32, error)

	// CreateTargets inserts materialized rack execution targets for a run. The
	// dispatcher calls this when opening a phase.
	CreateTargets(
		ctx context.Context,
		runID uuid.UUID,
		targets []*operationrun.OperationRunTarget,
	) error

	// ListTargets returns targets for one operation run, along with the total
	// count before pagination is applied.
	ListTargets(
		ctx context.Context,
		runID uuid.UUID,
		opts operationrun.TargetListOptions,
	) ([]*operationrun.OperationRunTarget, int32, error)

	// RunInTransaction executes fn within a database transaction. The
	// transaction is propagated through ctx so nested Store calls participate in
	// it automatically. fn must use the ctx it receives.
	RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

// txKeyType is an unexported type for the transaction context key, preventing
// accidental collisions with keys from other packages.
type txKeyType struct{}

var txKey = txKeyType{}

// PostgresStore implements Store using PostgreSQL via bun.
type PostgresStore struct {
	pg *cdb.Session
}

// NewPostgresStore creates a PostgreSQL-backed operation-run store.
func NewPostgresStore(pg *cdb.Session) *PostgresStore {
	return &PostgresStore{pg: pg}
}

// idb returns the active bun.IDB for ctx: the bun.Tx if inside a
// RunInTransaction call, or the underlying *bun.DB otherwise.
func (s *PostgresStore) idb(ctx context.Context) bun.IDB {
	if tx, ok := ctx.Value(txKey).(bun.Tx); ok {
		return tx
	}
	return s.pg.DB
}

// RunInTransaction implements Store.
func (s *PostgresStore) RunInTransaction(
	ctx context.Context,
	fn func(ctx context.Context) error,
) error {
	return s.pg.DB.RunInTx(
		ctx,
		&sql.TxOptions{},
		func(ctx context.Context, tx bun.Tx) error { //nolint:exhaustruct,wrapcheck
			return fn(context.WithValue(ctx, txKey, tx))
		},
	)
}

// Create implements Store.
func (s *PostgresStore) Create(
	ctx context.Context,
	run *operationrun.OperationRun,
) (uuid.UUID, error) {
	if run == nil {
		return uuid.Nil, fmt.Errorf("operation run is required")
	}
	run.Status = operationrun.OperationRunStatusPending
	run.StatusReason = operationrun.OperationRunStatusReasonNone

	row := dao.OperationRunTo(run)
	var id uuid.UUID
	err := s.idb(ctx).
		NewInsert().
		Model(row).
		Returning("id").
		Scan(ctx, &id)
	if err != nil {
		return uuid.Nil, err
	}

	return id, nil
}

// Get implements Store.
func (s *PostgresStore) Get(
	ctx context.Context,
	id uuid.UUID,
) (*operationrun.OperationRun, error) {
	var row dbmodel.OperationRun

	err := s.idb(ctx).NewSelect().
		Model(&row).
		Where("orun.id = ?", id).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("operation run %s not found", id)
		}

		return nil, err
	}

	return dao.OperationRunFrom(&row), nil
}

// List implements Store.
func (s *PostgresStore) List(
	ctx context.Context,
	opts operationrun.ListOptions,
) ([]*operationrun.OperationRun, int32, error) {
	var rows []dbmodel.OperationRun

	q := s.idb(ctx).NewSelect().Model(&rows)
	if opts.Name != nil {
		if filterable := opts.Name.ToFilterable("orun.name"); filterable != nil {
			q = filterable.ApplyTo(q)
		}
	}
	q = applyStateFilters(q, opts.States)
	q = applyOperationKindFilters(q, opts.OperationKinds)

	total, err := q.Count(ctx)
	if err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return nil, 0, nil
	}

	q = q.Column(
		"id",
		"name",
		"description",
		"status",
		"status_reason",
		"status_message",
		"options",
		"operation_type",
		"operation_code",
		"created_at",
		"updated_at",
		"started_at",
		"finished_at",
	).OrderExpr("orun.created_at DESC")
	if opts.Pagination != nil {
		q = q.Offset(opts.Pagination.Offset).Limit(opts.Pagination.Limit)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, 0, err
	}

	runs := make([]*operationrun.OperationRun, len(rows))
	for i := range rows {
		runs[i] = dao.OperationRunFrom(&rows[i])
	}

	return runs, int32(total), nil
}

// CreateTargets implements Store.
func (s *PostgresStore) CreateTargets(
	ctx context.Context,
	runID uuid.UUID,
	targets []*operationrun.OperationRunTarget,
) error {
	if runID == uuid.Nil {
		return fmt.Errorf("operation run ID is required")
	}
	if len(targets) == 0 {
		return nil
	}

	rows := make([]*dbmodel.OperationRunTarget, 0, len(targets))
	for idx, target := range targets {
		if target == nil {
			return fmt.Errorf("operation run target %d is required", idx)
		}
		target.OperationRunID = runID
		target.Status = operationrun.OperationRunTargetStatusPending
		rows = append(rows, dao.OperationRunTargetTo(target))
	}

	_, err := s.idb(ctx).NewInsert().Model(&rows).Exec(ctx)
	return err
}

// ListTargets implements Store.
func (s *PostgresStore) ListTargets(
	ctx context.Context,
	runID uuid.UUID,
	opts operationrun.TargetListOptions,
) ([]*operationrun.OperationRunTarget, int32, error) {
	if _, err := s.Get(ctx, runID); err != nil {
		return nil, 0, err
	}

	var rows []dbmodel.OperationRunTarget

	q := s.idb(ctx).NewSelect().
		Model(&rows).
		Where("ort.operation_run_id = ?", runID)
	if opts.Status != "" {
		q = q.Where("ort.status = ?", opts.Status)
	}
	q = applyTargetPhaseScope(q, runID, opts.PhaseScope)

	total, err := q.Count(ctx)
	if err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return nil, 0, nil
	}

	q = q.OrderExpr("ort.phase_index ASC, ort.sequence_index ASC")
	if opts.Pagination != nil {
		q = q.Offset(opts.Pagination.Offset).Limit(opts.Pagination.Limit)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, 0, err
	}

	targets := make([]*operationrun.OperationRunTarget, len(rows))
	for i := range rows {
		targets[i] = dao.OperationRunTargetFrom(&rows[i])
	}

	return targets, int32(total), nil
}

func applyStateFilters(
	q *bun.SelectQuery,
	filters []operationrun.StateFilter,
) *bun.SelectQuery {
	predicates := make([]string, 0, len(filters))
	args := make([]any, 0, len(filters)*2)

	for _, filter := range filters {
		if filter.IsZero() {
			continue
		}

		parts := make([]string, 0, 2)
		if filter.Status != "" {
			parts = append(parts, "orun.status = ?")
			args = append(args, filter.Status)
		}
		if filter.Reason != "" {
			parts = append(parts, "orun.status_reason = ?")
			args = append(args, filter.Reason)
		}

		predicates = append(
			predicates,
			"("+strings.Join(parts, " AND ")+")",
		)
	}

	if len(predicates) == 0 {
		return q
	}

	return q.Where("("+strings.Join(predicates, " OR ")+")", args...)
}

func applyOperationKindFilters(
	q *bun.SelectQuery,
	filters []operationrun.OperationKindFilter,
) *bun.SelectQuery {
	predicates := make([]string, 0, len(filters))
	args := make([]any, 0, len(filters)*2)

	for _, filter := range filters {
		if filter.Type == "" {
			continue
		}

		parts := []string{"orun.operation_type = ?"}
		args = append(args, filter.Type)
		if filter.Code != "" {
			parts = append(parts, "orun.operation_code = ?")
			args = append(args, filter.Code)
		}

		predicates = append(
			predicates,
			"("+strings.Join(parts, " AND ")+")",
		)
	}

	if len(predicates) == 0 {
		return q
	}

	return q.Where("("+strings.Join(predicates, " OR ")+")", args...)
}

func applyTargetPhaseScope(
	q *bun.SelectQuery,
	runID uuid.UUID,
	scope operationrun.TargetPhaseScope,
) *bun.SelectQuery {
	switch scope {
	case operationrun.TargetPhaseScopeCurrentPhase:
		return q.Where(
			"ort.phase_index = "+currentPhaseIndexSubquery,
			runID,
		)
	case operationrun.TargetPhaseScopeCompletedPhases:
		return q.Where(
			"ort.phase_index < "+currentPhaseIndexSubquery,
			runID,
		)
	case operationrun.TargetPhaseScopeCurrentAndCompletedPhases:
		return q
	default:
		return q.Where(
			"ort.phase_index = "+currentPhaseIndexSubquery,
			runID,
		)
	}
}
