// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
)

var (
	// ErrOperationRunRequired reports that Create was called without a run.
	ErrOperationRunRequired = errors.New("operation run is required")
	// ErrNoPlannedTargets reports that planning produced no executable targets.
	ErrNoPlannedTargets = errors.New("operation run has no planned targets")
)

// Create persists an operation run and its frozen planned targets.
func (m *ManagerImpl) Create(
	ctx context.Context,
	run *operationrun.OperationRun,
) (uuid.UUID, error) {
	if err := m.requireDependencies(); err != nil {
		return uuid.Nil, err
	}

	if run == nil {
		return uuid.Nil, ErrOperationRunRequired
	}

	targets, err := m.planner.Plan(ctx, run)
	if err != nil {
		return uuid.Nil, fmt.Errorf("plan operation run targets: %w", err)
	}
	if len(targets) == 0 {
		return uuid.Nil, ErrNoPlannedTargets
	}

	var id uuid.UUID
	transactionFn := func(txCtx context.Context) error {
		runID, err := m.store.Create(txCtx, run)
		if err != nil {
			return err
		}

		if err := m.store.CreateTargets(txCtx, runID, targets); err != nil {
			return err
		}

		id = runID
		return nil
	}

	if err := m.store.RunInTransaction(ctx, transactionFn); err != nil {
		return uuid.Nil, fmt.Errorf("create operation run: %w", err)
	}

	return id, nil
}
