// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package manager coordinates operation-run creation, planning, persistence,
// and future dispatching. Service code should depend on this package rather
// than reaching into planner or store directly.
package manager

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
	operationrunplanner "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun/manager/planner"
)

// Manager is the operation-run business logic boundary used by service code.
type Manager interface {
	Create(ctx context.Context, run *operationrun.OperationRun) (uuid.UUID, error)
	Get(ctx context.Context, id uuid.UUID) (*operationrun.OperationRun, error)
	List(
		ctx context.Context,
		opts operationrun.ListOptions,
	) ([]*operationrun.OperationRun, int32, error)
	ListTargets(
		ctx context.Context,
		id uuid.UUID,
		opts operationrun.TargetListOptions,
	) ([]*operationrun.OperationRunTarget, int32, error)
}

var _ Manager = (*ManagerImpl)(nil)

// ManagerImpl implements Manager.
type ManagerImpl struct {
	store   Store
	planner operationrunplanner.Planner
}

// New creates an operation-run manager.
func New(
	store Store,
	planner operationrunplanner.Planner,
) (*ManagerImpl, error) {
	manager := &ManagerImpl{store: store, planner: planner}
	if err := manager.requireDependencies(); err != nil {
		return nil, err
	}

	return manager, nil
}

func (m *ManagerImpl) requireDependencies() error {
	if m == nil {
		return fmt.Errorf("operation run manager is required")
	}

	if m.store == nil {
		return fmt.Errorf("operation run store is required")
	}

	if m.planner == nil {
		return fmt.Errorf("operation run planner is required")
	}

	return nil
}
