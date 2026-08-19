// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dao

import (
	"fmt"
	"time"

	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
)

// EventActionExecutionTo converts a domain execution to a database model.
func EventActionExecutionTo(
	execution *eventrule.Execution,
) (*dbmodel.EventActionExecution, error) {
	if err := execution.Validate(); err != nil {
		return nil, err
	}

	var nextAttemptAt *time.Time
	if !execution.NextAttemptAt.IsZero() {
		next := execution.NextAttemptAt
		nextAttemptAt = &next
	}
	return &dbmodel.EventActionExecution{
		ID:             execution.ID,
		EventID:        execution.EventID,
		RuleID:         execution.RuleID,
		ActionID:       execution.ActionID,
		CorrelationKey: execution.CorrelationKey,
		Status:         string(execution.Status),
		Reason:         string(execution.Reason),
		Observations:   execution.Observations,
		Attempts:       execution.Attempts,
		StatusMessage:  execution.StatusMessage,
		CreatedAt:      execution.CreatedAt,
		UpdatedAt:      execution.UpdatedAt,
		NextAttemptAt:  nextAttemptAt,
	}, nil
}

// EventActionExecutionFrom converts a database model to a domain execution.
func EventActionExecutionFrom(
	persisted *dbmodel.EventActionExecution,
) (*eventrule.Execution, error) {
	if persisted == nil {
		return nil, nil
	}

	var nextAttemptAt time.Time
	if persisted.NextAttemptAt != nil {
		nextAttemptAt = *persisted.NextAttemptAt
	}
	execution := &eventrule.Execution{
		ExecutionState: eventrule.ExecutionState{
			ExecutionStatusDetails: eventrule.ExecutionStatusDetails{
				Status:        eventrule.ExecutionStatus(persisted.Status),
				Reason:        eventrule.ExecutionReason(persisted.Reason),
				StatusMessage: persisted.StatusMessage,
			},
			NextAttemptAt: nextAttemptAt,
		},
		ExecutionIdentity: eventrule.ExecutionIdentity{
			EventID:        persisted.EventID,
			RuleID:         persisted.RuleID,
			ActionID:       persisted.ActionID,
			CorrelationKey: persisted.CorrelationKey,
		},
		ID:           persisted.ID,
		Observations: persisted.Observations,
		Attempts:     persisted.Attempts,
		CreatedAt:    persisted.CreatedAt,
		UpdatedAt:    persisted.UpdatedAt,
	}
	if err := execution.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", eventrule.ErrInvalidPersistedExecution, err)
	}
	return execution, nil
}
