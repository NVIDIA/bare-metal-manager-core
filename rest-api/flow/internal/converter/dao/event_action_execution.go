// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dao

import (
	"fmt"
	"time"

	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	eventrulecodec "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/codec"
)

// EventActionExecutionTo converts a domain execution to a database model.
func EventActionExecutionTo(
	execution *eventrule.Execution,
) (*dbmodel.EventActionExecution, error) {
	if err := execution.Validate(); err != nil {
		return nil, err
	}
	plan, err := eventrulecodec.MarshalExecutionPlan(execution.Plan)
	if err != nil {
		return nil, fmt.Errorf("encode execution plan: %w", err)
	}

	var nextAttemptAt *time.Time
	if !execution.NextAttemptAt.IsZero() {
		next := execution.NextAttemptAt
		nextAttemptAt = &next
	}
	var reason *string
	if execution.Reason != eventrule.ExecutionReasonNone {
		value := string(execution.Reason)
		reason = &value
	}
	var statusMessage *string
	if execution.StatusMessage != "" {
		value := execution.StatusMessage
		statusMessage = &value
	}
	return &dbmodel.EventActionExecution{
		ID:            execution.ID,
		EventID:       execution.EventID,
		ActionName:    execution.ActionName,
		ActionType:    string(execution.Plan.Type()),
		Plan:          plan,
		Status:        string(execution.Status),
		Reason:        reason,
		Attempts:      execution.Attempts,
		StatusMessage: statusMessage,
		CreatedAt:     execution.CreatedAt,
		UpdatedAt:     execution.UpdatedAt,
		NextAttemptAt: nextAttemptAt,
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
	var reason eventrule.ExecutionReason
	if persisted.Reason != nil {
		reason = eventrule.ExecutionReason(*persisted.Reason)
	}
	var statusMessage string
	if persisted.StatusMessage != nil {
		statusMessage = *persisted.StatusMessage
	}
	plan, err := eventrulecodec.UnmarshalExecutionPlan(persisted.Plan)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: decode plan: %w",
			eventrule.ErrInvalidPersistedExecution,
			err,
		)
	}
	if string(plan.Type()) != persisted.ActionType {
		return nil, fmt.Errorf(
			"%w: action type %q does not match plan type %q",
			eventrule.ErrInvalidPersistedExecution,
			persisted.ActionType,
			plan.Type(),
		)
	}
	execution := &eventrule.Execution{
		ExecutionState: eventrule.ExecutionState{
			ExecutionStatusDetails: eventrule.ExecutionStatusDetails{
				Status:        eventrule.ExecutionStatus(persisted.Status),
				Reason:        reason,
				StatusMessage: statusMessage,
			},
			NextAttemptAt: nextAttemptAt,
		},
		ID:         persisted.ID,
		EventID:    persisted.EventID,
		ActionName: persisted.ActionName,
		Plan:       plan,
		Attempts:   persisted.Attempts,
		CreatedAt:  persisted.CreatedAt,
		UpdatedAt:  persisted.UpdatedAt,
	}
	if err := execution.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", eventrule.ErrInvalidPersistedExecution, err)
	}
	return execution, nil
}
