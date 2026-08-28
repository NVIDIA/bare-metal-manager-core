// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package executor

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operation"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
)

// TaskManager is the downstream task-submission surface used by TaskExecutor.
type TaskManager interface {
	SubmitTask(context.Context, *operation.Request) ([]uuid.UUID, error)
}

// TaskExecutor submits one idempotent task per persisted rack target. The
// execution-task association remains temporary until generic task trigger
// provenance is introduced.
type TaskExecutor struct {
	manager      TaskManager
	associations eventrule.ExecutionTaskStore
}

// Execute submits every unrecorded rack target from the immutable plan.
func (e *TaskExecutor) Execute(ctx context.Context, request ExecutionRequest) error {
	if e == nil || e.manager == nil || e.associations == nil {
		return terminalError(fmt.Errorf("task manager and execution task store are required"))
	}

	plan, ok := request.Plan.(*eventrule.SubmitTaskPlan)
	if !ok || plan == nil {
		return terminalError(fmt.Errorf(
			"task executor received plan %T",
			request.Plan,
		))
	}

	for _, target := range plan.Targets {
		if err := e.submitTarget(ctx, request.ExecutionID, plan, target); err != nil {
			return err
		}
	}

	return nil
}

func (e *TaskExecutor) submitTarget(
	ctx context.Context,
	executionID uuid.UUID,
	plan *eventrule.SubmitTaskPlan,
	target operation.RackExecutionTarget,
) error {
	associated, err := e.associations.GetExecutionTask(ctx, executionID, target.RackID)
	if err != nil {
		return retryableError("load execution task association", err)
	}

	if associated != nil {
		if err := validateTaskAssociation(associated, executionID, target.RackID); err != nil {
			return terminalError(err)
		}

		return nil
	}

	request, err := operationRequest(executionID, plan, target)
	if err != nil {
		return terminalError(err)
	}

	taskIDs, err := e.manager.SubmitTask(ctx, request)
	if err != nil {
		return retryableError("submit task", err)
	}

	if len(taskIDs) != 1 || taskIDs[0] == uuid.Nil {
		return terminalError(errors.New("task submission did not return exactly one valid task id"))
	}

	requested := eventrule.ExecutionTask{
		ExecutionID: executionID,
		RackID:      target.RackID,
		TaskID:      taskIDs[0],
	}

	associated, err = e.associations.CreateExecutionTask(ctx, requested)
	if err != nil {
		return retryableError("persist execution task association", err)
	}

	if associated == nil {
		return terminalError(errors.New("execution task store returned a nil association"))
	}

	if err := validateTaskAssociation(associated, executionID, target.RackID); err != nil {
		return terminalError(err)
	}

	if associated.TaskID != requested.TaskID {
		return terminalError(fmt.Errorf(
			"execution task association returned task %s, submitted task was %s",
			associated.TaskID,
			requested.TaskID,
		))
	}

	return nil
}

func validateTaskAssociation(
	association *eventrule.ExecutionTask,
	executionID uuid.UUID,
	rackID uuid.UUID,
) error {
	if err := association.Validate(); err != nil {
		return fmt.Errorf("invalid execution task association: %w", err)
	}

	if association.ExecutionID != executionID || association.RackID != rackID {
		return fmt.Errorf(
			"execution task association identity does not match execution %s rack %s",
			executionID,
			rackID,
		)
	}

	return nil
}

func operationRequest(
	executionID uuid.UUID,
	plan *eventrule.SubmitTaskPlan,
	target operation.RackExecutionTarget,
) (*operation.Request, error) {
	componentIDs := target.ComponentsByType.AllComponentUUIDs()
	componentTargets := make([]operation.ComponentTarget, len(componentIDs))
	for i, id := range componentIDs {
		componentTargets[i] = operation.ComponentTarget{UUID: id}
	}

	request := &operation.Request{
		Operation:        plan.Operation,
		TargetSpec:       operation.TargetSpec{Components: componentTargets},
		Description:      plan.Description,
		ConflictStrategy: plan.ConflictStrategy,
		RuleID:           operations.ExtractRuleID(plan.Operation.Info),
		RequiredRackID:   target.RackID,
		IdempotencyKey:   taskIdempotencyKey(executionID, target.RackID),
	}

	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("validate task request: %w", err)
	}

	return request, nil
}

func taskIdempotencyKey(executionID uuid.UUID, rackID uuid.UUID) string {
	return fmt.Sprintf("event-rule-execution:%s:rack:%s", executionID, rackID)
}

var _ Executor = (*TaskExecutor)(nil)
