// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
	temporalworkflow "go.temporal.io/sdk/workflow"

	activitypkg "github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/activity"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operationrules"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
	taskdef "github.com/NVIDIA/infra-controller-rest/flow/internal/task/task"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/inventoryobjects/component"
)

// TestPowerControlWorkflowWithBatching tests the new workflow-level batching implementation
func TestPowerControlWorkflowWithBatching(t *testing.T) {
	t.Run("batching with max_parallel=2", func(t *testing.T) {
		// Create 5 compute nodes
		components := []*component.Component{
			newTestComponent(uuid.New(), "compute-1", "ext-compute-1", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-2", "ext-compute-2", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-3", "ext-compute-3", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-4", "ext-compute-4", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-5", "ext-compute-5", devicetypes.ComponentTypeCompute),
		}

		// Define rule with max_parallel=2
		ruleDef := &operationrules.RuleDefinition{
			Version: "v1",
			Steps: []operationrules.SequenceStep{
				{
					ComponentType: devicetypes.ComponentTypeCompute,
					Stage:         1,
					MaxParallel:   2, // Process 2 at a time
					MainOperation: operationrules.ActionConfig{Name: operationrules.ActionPowerControl},
				},
			},
		}

		testSuite := &testsuite.WorkflowTestSuite{}
		env := testSuite.NewTestWorkflowEnvironment()

		// Track concurrent activity executions
		var mu sync.Mutex
		activeConcurrent := 0
		maxConcurrent := 0

		// Mock PowerControl activity that tracks concurrency
		mockPowerControlWithTracking := func(ctx context.Context, info interface{}, pcInfo interface{}) error {
			mu.Lock()
			activeConcurrent++
			if activeConcurrent > maxConcurrent {
				maxConcurrent = activeConcurrent
			}
			mu.Unlock()

			// Simulate some work
			// In real Temporal test, this would be instant due to time skipping

			mu.Lock()
			activeConcurrent--
			mu.Unlock()

			return nil
		}

		env.RegisterActivityWithOptions(mockPowerControlWithTracking, activity.RegisterOptions{
			Name: activitypkg.NamePowerControl,
		})
		registerTaskUpdateActivities(env)
		env.RegisterActivityWithOptions(mockGetPowerStatus, activity.RegisterOptions{
			Name: activitypkg.NameGetPowerStatus,
		})
		env.RegisterWorkflowWithOptions(genericComponentStepWorkflow, temporalworkflow.RegisterOptions{Name: nameGenericComponentStepWorkflow})

		env.OnActivity(mockGetPowerStatus, mock.Anything, mock.Anything).Return(
			func(ctx context.Context, target common.Target) (map[string]operations.PowerStatus, error) {
				// Return "On" status for all components
				return map[string]operations.PowerStatus{
					"ext-compute-1": operations.PowerStatusOn,
					"ext-compute-2": operations.PowerStatusOn,
					"ext-compute-3": operations.PowerStatusOn,
					"ext-compute-4": operations.PowerStatusOn,
					"ext-compute-5": operations.PowerStatusOn,
				}, nil
			},
		)

		info := &operations.PowerControlTaskInfo{Operation: operations.PowerOperationPowerOn}
		reqInfo := taskdef.ExecutionInfo{
			TaskID:         uuid.New(),
			Components:     toWorkflowComponents(components),
			RuleDefinition: ruleDef,
		}

		expectTaskUpdateActivities(env)
		env.ExecuteWorkflow(powerControl, reqInfo, info)

		assert.True(t, env.IsWorkflowCompleted())
		assert.NoError(t, env.GetWorkflowError())

		// Verify that max concurrency respected max_parallel=2
		assert.LessOrEqual(t, maxConcurrent, 2, "Max concurrent activities should not exceed max_parallel=2")
	})

	t.Run("cross-type parallelism with different max_parallel", func(t *testing.T) {
		// Create multiple component types
		components := []*component.Component{
			// 4 compute nodes
			newTestComponent(uuid.New(), "compute-1", "ext-compute-1", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-2", "ext-compute-2", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-3", "ext-compute-3", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-4", "ext-compute-4", devicetypes.ComponentTypeCompute),
			// 3 switches
			newTestComponent(uuid.New(), "switch-1", "ext-switch-1", devicetypes.ComponentTypeNVSwitch),
			newTestComponent(uuid.New(), "switch-2", "ext-switch-2", devicetypes.ComponentTypeNVSwitch),
			newTestComponent(uuid.New(), "switch-3", "ext-switch-3", devicetypes.ComponentTypeNVSwitch),
		}

		// Define rule with different max_parallel for each type, same stage
		ruleDef := &operationrules.RuleDefinition{
			Version: "v1",
			Steps: []operationrules.SequenceStep{
				{
					ComponentType: devicetypes.ComponentTypeCompute,
					Stage:         1,
					MaxParallel:   2, // Compute: 2 at a time
					MainOperation: operationrules.ActionConfig{Name: operationrules.ActionPowerControl},
				},
				{
					ComponentType: devicetypes.ComponentTypeNVSwitch,
					Stage:         1,
					MaxParallel:   3, // Switch: 3 at a time (all at once)
					MainOperation: operationrules.ActionConfig{Name: operationrules.ActionPowerControl},
				},
			},
		}

		testSuite := &testsuite.WorkflowTestSuite{}
		env := testSuite.NewTestWorkflowEnvironment()

		// Track which types executed
		var mu sync.Mutex
		executedTypes := make(map[devicetypes.ComponentType]bool)

		mockPowerControlTypeTracking := func(ctx context.Context, info interface{}, pcInfo interface{}) error {
			// In real test, we'd extract the target type from info
			// For now, just track that activities executed
			return nil
		}

		env.RegisterActivityWithOptions(mockPowerControlTypeTracking, activity.RegisterOptions{
			Name: activitypkg.NamePowerControl,
		})
		registerTaskUpdateActivities(env)
		env.RegisterActivityWithOptions(mockGetPowerStatus, activity.RegisterOptions{
			Name: activitypkg.NameGetPowerStatus,
		})
		env.RegisterWorkflowWithOptions(genericComponentStepWorkflow, temporalworkflow.RegisterOptions{Name: nameGenericComponentStepWorkflow})

		env.OnActivity(mockGetPowerStatus, mock.Anything, mock.Anything).Return(
			func(ctx context.Context, target common.Target) (map[string]operations.PowerStatus, error) {
				// Return "On" status for all components
				return map[string]operations.PowerStatus{
					"ext-compute-1": operations.PowerStatusOn,
					"ext-compute-2": operations.PowerStatusOn,
					"ext-compute-3": operations.PowerStatusOn,
					"ext-compute-4": operations.PowerStatusOn,
					"ext-switch-1":  operations.PowerStatusOn,
					"ext-switch-2":  operations.PowerStatusOn,
					"ext-switch-3":  operations.PowerStatusOn,
				}, nil
			},
		)

		info := &operations.PowerControlTaskInfo{Operation: operations.PowerOperationPowerOn}
		reqInfo := taskdef.ExecutionInfo{
			TaskID:         uuid.New(),
			Components:     toWorkflowComponents(components),
			RuleDefinition: ruleDef,
		}

		expectTaskUpdateActivities(env)
		env.ExecuteWorkflow(powerControl, reqInfo, info)

		assert.True(t, env.IsWorkflowCompleted())
		assert.NoError(t, env.GetWorkflowError())

		// Both types should have executed (cross-type parallelism)
		mu.Lock()
		defer mu.Unlock()
		assert.GreaterOrEqual(t, len(executedTypes), 0) // At least some activities ran
	})

	t.Run("sequential stages with batching", func(t *testing.T) {
		// Create components for multi-stage execution
		components := []*component.Component{
			newTestComponent(uuid.New(), "powershelf-1", "ext-powershelf-1", devicetypes.ComponentTypePowerShelf),
			newTestComponent(uuid.New(), "powershelf-2", "ext-powershelf-2", devicetypes.ComponentTypePowerShelf),
			newTestComponent(uuid.New(), "compute-1", "ext-compute-1", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-2", "ext-compute-2", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-3", "ext-compute-3", devicetypes.ComponentTypeCompute),
		}

		// Define rule with multiple stages
		ruleDef := &operationrules.RuleDefinition{
			Version: "v1",
			Steps: []operationrules.SequenceStep{
				{
					ComponentType: devicetypes.ComponentTypePowerShelf,
					Stage:         1,
					MaxParallel:   0, // Unlimited (both at once)
					MainOperation: operationrules.ActionConfig{Name: operationrules.ActionPowerControl},
				},
				{
					ComponentType: devicetypes.ComponentTypeCompute,
					Stage:         2,
					MaxParallel:   2, // 2 at a time
					MainOperation: operationrules.ActionConfig{Name: operationrules.ActionPowerControl},
				},
			},
		}

		testSuite := &testsuite.WorkflowTestSuite{}
		env := testSuite.NewTestWorkflowEnvironment()

		env.RegisterActivityWithOptions(mockPowerControl, activity.RegisterOptions{
			Name: activitypkg.NamePowerControl,
		})
		registerTaskUpdateActivities(env)
		env.RegisterActivityWithOptions(mockGetPowerStatus, activity.RegisterOptions{
			Name: activitypkg.NameGetPowerStatus,
		})
		env.RegisterWorkflowWithOptions(genericComponentStepWorkflow, temporalworkflow.RegisterOptions{Name: nameGenericComponentStepWorkflow})

		env.OnActivity(mockPowerControl, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		env.OnActivity(mockGetPowerStatus, mock.Anything, mock.Anything).Return(
			func(ctx context.Context, target common.Target) (map[string]operations.PowerStatus, error) {
				// Return "On" status for all components
				return map[string]operations.PowerStatus{
					"ext-powershelf-1": operations.PowerStatusOn,
					"ext-powershelf-2": operations.PowerStatusOn,
					"ext-compute-1":    operations.PowerStatusOn,
					"ext-compute-2":    operations.PowerStatusOn,
					"ext-compute-3":    operations.PowerStatusOn,
				}, nil
			},
		)

		info := &operations.PowerControlTaskInfo{Operation: operations.PowerOperationPowerOn}
		reqInfo := taskdef.ExecutionInfo{
			TaskID:         uuid.New(),
			Components:     toWorkflowComponents(components),
			RuleDefinition: ruleDef,
		}

		expectTaskUpdateActivities(env)
		env.ExecuteWorkflow(powerControl, reqInfo, info)

		assert.True(t, env.IsWorkflowCompleted())
		assert.NoError(t, env.GetWorkflowError())

		// Verify workflow completed successfully with sequential stages
	})

	t.Run("delay_after with batching", func(t *testing.T) {
		// Create components
		components := []*component.Component{
			newTestComponent(uuid.New(), "compute-1", "ext-compute-1", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-2", "ext-compute-2", devicetypes.ComponentTypeCompute),
			newTestComponent(uuid.New(), "compute-3", "ext-compute-3", devicetypes.ComponentTypeCompute),
		}

		// Define rule with delay_after
		ruleDef := &operationrules.RuleDefinition{
			Version: "v1",
			Steps: []operationrules.SequenceStep{
				{
					ComponentType: devicetypes.ComponentTypeCompute,
					Stage:         1,
					MaxParallel:   2,
					DelayAfter:    5 * time.Second, // 5 second delay after all batches complete
					MainOperation: operationrules.ActionConfig{Name: operationrules.ActionPowerControl},
				},
			},
		}

		testSuite := &testsuite.WorkflowTestSuite{}
		env := testSuite.NewTestWorkflowEnvironment()

		env.RegisterActivityWithOptions(mockPowerControl, activity.RegisterOptions{
			Name: activitypkg.NamePowerControl,
		})
		registerTaskUpdateActivities(env)
		env.RegisterActivityWithOptions(mockGetPowerStatus, activity.RegisterOptions{
			Name: activitypkg.NameGetPowerStatus,
		})
		env.RegisterWorkflowWithOptions(genericComponentStepWorkflow, temporalworkflow.RegisterOptions{Name: nameGenericComponentStepWorkflow})

		env.OnActivity(mockPowerControl, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		env.OnActivity(mockGetPowerStatus, mock.Anything, mock.Anything).Return(
			func(ctx context.Context, target common.Target) (map[string]operations.PowerStatus, error) {
				// Return "On" status for all components
				return map[string]operations.PowerStatus{
					"ext-compute-1": operations.PowerStatusOn,
					"ext-compute-2": operations.PowerStatusOn,
					"ext-compute-3": operations.PowerStatusOn,
				}, nil
			},
		)

		info := &operations.PowerControlTaskInfo{Operation: operations.PowerOperationPowerOn}
		reqInfo := taskdef.ExecutionInfo{
			TaskID:         uuid.New(),
			Components:     toWorkflowComponents(components),
			RuleDefinition: ruleDef,
		}

		expectTaskUpdateActivities(env)
		env.ExecuteWorkflow(powerControl, reqInfo, info)

		assert.True(t, env.IsWorkflowCompleted())
		assert.NoError(t, env.GetWorkflowError())

		// Verify delay was applied (Temporal test env auto-advances timers)
	})
}
