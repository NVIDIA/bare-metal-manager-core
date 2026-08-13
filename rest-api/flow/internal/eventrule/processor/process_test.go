// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	eventexecutor "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	memorystore "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/store/memory"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/deviceinfo"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/location"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/inventoryobjects/rack"
	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const (
	runtimeMaxExecutionAttempts = 3
	runtimeInitialRetryDelay    = time.Second
)

func TestProcessor_Process(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	tests := map[string]struct {
		rule             *eventrule.Rule
		targets          []eventexecutor.Target
		targetErr        error
		executorErr      error
		wantErr          error
		wantStatus       eventrule.ExecutionStatus
		wantReason       eventrule.ExecutionReason
		wantExecutions   int
		wantExecutorRuns int
	}{
		"no effective rule is accepted": {},
		"condition skip creates no execution": {
			rule: processorRuntimeRule(eventrule.NewAction(
				"skip",
				eventrule.ActionCondition{
					ComponentTypes: []flowtypes.ComponentType{flowtypes.ComponentTypeNVSwitch},
				},
				eventrule.Noop{},
			)),
		},
		"noop completes": {
			rule:             processorRuntimeRule(noopAction("noop")),
			wantStatus:       eventrule.ExecutionStatusCompleted,
			wantExecutions:   1,
			wantExecutorRuns: 1,
		},
		"no targets skips submit": {
			rule:           processorRuntimeRule(submitAction("submit")),
			wantStatus:     eventrule.ExecutionStatusSkipped,
			wantReason:     eventrule.ExecutionReasonNoTargets,
			wantExecutions: 1,
		},
		"terminal target error produces failed outcome": {
			rule:           processorRuntimeRule(submitAction("submit")),
			targetErr:      terminalError(errors.New("invalid topology")),
			wantStatus:     eventrule.ExecutionStatusFailed,
			wantExecutions: 1,
		},
		"retryable executor error schedules retry": {
			rule:             processorRuntimeRule(noopAction("noop")),
			executorErr:      errors.New("alert service unavailable"),
			wantStatus:       eventrule.ExecutionStatusDeferred,
			wantReason:       eventrule.ExecutionReasonAttemptFailed,
			wantExecutions:   1,
			wantExecutorRuns: 1,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			store := memorystore.New()
			var executorRuns int
			processor := runtimeProcessor(
				t,
				rackID,
				test.rule,
				store,
				targetResolverFunc(func(
					context.Context,
					eventexecutor.TargetRequest,
				) ([]eventexecutor.Target, error) {
					return test.targets, test.targetErr
				}),
				actionExecutorFunc(func(
					context.Context,
					eventexecutor.ExecutionRequest,
				) (string, error) {
					executorRuns++
					return "result-1", test.executorErr
				}),
				&now,
			)

			err := processor.Process(context.Background(), runtimeEnvelope(rackID))
			if test.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr.Error())
				if errors.Is(test.wantErr, ErrTerminal) {
					require.ErrorIs(t, err, ErrTerminal)
				}
			}
			require.Equal(t, test.wantExecutorRuns, executorRuns)
			executions, err := store.Executions()
			require.NoError(t, err)
			require.Len(t, executions, test.wantExecutions)
			if test.wantExecutions > 0 {
				require.Equal(t, test.wantStatus, executions[0].Status)
				require.Equal(t, test.wantReason, executions[0].Reason)
			}
		})
	}

	t.Run("deduplication", testProcessDeduplication)
	t.Run("retries and exhausts", testProcessRetriesAndExhausts)
	t.Run("processes actions independently", testProcessProcessesActionsIndependently)
	t.Run("concurrent duplicate executes once", testProcessConcurrentDuplicateExecutesOnce)
}

func testProcessDeduplication(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	tests := map[string]struct {
		dedupe        *eventrule.Dedupe
		secondEventID uuid.UUID
	}{
		"delivery duplicate without semantic dedupe": {},
		"semantic duplicate across event IDs": {
			dedupe:        &eventrule.Dedupe{Window: time.Minute},
			secondEventID: uuid.New(),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			store := memorystore.New()
			rule := processorRuntimeRule(noopAction("noop"))
			rule.Dedupe = test.dedupe
			var runs int
			processor := runtimeProcessor(
				t, rackID, rule, store, nil,
				actionExecutorFunc(func(context.Context, eventexecutor.ExecutionRequest) (string, error) {
					runs++
					return "", nil
				}),
				&now,
			)
			first := runtimeEnvelope(rackID)
			first.CorrelationKey = "incident-1"
			second := first
			if test.secondEventID != uuid.Nil {
				second.ID = test.secondEventID
			}

			require.NoError(t, processor.Process(context.Background(), first))
			require.NoError(t, processor.Process(context.Background(), second))
			require.Equal(t, 1, runs)
			executions, err := store.Executions()
			require.NoError(t, err)
			require.Len(t, executions, 1)
			require.Equal(t, 2, executions[0].Observations)
		})
	}
}

func testProcessRetriesAndExhausts(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	store := memorystore.New()
	executorErr := errors.New("downstream unavailable")
	processor := runtimeProcessor(
		t, rackID, processorRuntimeRule(noopAction("noop")), store, nil,
		actionExecutorFunc(func(context.Context, eventexecutor.ExecutionRequest) (string, error) {
			return "", executorErr
		}),
		&now,
	)
	envelope := runtimeEnvelope(rackID)

	for attempt := 1; attempt <= runtimeMaxExecutionAttempts; attempt++ {
		err := processor.Process(context.Background(), envelope)
		require.NoError(t, err)
		executions, snapshotsErr := store.Executions()
		require.NoError(t, snapshotsErr)
		execution := executions[0]
		require.Equal(t, attempt, execution.Attempts)
		if attempt < runtimeMaxExecutionAttempts {
			require.Equal(t, eventrule.ExecutionStatusDeferred, execution.Status)
			require.Equal(
				t,
				now.Add(runtimeRetryDelay(attempt)),
				execution.NextAttemptAt,
			)
			earlyErr := processor.Process(context.Background(), envelope)
			require.ErrorIs(t, earlyErr, eventrule.ErrRetryScheduled)
			executions, snapshotsErr = store.Executions()
			require.NoError(t, snapshotsErr)
			require.Equal(t, attempt, executions[0].Attempts)
			now = execution.NextAttemptAt
		} else {
			require.Equal(t, eventrule.ExecutionStatusFailed, execution.Status)
		}
	}
}

func testProcessProcessesActionsIndependently(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	store := memorystore.New()
	firstErr := errors.New("first action unavailable")
	var executed []string
	processor := runtimeProcessor(
		t,
		rackID,
		processorRuntimeRule(noopAction("first"), noopAction("second")),
		store,
		nil,
		actionExecutorFunc(func(
			_ context.Context,
			request eventexecutor.ExecutionRequest,
		) (string, error) {
			executed = append(executed, request.Action.ID)
			if request.Action.ID == "first" {
				return "", firstErr
			}
			return "", nil
		}),
		&now,
	)

	err := processor.Process(context.Background(), runtimeEnvelope(rackID))
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second"}, executed)
	executions, snapshotsErr := store.Executions()
	require.NoError(t, snapshotsErr)
	require.Len(t, executions, 2)
	statuses := make(map[string]eventrule.ExecutionStatus, len(executions))
	for _, execution := range executions {
		statuses[execution.ActionID] = execution.Status
	}
	require.Equal(t, eventrule.ExecutionStatusDeferred, statuses["first"])
	require.Equal(t, eventrule.ExecutionStatusCompleted, statuses["second"])
}

func testProcessConcurrentDuplicateExecutesOnce(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	store := memorystore.New()
	entered := make(chan struct{})
	release := make(chan struct{})
	var runs atomic.Int32
	processor := runtimeProcessor(
		t, rackID, processorRuntimeRule(noopAction("noop")), store, nil,
		actionExecutorFunc(func(context.Context, eventexecutor.ExecutionRequest) (string, error) {
			if runs.Add(1) == 1 {
				close(entered)
			}
			<-release
			return "", nil
		}),
		&now,
	)
	envelope := runtimeEnvelope(rackID)

	const deliveries = 20
	start := make(chan struct{})
	errs := make(chan error, deliveries)
	var wg sync.WaitGroup
	for range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- processor.Process(context.Background(), envelope)
		}()
	}
	close(start)
	<-entered
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), runs.Load())
	executions, err := store.Executions()
	require.NoError(t, err)
	require.Len(t, executions, 1)
}

func runtimeProcessor(
	t *testing.T,
	rackID uuid.UUID,
	rule *eventrule.Rule,
	store eventrule.ExecutionStore,
	targets eventexecutor.TargetResolver,
	execute actionExecutorFunc,
	now *time.Time,
) *Processor {
	t.Helper()
	if targets == nil {
		targets = targetResolverFunc(func(
			context.Context,
			eventexecutor.TargetRequest,
		) ([]eventexecutor.Target, error) {
			return nil, nil
		})
	}
	resolver := ruleResolverFunc(func(
		context.Context,
		eventrule.Type,
		uuid.UUID,
	) (*eventrule.Rule, error) {
		return rule, nil
	})
	processor, err := New(Config{
		Inventory: &processorInventory{
			rack: rack.New(deviceinfo.DeviceInfo{ID: rackID}, location.Location{}),
		},
		Rules:      resolver,
		Executions: store,
		Executor: runtimeExecutor{
			targets: targets,
			execute: execute,
			now:     now,
		},
		Clock: func() time.Time { return *now },
	})
	require.NoError(t, err)
	return processor
}

func newTestProcessor(
	t *testing.T,
	inventory *processorInventory,
	rules RuleResolver,
) *Processor {
	t.Helper()
	if rules == nil {
		rules = ruleResolverFunc(func(
			context.Context,
			eventrule.Type,
			uuid.UUID,
		) (*eventrule.Rule, error) {
			return nil, nil
		})
	}
	processor, err := New(Config{
		Inventory:  inventory,
		Rules:      rules,
		Executions: memorystore.New(),
		Executor: runtimeExecutor{
			targets: targetResolverFunc(func(
				context.Context,
				eventexecutor.TargetRequest,
			) ([]eventexecutor.Target, error) {
				return nil, nil
			}),
			execute: func(context.Context, eventexecutor.ExecutionRequest) (string, error) {
				return "", nil
			},
		},
	})
	require.NoError(t, err)
	return processor
}

func processorRuntimeRule(actions ...eventrule.Action) *eventrule.Rule {
	return &eventrule.Rule{
		ID:        uuid.New(),
		EventType: "test.event",
		Policy:    eventrule.Policy{Actions: actions},
	}
}

func runtimeEnvelope(rackID uuid.UUID) eventrule.Envelope {
	return eventrule.Envelope{
		ID:       uuid.New(),
		Type:     "test.event",
		Resource: eventrule.Resource{Kind: eventrule.ResourceKindRack, ID: rackID},
	}
}

func noopAction(id string) eventrule.Action {
	return eventrule.NewAction(id, eventrule.ActionCondition{}, eventrule.Noop{})
}

func submitAction(id string) eventrule.Action {
	return eventrule.NewAction(id, eventrule.ActionCondition{}, eventrule.SubmitTask{})
}

type targetResolverFunc func(
	context.Context,
	eventexecutor.TargetRequest,
) ([]eventexecutor.Target, error)

func (f targetResolverFunc) ResolveTargets(
	ctx context.Context,
	request eventexecutor.TargetRequest,
) ([]eventexecutor.Target, error) {
	return f(ctx, request)
}

type actionExecutorFunc func(context.Context, eventexecutor.ExecutionRequest) (string, error)

type runtimeExecutor struct {
	targets eventexecutor.TargetResolver
	execute actionExecutorFunc
	now     *time.Time
}

func (e runtimeExecutor) Prepare(
	ctx context.Context,
	request eventexecutor.PrepareRequest,
) (eventexecutor.PreparationResult, error) {
	var targets []eventexecutor.Target
	if request.Action.Spec.Type() == eventrule.ActionTypeSubmitTask {
		task := request.Action.Spec.(eventrule.SubmitTask)
		var err error
		targets, err = e.targets.ResolveTargets(ctx, eventexecutor.TargetRequest{
			EventType: request.Envelope.Type,
			Payload:   request.Envelope.Payload,
			Resource:  request.Resource,
			Task:      task,
		})
		if err != nil {
			outcome := e.failureOutcome(request.Execution, err)
			return eventexecutor.PreparationResult{Outcome: &outcome}, nil
		}
		if len(targets) == 0 {
			outcome := eventrule.ExecutionState{
				Status: eventrule.ExecutionStatusSkipped,
				Reason: eventrule.ExecutionReasonNoTargets,
			}
			return eventexecutor.PreparationResult{Outcome: &outcome}, nil
		}
	}

	return eventexecutor.PreparationResult{Request: &eventexecutor.ExecutionRequest{
		Execution: request.Execution,
		Action:    request.Action,
		Targets:   targets,
	}}, nil
}

func (e runtimeExecutor) Execute(
	ctx context.Context,
	request eventexecutor.ExecutionRequest,
) (eventrule.ExecutionState, error) {
	_, err := e.execute(ctx, request)
	if err != nil {
		return e.failureOutcome(request.Execution, err), nil
	}

	status := eventrule.ExecutionStatusCompleted
	if request.Action.Spec.Type() == eventrule.ActionTypeSubmitTask {
		status = eventrule.ExecutionStatusSubmitted
	}
	return eventrule.ExecutionState{Status: status}, nil
}

func (e runtimeExecutor) failureOutcome(
	execution eventrule.Execution,
	cause error,
) eventrule.ExecutionState {
	if errors.Is(cause, ErrTerminal) ||
		execution.Attempts >= runtimeMaxExecutionAttempts {
		return eventrule.ExecutionState{
			Status:        eventrule.ExecutionStatusFailed,
			StatusMessage: cause.Error(),
		}
	}

	now := time.Now()
	if e.now != nil {
		now = *e.now
	}
	return eventrule.ExecutionState{
		Status:        eventrule.ExecutionStatusDeferred,
		Reason:        eventrule.ExecutionReasonAttemptFailed,
		StatusMessage: cause.Error(),
		NextAttemptAt: now.Add(runtimeRetryDelay(execution.Attempts)),
	}
}

func runtimeRetryDelay(attempt int) time.Duration {
	return runtimeInitialRetryDelay * time.Duration(1<<max(attempt-1, 0))
}

func validProcessorConfig() Config {
	return Config{
		Inventory: &processorInventory{},
		Rules: ruleResolverFunc(func(
			context.Context,
			eventrule.Type,
			uuid.UUID,
		) (*eventrule.Rule, error) {
			return nil, nil
		}),
		Executions: memorystore.New(),
		Executor: runtimeExecutor{
			targets: targetResolverFunc(func(
				context.Context,
				eventexecutor.TargetRequest,
			) ([]eventexecutor.Target, error) {
				return nil, nil
			}),
			execute: func(context.Context, eventexecutor.ExecutionRequest) (string, error) {
				return "", nil
			},
		},
	}
}
