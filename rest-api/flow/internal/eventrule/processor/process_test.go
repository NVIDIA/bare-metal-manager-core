// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	eventexecutor "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	memorystore "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/store/memory"
	eventtarget "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/target"
	inventoryresolver "github.com/NVIDIA/infra-controller/rest-api/flow/internal/inventory/resolver"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/deviceinfo"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/location"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/inventoryobjects/rack"
	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestProcessor_Process(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	tests := map[string]struct {
		rule             *eventrule.Rule
		ruleErr          error
		invalidEnvelope  bool
		noTargets        bool
		targetErr        error
		executorErr      error
		cancelContext    bool
		invalidResult    bool
		dedupe           *eventrule.Dedupe
		wantErr          error
		wantStatus       eventrule.ExecutionStatus
		wantReason       eventrule.ExecutionReason
		wantMessage      string
		wantExecutions   int
		wantExecutorRuns int
	}{
		"no effective rule is accepted": {},
		"invalid envelope is terminal": {
			invalidEnvelope: true,
			wantErr:         ErrTerminal,
		},
		"invalid persisted rule is terminal": {
			ruleErr: fmt.Errorf("decode rule: %w", eventrule.ErrInvalidPersistedRule),
			wantErr: ErrTerminal,
		},
		"condition skip creates no execution": {
			rule: processorRuntimeRule(eventrule.NewAction(
				"skip",
				eventrule.ActionCondition{
					ComponentTypes: []flowtypes.ComponentType{flowtypes.ComponentTypeNVSwitch},
				},
				eventrule.Noop{},
			)),
		},
		"dedupe without correlation key fails before condition skip": {
			rule: processorRuntimeRule(eventrule.NewAction(
				"skip",
				eventrule.ActionCondition{
					ComponentTypes: []flowtypes.ComponentType{flowtypes.ComponentTypeNVSwitch},
				},
				eventrule.Noop{},
			)),
			dedupe:  &eventrule.Dedupe{Window: time.Minute},
			wantErr: ErrTerminal,
		},
		"noop completes on creator fast path": {
			rule:             processorRuntimeRule(noopAction("noop")),
			wantStatus:       eventrule.ExecutionStatusCompleted,
			wantExecutions:   1,
			wantExecutorRuns: 1,
		},
		"task submits on creator fast path": {
			rule:             processorRuntimeRule(submitAction("submit")),
			wantStatus:       eventrule.ExecutionStatusSubmitted,
			wantExecutions:   1,
			wantExecutorRuns: 1,
		},
		"no targets skips task": {
			rule:           processorRuntimeRule(submitAction("submit")),
			noTargets:      true,
			wantStatus:     eventrule.ExecutionStatusSkipped,
			wantReason:     eventrule.ExecutionReasonNoTargets,
			wantExecutions: 1,
		},
		"unresolvable target fails": {
			rule:           processorRuntimeRule(submitAction("submit")),
			targetErr:      fmt.Errorf("%w: invalid topology", eventtarget.ErrUnresolvable),
			wantStatus:     eventrule.ExecutionStatusFailed,
			wantMessage:    "event target cannot be resolved: invalid topology",
			wantExecutions: 1,
		},
		"unresolvable inventory target fails": {
			rule: processorRuntimeRule(submitAction("submit")),
			targetErr: fmt.Errorf(
				"rack lookup: %w",
				inventoryresolver.ErrUnresolvable,
			),
			wantStatus:     eventrule.ExecutionStatusFailed,
			wantMessage:    "rack lookup: inventory resource cannot be resolved",
			wantExecutions: 1,
		},
		"transient target failure defers to scheduler": {
			rule:           processorRuntimeRule(submitAction("submit")),
			targetErr:      errors.New("inventory unavailable"),
			wantStatus:     eventrule.ExecutionStatusDeferred,
			wantReason:     eventrule.ExecutionReasonAttemptFailed,
			wantMessage:    "inventory unavailable",
			wantExecutions: 1,
		},
		"executor contract failure is persisted": {
			rule:             processorRuntimeRule(noopAction("noop")),
			executorErr:      errors.New("invalid executor result"),
			wantStatus:       eventrule.ExecutionStatusFailed,
			wantMessage:      "executor execution failed: invalid executor result",
			wantExecutions:   1,
			wantExecutorRuns: 1,
		},
		"canceled executor attempt defers to scheduler": {
			rule: processorRuntimeRule(noopAction("noop")),
			executorErr: fmt.Errorf(
				"worker shutdown: %w",
				context.Canceled,
			),
			wantStatus:       eventrule.ExecutionStatusDeferred,
			wantReason:       eventrule.ExecutionReasonAttemptInterrupted,
			wantMessage:      "executor execution interrupted: worker shutdown: context canceled",
			wantExecutions:   1,
			wantExecutorRuns: 1,
		},
		"canceled processing context defers executor error": {
			rule:             processorRuntimeRule(noopAction("noop")),
			executorErr:      errors.New("executor stopped"),
			cancelContext:    true,
			wantStatus:       eventrule.ExecutionStatusDeferred,
			wantReason:       eventrule.ExecutionReasonAttemptInterrupted,
			wantMessage:      "executor execution interrupted: executor stopped",
			wantExecutions:   1,
			wantExecutorRuns: 1,
		},
		"expired executor attempt defers to scheduler": {
			rule:             processorRuntimeRule(noopAction("noop")),
			executorErr:      context.DeadlineExceeded,
			wantStatus:       eventrule.ExecutionStatusDeferred,
			wantReason:       eventrule.ExecutionReasonAttemptInterrupted,
			wantMessage:      "executor execution interrupted: context deadline exceeded",
			wantExecutions:   1,
			wantExecutorRuns: 1,
		},
		"invalid executor result is persisted": {
			rule:             processorRuntimeRule(noopAction("noop")),
			invalidResult:    true,
			wantStatus:       eventrule.ExecutionStatusFailed,
			wantMessage:      `invalid executor result: unknown execution status ""`,
			wantExecutions:   1,
			wantExecutorRuns: 1,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			store := memorystore.NewWithClock(func() time.Time { return now })
			rule := test.rule
			if rule != nil {
				cloned := rule.Clone()
				cloned.Dedupe = test.dedupe.Clone()
				rule = &cloned
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var executorRuns int
			targets := defaultTargetResolver(rackID)
			if test.noTargets || test.targetErr != nil {
				targets = targetResolverFunc(func(
					context.Context,
					eventtarget.ResolveRequest,
				) ([]eventtarget.Target, error) {
					return nil, test.targetErr
				})
			}
			execute := executorFunc(func(
				_ context.Context,
				request eventexecutor.ExecutionRequest,
			) (eventrule.ExecutionResult, error) {
				executorRuns++
				if test.cancelContext {
					cancel()
				}
				if test.executorErr != nil {
					return eventrule.ExecutionResult{}, test.executorErr
				}
				if test.invalidResult {
					return eventrule.ExecutionResult{}, nil
				}
				return successResult(request), nil
			})
			processor := runtimeProcessor(
				t,
				rackID,
				rule,
				test.ruleErr,
				store,
				targets,
				execute,
			)
			envelope := runtimeEnvelope(rackID)
			if test.invalidEnvelope {
				envelope.ID = uuid.Nil
			}

			err := processor.Process(ctx, envelope)
			if test.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.wantErr)
			}
			require.Equal(t, test.wantExecutorRuns, executorRuns)

			executions, err := store.Executions()
			require.NoError(t, err)
			require.Len(t, executions, test.wantExecutions)
			if test.wantExecutions == 1 {
				require.Equal(t, test.wantStatus, executions[0].Status)
				require.Equal(t, test.wantReason, executions[0].Reason)
				require.Equal(t, test.wantMessage, executions[0].StatusMessage)
				require.Equal(t, 1, executions[0].Attempts)
				require.Equal(t, now, executions[0].CreatedAt)
				if test.wantStatus == eventrule.ExecutionStatusDeferred {
					require.Equal(
						t,
						now.Add(initialRetryDelay),
						executions[0].NextAttemptAt,
					)
				}
			}
		})
	}

	t.Run("deduplication", testProcessDeduplication)
	t.Run("transient target redelivery does not dispatch", testProcessDeferredRedelivery)
	t.Run("processes actions independently", testProcessActionsIndependently)
	t.Run("concurrent duplicate dispatches once", testProcessConcurrentDuplicateDispatchesOnce)
}

func TestProcessor_persistExecution(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	store := memorystore.NewWithClock(func() time.Time { return now })
	created, err := store.CreateExecution(
		context.Background(),
		eventrule.ExecutionIdentity{
			EventID:  uuid.New(),
			RuleID:   uuid.New(),
			ActionID: "action",
		},
		nil,
	)
	require.NoError(t, err)

	attemptCtx, cancelAttempt := context.WithCancel(context.Background())
	cancelAttempt()
	require.ErrorIs(t, attemptCtx.Err(), context.Canceled)

	processor := Processor{
		executions: transitionContextStore{ExecutionStore: store},
	}
	require.NoError(t, processor.persistExecution(
		attemptCtx,
		created.ID,
		eventrule.CompletedExecutionResult(),
	))

	executions, err := store.Executions()
	require.NoError(t, err)
	require.Len(t, executions, 1)
	require.Equal(t, eventrule.ExecutionStatusCompleted, executions[0].Status)
}

func testProcessDeduplication(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	tests := map[string]struct {
		dedupe        *eventrule.Dedupe
		secondEventID uuid.UUID
	}{
		"delivery duplicate": {},
		"semantic duplicate across event IDs": {
			dedupe:        &eventrule.Dedupe{Window: time.Minute},
			secondEventID: uuid.New(),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			store := memorystore.NewWithClock(func() time.Time { return now })
			rule := processorRuntimeRule(noopAction("noop"))
			rule.Dedupe = test.dedupe
			var runs int
			processor := runtimeProcessor(
				t, rackID, rule, nil, store, defaultTargetResolver(rackID),
				executorFunc(func(
					_ context.Context,
					request eventexecutor.ExecutionRequest,
				) (eventrule.ExecutionResult, error) {
					runs++
					return successResult(request), nil
				}),
			)
			first := runtimeEnvelope(rackID)
			first.CorrelationKey = "incident-1"
			second := first
			if test.secondEventID != uuid.Nil {
				second.ID = test.secondEventID
			}

			require.NoError(t, processor.Process(context.Background(), first))
			now = now.Add(time.Second)
			require.NoError(t, processor.Process(context.Background(), second))
			require.Equal(t, 1, runs)

			executions, err := store.Executions()
			require.NoError(t, err)
			require.Len(t, executions, 1)
			require.Equal(t, 2, executions[0].Observations)
			require.Equal(t, eventrule.ExecutionStatusCompleted, executions[0].Status)
		})
	}
}

func testProcessDeferredRedelivery(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	store := memorystore.NewWithClock(func() time.Time { return now })
	var resolverRuns int
	processor := runtimeProcessor(
		t,
		rackID,
		processorRuntimeRule(submitAction("submit")),
		nil,
		store,
		targetResolverFunc(func(
			context.Context,
			eventtarget.ResolveRequest,
		) ([]eventtarget.Target, error) {
			resolverRuns++
			return nil, errors.New("inventory unavailable")
		}),
		executorFunc(func(
			context.Context,
			eventexecutor.ExecutionRequest,
		) (eventrule.ExecutionResult, error) {
			t.Fatal("executor must not run without targets")
			return eventrule.ExecutionResult{}, nil
		}),
	)
	envelope := runtimeEnvelope(rackID)

	require.NoError(t, processor.Process(context.Background(), envelope))
	now = now.Add(time.Minute)
	require.NoError(t, processor.Process(context.Background(), envelope))
	require.Equal(t, 1, resolverRuns)

	executions, err := store.Executions()
	require.NoError(t, err)
	require.Len(t, executions, 1)
	require.Equal(t, eventrule.ExecutionStatusDeferred, executions[0].Status)
	require.Equal(t, 2, executions[0].Observations)
}

func testProcessActionsIndependently(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	store := memorystore.NewWithClock(func() time.Time { return now })
	processor := runtimeProcessor(
		t,
		rackID,
		processorRuntimeRule(noopAction("first"), noopAction("second")),
		nil,
		store,
		defaultTargetResolver(rackID),
		executorFunc(func(
			_ context.Context,
			request eventexecutor.ExecutionRequest,
		) (eventrule.ExecutionResult, error) {
			if request.Action.ID == "first" {
				return eventrule.DeferredExecutionResult(
					eventrule.ExecutionReasonAttemptFailed,
					"downstream unavailable",
					0,
				), nil
			}
			return successResult(request), nil
		}),
	)

	require.NoError(t, processor.Process(context.Background(), runtimeEnvelope(rackID)))
	executions, err := store.Executions()
	require.NoError(t, err)
	require.Len(t, executions, 2)
	statuses := make(map[string]eventrule.ExecutionStatus, len(executions))
	for _, execution := range executions {
		statuses[execution.ActionID] = execution.Status
	}
	require.Equal(t, eventrule.ExecutionStatusDeferred, statuses["first"])
	require.Equal(t, eventrule.ExecutionStatusCompleted, statuses["second"])
}

func testProcessConcurrentDuplicateDispatchesOnce(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rackID := uuid.New()
	store := memorystore.NewWithClock(func() time.Time { return now })
	entered := make(chan struct{})
	release := make(chan struct{})
	var runs atomic.Int32
	processor := runtimeProcessor(
		t,
		rackID,
		processorRuntimeRule(noopAction("noop")),
		nil,
		store,
		defaultTargetResolver(rackID),
		executorFunc(func(
			_ context.Context,
			request eventexecutor.ExecutionRequest,
		) (eventrule.ExecutionResult, error) {
			if runs.Add(1) == 1 {
				close(entered)
			}
			<-release
			return successResult(request), nil
		}),
	)
	envelope := runtimeEnvelope(rackID)

	const deliveries = 20
	errs := make(chan error, deliveries)
	var wg sync.WaitGroup
	for range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- processor.Process(context.Background(), envelope)
		}()
	}
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
	require.Equal(t, eventrule.ExecutionStatusCompleted, executions[0].Status)
}

func runtimeProcessor(
	t *testing.T,
	rackID uuid.UUID,
	rule *eventrule.Rule,
	ruleErr error,
	store eventrule.ExecutionStore,
	targets eventtarget.Resolver,
	execute eventexecutor.Executor,
) *Processor {
	t.Helper()
	resolver := ruleResolverFunc(func(
		context.Context,
		eventrule.Type,
		uuid.UUID,
	) (*eventrule.Rule, error) {
		return rule, ruleErr
	})
	processor, err := New(Config{
		Inventory: &processorInventory{
			rack: rack.New(deviceinfo.DeviceInfo{ID: rackID}, location.Location{}),
		},
		Rules:      resolver,
		Executions: store,
		Targets:    targets,
		Executor:   execute,
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
		Targets:    defaultTargetResolver(uuid.New()),
		Executor: executorFunc(func(
			_ context.Context,
			request eventexecutor.ExecutionRequest,
		) (eventrule.ExecutionResult, error) {
			return successResult(request), nil
		}),
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
	return eventrule.NewAction(id, eventrule.ActionCondition{}, eventrule.SubmitTask{
		OperationType:    taskcommon.TaskTypePowerControl,
		OperationCode:    taskcommon.OpCodePowerControlForcePowerOff,
		TargetStrategy:   eventrule.TargetStrategyRack,
		ConflictStrategy: eventrule.ConflictStrategyQueue,
	})
}

func successResult(request eventexecutor.ExecutionRequest) eventrule.ExecutionResult {
	if request.Action.Spec.Type() == eventrule.ActionTypeSubmitTask {
		return eventrule.SubmittedExecutionResult()
	}
	return eventrule.CompletedExecutionResult()
}

type targetResolverFunc func(
	context.Context,
	eventtarget.ResolveRequest,
) ([]eventtarget.Target, error)

func (f targetResolverFunc) Resolve(
	ctx context.Context,
	request eventtarget.ResolveRequest,
) ([]eventtarget.Target, error) {
	return f(ctx, request)
}

func defaultTargetResolver(rackID uuid.UUID) eventtarget.Resolver {
	return targetResolverFunc(func(
		context.Context,
		eventtarget.ResolveRequest,
	) ([]eventtarget.Target, error) {
		return []eventtarget.Target{{Kind: eventrule.ResourceKindRack, ID: rackID}}, nil
	})
}

type executorFunc func(
	context.Context,
	eventexecutor.ExecutionRequest,
) (eventrule.ExecutionResult, error)

func (f executorFunc) Execute(
	ctx context.Context,
	request eventexecutor.ExecutionRequest,
) (eventrule.ExecutionResult, error) {
	return f(ctx, request)
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
		Targets:    defaultTargetResolver(uuid.New()),
		Executor: executorFunc(func(
			_ context.Context,
			request eventexecutor.ExecutionRequest,
		) (eventrule.ExecutionResult, error) {
			return successResult(request), nil
		}),
	}
}

type createFailingStore struct {
	errors map[string]error
}

type transitionContextStore struct {
	eventrule.ExecutionStore
}

func (s transitionContextStore) TransitionExecution(
	ctx context.Context,
	executionID uuid.UUID,
	result eventrule.ExecutionResult,
) (*eventrule.Execution, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("transition context: %w", err)
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("transition context requires a deadline")
	}
	return s.ExecutionStore.TransitionExecution(ctx, executionID, result)
}

func (s createFailingStore) CreateExecution(
	_ context.Context,
	identity eventrule.ExecutionIdentity,
	_ *eventrule.Dedupe,
) (*eventrule.Execution, error) {
	return nil, s.errors[identity.ActionID]
}

func (createFailingStore) TransitionExecution(
	context.Context,
	uuid.UUID,
	eventrule.ExecutionResult,
) (*eventrule.Execution, error) {
	return nil, errors.New("unexpected action execution transition")
}

func TestProcessor_ProcessJoinsActionCreationErrors(t *testing.T) {
	rackID := uuid.New()
	firstErr := errors.New("first create failed")
	secondErr := errors.New("second create failed")
	store := createFailingStore{errors: map[string]error{
		"first":  firstErr,
		"second": secondErr,
	}}
	processor := runtimeProcessor(
		t,
		rackID,
		processorRuntimeRule(noopAction("first"), noopAction("second")),
		nil,
		store,
		defaultTargetResolver(rackID),
		executorFunc(func(
			context.Context,
			eventexecutor.ExecutionRequest,
		) (eventrule.ExecutionResult, error) {
			t.Fatal("executor must not run when creation fails")
			return eventrule.ExecutionResult{}, nil
		}),
	)

	err := processor.Process(context.Background(), runtimeEnvelope(rackID))
	require.ErrorIs(t, err, firstErr)
	require.ErrorIs(t, err, secondErr)
}
