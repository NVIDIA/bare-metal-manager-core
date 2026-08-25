// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	eventexecutor "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	memorystore "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/store/memory"
	eventtarget "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/target"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/deviceinfo"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/location"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/inventoryobjects/component"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/inventoryobjects/rack"
)

func TestProcessorProcessPersistsEventBeforeDispatch(t *testing.T) {
	rackID := uuid.New()
	store := memorystore.New()
	rule := processorRuntimeRule(
		noopAction("always"),
		conditionalNoopAction("critical", eventrule.SeverityCritical),
	)
	var received []eventrule.Execution
	processor := runtimeProcessor(
		t,
		processorInventoryWithRack(rackID),
		rule,
		store,
		defaultTargetResolver(rackID),
		executorFunc(func(_ context.Context, request eventexecutor.ExecutionRequest) error {
			received = append(received, request.Execution.Clone())
			events, err := store.Events()
			require.NoError(t, err)
			require.NotNil(t, events[0].PlannedAt)
			return nil
		}),
	)

	envelope := runtimeEnvelope(rackID)
	envelope.Severity = eventrule.SeverityInfo
	envelope.Payload = []byte(`{"secret":"must-not-be-persisted"}`)
	require.NoError(t, processor.Process(context.Background(), envelope))

	events, err := store.Events()
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, envelope.Key, events[0].Key)
	require.Equal(t, eventrule.ResourceIdentity{Kind: eventrule.ResourceKindRack, ID: rackID}, events[0].Resource)
	require.Equal(t, rule.ID, events[0].AppliedRuleID)
	require.Len(t, events[0].EffectivePolicy.Actions, 1)
	require.NotNil(t, events[0].PlannedAt)
	require.NotContains(t, events[0].Summary, string(envelope.Payload))

	executions, err := store.Executions()
	require.NoError(t, err)
	require.Len(t, executions, 1)
	require.Equal(t, "always", executions[0].ActionName)
	require.IsType(t, &eventrule.NoopPlan{}, executions[0].Plan)
	require.Equal(t, eventrule.ExecutionStatusCompleted, executions[0].Status)
	require.Len(t, received, 1)
}

func TestProcessorProcessDeduplicatesAtEventBoundary(t *testing.T) {
	t.Run("planned duplicate records observation and stops", func(t *testing.T) {
		rackID := uuid.New()
		store := memorystore.New()
		ruleCalls := 0
		executorCalls := 0
		rules := ruleResolverFunc(func(context.Context, eventrule.Type, uuid.UUID) (*eventrule.Rule, error) {
			ruleCalls++
			return processorRuntimeRule(noopAction("once")), nil
		})
		processor := runtimeProcessorWithRules(
			t,
			processorInventoryWithRack(rackID),
			rules,
			store,
			defaultTargetResolver(rackID),
			executorFunc(func(context.Context, eventexecutor.ExecutionRequest) error {
				executorCalls++
				return nil
			}),
		)
		envelope := runtimeEnvelope(rackID)
		require.NoError(t, processor.Process(context.Background(), envelope))
		require.NoError(t, processor.Process(context.Background(), envelope))

		require.Equal(t, 1, ruleCalls)
		require.Equal(t, 1, executorCalls)
		events, err := store.Events()
		require.NoError(t, err)
		require.Equal(t, 2, events[0].Observations)
	})

	t.Run("duplicate does not take over active creator planning", func(t *testing.T) {
		rackID := uuid.New()
		store := memorystore.New()
		enteredPlanning := make(chan struct{})
		releasePlanning := make(chan struct{})
		executions := &blockingExecutionStore{
			ExecutionStore: store,
			entered:        enteredPlanning,
			release:        releasePlanning,
		}
		executorCalls := 0
		processor, err := New(Config{
			Inventory: processorInventoryWithRack(rackID),
			Rules: ruleResolverFunc(func(context.Context, eventrule.Type, uuid.UUID) (*eventrule.Rule, error) {
				return processorRuntimeRule(noopAction("once")), nil
			}),
			Events:     store,
			Executions: executions,
			Targets:    targetRegistry(t, defaultTargetResolver(rackID)),
			Executors: executorRegistry(t, executorFunc(func(context.Context, eventexecutor.ExecutionRequest) error {
				executorCalls++
				return nil
			})),
		})
		require.NoError(t, err)

		envelope := runtimeEnvelope(rackID)
		creatorResult := make(chan error, 1)
		go func() {
			creatorResult <- processor.Process(context.Background(), envelope)
		}()

		select {
		case <-enteredPlanning:
		case <-time.After(5 * time.Second):
			close(releasePlanning)
			t.Fatal("creator did not reach execution planning")
		}

		duplicateErr := processor.Process(context.Background(), envelope)
		eventsBeforeRelease, eventsErr := store.Events()
		executionsBeforeRelease, executionsErr := store.Executions()
		executorCallsBeforeRelease := executorCalls
		close(releasePlanning)

		var creatorErr error
		select {
		case creatorErr = <-creatorResult:
		case <-time.After(5 * time.Second):
			t.Fatal("creator did not finish execution planning")
		}

		require.NoError(t, duplicateErr)
		require.NoError(t, creatorErr)
		require.NoError(t, eventsErr)
		require.Len(t, eventsBeforeRelease, 1)
		require.Nil(t, eventsBeforeRelease[0].PlannedAt)
		require.Equal(t, 2, eventsBeforeRelease[0].Observations)
		require.NoError(t, executionsErr)
		require.Empty(t, executionsBeforeRelease)
		require.Zero(t, executorCallsBeforeRelease)

		storedExecutions, err := store.Executions()
		require.NoError(t, err)
		require.Len(t, storedExecutions, 1)
		require.Equal(t, 1, executorCalls)
	})

	t.Run("concurrent event creation loser stops", func(t *testing.T) {
		rackID := uuid.New()
		store := memorystore.New()
		events := &concurrentWinnerEventStore{EventStore: store}
		executorCalls := 0
		processor, err := New(Config{
			Inventory: processorInventoryWithRack(rackID),
			Rules: ruleResolverFunc(func(context.Context, eventrule.Type, uuid.UUID) (*eventrule.Rule, error) {
				return processorRuntimeRule(noopAction("once")), nil
			}),
			Events:     events,
			Executions: store,
			Targets:    targetRegistry(t, defaultTargetResolver(rackID)),
			Executors: executorRegistry(t, executorFunc(func(context.Context, eventexecutor.ExecutionRequest) error {
				executorCalls++
				return nil
			})),
		})
		require.NoError(t, err)

		require.NoError(t, processor.Process(context.Background(), runtimeEnvelope(rackID)))

		storedEvents, err := store.Events()
		require.NoError(t, err)
		require.Len(t, storedEvents, 1)
		require.Equal(t, 2, storedEvents[0].Observations)
		require.Nil(t, storedEvents[0].PlannedAt)
		storedExecutions, err := store.Executions()
		require.NoError(t, err)
		require.Empty(t, storedExecutions)
		require.Zero(t, executorCalls)
	})
}

func TestProcessorProcessPersistsEmptyEffectivePolicy(t *testing.T) {
	rackID := uuid.New()
	store := memorystore.New()
	processor := runtimeProcessor(
		t,
		processorInventoryWithRack(rackID),
		processorRuntimeRule(conditionalNoopAction("critical", eventrule.SeverityCritical)),
		store,
		defaultTargetResolver(rackID),
		executorFunc(func(context.Context, eventexecutor.ExecutionRequest) error {
			t.Fatal("empty effective policy must not dispatch")
			return nil
		}),
	)
	envelope := runtimeEnvelope(rackID)
	envelope.Severity = eventrule.SeverityInfo
	require.NoError(t, processor.Process(context.Background(), envelope))

	events, err := store.Events()
	require.NoError(t, err)
	require.Empty(t, events[0].EffectivePolicy.Actions)
	require.NotNil(t, events[0].PlannedAt)
	executions, err := store.Executions()
	require.NoError(t, err)
	require.Empty(t, executions)
}

func TestProcessorPlansConcreteSubmitTaskTargets(t *testing.T) {
	rackID := uuid.New()
	computeID := uuid.New()
	nvSwitchID := uuid.New()
	resolvedRack := rack.New(deviceinfo.DeviceInfo{ID: rackID}, location.Location{})
	resolvedRack.Components = []component.Component{
		component.New(devicetypes.ComponentTypeNVSwitch, &deviceinfo.DeviceInfo{ID: nvSwitchID}, "", nil),
		component.New(devicetypes.ComponentTypeCompute, &deviceinfo.DeviceInfo{ID: computeID}, "", nil),
	}
	store := memorystore.New()
	processor := runtimeProcessor(
		t,
		&processorInventory{rack: resolvedRack},
		processorRuntimeRule(submitAction("power_off")),
		store,
		defaultTargetResolver(rackID),
		executorFunc(func(context.Context, eventexecutor.ExecutionRequest) error { return nil }),
	)
	require.NoError(t, processor.Process(context.Background(), runtimeEnvelope(rackID)))

	executions, err := store.Executions()
	require.NoError(t, err)
	plan := executions[0].Plan.(*eventrule.SubmitTaskPlan)
	require.Equal(t, operations.PowerOperationForcePowerOff.CodeString(), plan.Operation.Code)
	require.Equal(t, "ForcePowerOff, forced false", plan.Description)
	require.Len(t, plan.Targets, 1)
	require.Equal(t, rackID, plan.Targets[0].RackID)
	require.Equal(t, []uuid.UUID{computeID}, plan.Targets[0].ComponentsByType[devicetypes.ComponentTypeCompute])
	require.Equal(t, []uuid.UUID{nvSwitchID}, plan.Targets[0].ComponentsByType[devicetypes.ComponentTypeNVSwitch])
}

func TestProcessorPersistsNoTargetExecutionAsSkipped(t *testing.T) {
	rackID := uuid.New()
	store := memorystore.New()
	processor := runtimeProcessor(
		t,
		processorInventoryWithRack(rackID),
		processorRuntimeRule(submitAction("power_off")),
		store,
		&testTargetResolver{},
		executorFunc(func(context.Context, eventexecutor.ExecutionRequest) error {
			t.Fatal("no-target execution must not reach executor")
			return nil
		}),
	)
	require.NoError(t, processor.Process(context.Background(), runtimeEnvelope(rackID)))
	executions, err := store.Executions()
	require.NoError(t, err)
	require.Equal(t, eventrule.ExecutionStatusSkipped, executions[0].Status)
	require.Equal(t, eventrule.ExecutionReasonNoTargets, executions[0].Reason)
}

func runtimeProcessor(
	t *testing.T,
	inventory *processorInventory,
	rule *eventrule.Rule,
	store *memorystore.Store,
	targets eventtarget.Resolver,
	execute eventexecutor.Executor,
) *Processor {
	t.Helper()
	return runtimeProcessorWithRules(t, inventory, ruleResolverFunc(func(
		context.Context,
		eventrule.Type,
		uuid.UUID,
	) (*eventrule.Rule, error) {
		return rule, nil
	}), store, targets, execute)
}

func runtimeProcessorWithRules(
	t *testing.T,
	inventory *processorInventory,
	rules RuleResolver,
	store *memorystore.Store,
	targets eventtarget.Resolver,
	execute eventexecutor.Executor,
) *Processor {
	t.Helper()
	processor, err := New(Config{
		Inventory:  inventory,
		Rules:      rules,
		Events:     store,
		Executions: store,
		Targets:    targetRegistry(t, targets),
		Executors:  executorRegistry(t, execute),
	})
	require.NoError(t, err)
	return processor
}

func newTestProcessor(t *testing.T, inventory *processorInventory, rules RuleResolver) *Processor {
	t.Helper()
	if rules == nil {
		rules = ruleResolverFunc(func(context.Context, eventrule.Type, uuid.UUID) (*eventrule.Rule, error) {
			return nil, nil
		})
	}
	store := memorystore.New()
	return runtimeProcessorWithRules(
		t,
		inventory,
		rules,
		store,
		defaultTargetResolver(uuid.New()),
		executorFunc(func(context.Context, eventexecutor.ExecutionRequest) error { return nil }),
	)
}

func processorRuntimeRule(actions ...eventrule.Action) *eventrule.Rule {
	return &eventrule.Rule{ID: uuid.New(), EventType: "test.event", Policy: eventrule.Policy{Actions: actions}}
}

func runtimeEnvelope(rackID uuid.UUID) eventrule.Envelope {
	return eventrule.Envelope{
		Key:      eventrule.EventKey{SourceName: "test", SourceKey: uuid.NewString()},
		Type:     "test.event",
		Resource: eventrule.Resource{Kind: eventrule.ResourceKindRack, ID: rackID},
	}
}

func noopAction(name string) eventrule.Action {
	return eventrule.Action{Name: name, Spec: &eventrule.Noop{}}
}

func conditionalNoopAction(name string, severity eventrule.Severity) eventrule.Action {
	return eventrule.Action{
		Name:      name,
		Condition: eventrule.ActionCondition{Severities: []eventrule.Severity{severity}},
		Spec:      &eventrule.Noop{},
	}
}

func submitAction(name string) eventrule.Action {
	return eventrule.Action{Name: name, Spec: &eventrule.SubmitTask{
		Operation:        &operations.PowerControlTaskInfo{Operation: operations.PowerOperationForcePowerOff},
		TargetStrategy:   eventrule.TargetStrategyRack,
		ConflictStrategy: eventrule.ConflictStrategyQueue,
	}}
}

func targetRegistry(t *testing.T, resolver eventtarget.Resolver) *eventtarget.Registry {
	t.Helper()
	registry := eventtarget.New()
	require.NoError(t, registry.Register("test.event", eventrule.TargetStrategyRack, resolver))
	return registry
}

func defaultTargetResolver(rackID uuid.UUID) eventtarget.Resolver {
	return &testTargetResolver{targets: []eventtarget.Target{{
		Kind:   eventrule.ResourceKindRack,
		ID:     rackID,
		RackID: rackID,
	}}}
}

type testTargetResolver struct {
	targets []eventtarget.Target
	err     error
}

func (r *testTargetResolver) Resolve(context.Context, eventtarget.ResolveRequest) ([]eventtarget.Target, error) {
	return r.targets, r.err
}

type executorFunc func(context.Context, eventexecutor.ExecutionRequest) error

func (f executorFunc) Execute(ctx context.Context, request eventexecutor.ExecutionRequest) error {
	return f(ctx, request)
}

type blockingExecutionStore struct {
	eventrule.ExecutionStore
	blocked atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (s *blockingExecutionStore) CommitEventPlan(
	ctx context.Context,
	eventID uuid.UUID,
	planned []eventrule.PlannedExecution,
) ([]eventrule.Execution, error) {
	if s.blocked.CompareAndSwap(false, true) {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.ExecutionStore.CommitEventPlan(ctx, eventID, planned)
}

type concurrentWinnerEventStore struct {
	eventrule.EventStore
}

func (*concurrentWinnerEventStore) ObserveEvent(
	context.Context,
	eventrule.EventKey,
) (*eventrule.Event, error) {
	return nil, nil
}

func (s *concurrentWinnerEventStore) CreateEvent(
	ctx context.Context,
	definition eventrule.Event,
) (*eventrule.Event, error) {
	winner, err := s.EventStore.CreateEvent(ctx, definition)
	if err != nil || winner == nil {
		return nil, err
	}
	return s.EventStore.CreateEvent(ctx, definition)
}

type executorLookup map[eventrule.ActionType]eventexecutor.Executor

func (r executorLookup) Executor(
	actionType eventrule.ActionType,
) (eventexecutor.Executor, error) {
	actionExecutor, ok := r[actionType]
	if !ok {
		return nil, fmt.Errorf("no executor registered for action type %q", actionType)
	}

	return actionExecutor, nil
}

func executorRegistry(t *testing.T, actionExecutor eventexecutor.Executor) ExecutorRegistry {
	t.Helper()
	registry := executorLookup{}
	for _, actionType := range []eventrule.ActionType{
		eventrule.ActionTypeSubmitTask,
		eventrule.ActionTypeSendAlert,
		eventrule.ActionTypeNoop,
	} {
		registry[actionType] = actionExecutor
	}
	return registry
}

func validProcessorConfig(t *testing.T) Config {
	t.Helper()
	store := memorystore.New()
	return Config{
		Inventory: &processorInventory{},
		Rules: ruleResolverFunc(func(context.Context, eventrule.Type, uuid.UUID) (*eventrule.Rule, error) {
			return nil, nil
		}),
		Events:     store,
		Executions: store,
		Targets:    targetRegistry(t, defaultTargetResolver(uuid.New())),
		Executors: executorRegistry(t, executorFunc(func(context.Context, eventexecutor.ExecutionRequest) error {
			return nil
		})),
	}
}

func processorInventoryWithRack(rackID uuid.UUID) *processorInventory {
	return &processorInventory{rack: rack.New(deviceinfo.DeviceInfo{ID: rackID}, location.Location{})}
}
