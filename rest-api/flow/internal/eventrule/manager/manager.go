// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package manager owns event-rule management and event processing.
package manager

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	eventexecutor "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/leakage"
	eventprocessor "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/processor"
	eventscheduler "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/scheduler"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/target"
	inventoryresolver "github.com/NVIDIA/infra-controller/rest-api/flow/internal/inventory/resolver"
	"github.com/google/uuid"
)

// Manager is the event-rule subsystem facade. It owns rule management and the
// internally assembled event-processing runtime.
type Manager struct {
	builtIns  *builtInRegistry
	store     eventRuleStore
	targets   *target.Registry
	executors *eventexecutor.Registry
	processor *eventprocessor.Processor
	scheduler *eventscheduler.Scheduler
}

// New constructs a fully assembled event-rule manager.
func New(config Config) (*Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	store, err := newStore(config.Store)
	if err != nil {
		return nil, err
	}

	executors, err := newExecutorRegistry(config, store)
	if err != nil {
		return nil, err
	}

	targets, err := newTargetRegistry(config)
	if err != nil {
		return nil, err
	}

	builtIns, err := newBuiltInRulesRegistry(executors, targets)
	if err != nil {
		return nil, err
	}

	executionScheduler, err := eventscheduler.New(eventscheduler.Config{
		InstanceID: config.Scheduler.InstanceID,
		Dependencies: eventscheduler.Dependencies{
			Store:     store,
			Executors: executors,
		},
		Runtime: config.Scheduler.Runtime,
		Policy:  config.Scheduler.Policy,
	})
	if err != nil {
		return nil, err
	}

	processor, err := newProcessor(
		config,
		store,
		builtIns,
		targets,
		executionScheduler,
	)
	if err != nil {
		return nil, err
	}

	return &Manager{
		builtIns:  builtIns,
		store:     store,
		targets:   targets,
		executors: executors,
		processor: processor,
		scheduler: executionScheduler,
	}, nil
}

func newTargetRegistry(config Config) (*target.Registry, error) {
	targets := target.New()

	err := leakage.RegisterTargetResolvers(
		targets,
		inventoryresolver.New(config.Inventory),
	)
	if err != nil {
		return nil, err
	}

	return targets, nil
}

func newBuiltInRulesRegistry(
	executors *eventexecutor.Registry,
	targets *target.Registry,
) (*builtInRegistry, error) {
	// Register the built-in rule for each supported event type here.
	rules := []*eventrule.Rule{
		leakage.DefaultRule(),
	}

	builtIns := &builtInRegistry{
		byID:        make(map[uuid.UUID]eventrule.Rule, len(rules)),
		byEventType: make(map[eventrule.Type]uuid.UUID, len(rules)),
	}

	for _, rule := range rules {
		if err := builtIns.addRule(rule); err != nil {
			return nil, err
		}
	}

	for _, rule := range rules {
		if err := executors.ValidateActions(rule.Actions); err != nil {
			return nil, fmt.Errorf("validate built-in event rule executors: %w", err)
		}

		if err := targets.ValidateRule(rule); err != nil {
			return nil, fmt.Errorf("validate built-in event rule targets: %w", err)
		}
	}

	return builtIns, nil
}

func newProcessor(
	config Config,
	store eventRuleStore,
	builtIns *builtInRegistry,
	targets *target.Registry,
	notifier eventprocessor.ExecutionNotifier,
) (*eventprocessor.Processor, error) {
	cfg := eventprocessor.Config{
		Inventory: config.Inventory,
		Rules:     &ruleResolver{builtIns: builtIns, store: store},
		Store:     store,
		Targets:   targets,
		Notifier:  notifier,
	}

	return eventprocessor.New(cfg)
}

func newExecutorRegistry(
	config Config,
	executionTasks eventrule.ExecutionTaskStore,
) (*eventexecutor.Registry, error) {
	cfg := eventexecutor.Config{
		TaskManager:    config.TaskManager,
		ExecutionTasks: executionTasks,
		AlertSender:    config.AlertSender,
	}

	return eventexecutor.New(cfg)
}

// Start launches the internally assembled execution scheduler in the
// background.
func (m *Manager) Start(ctx context.Context) error {
	return m.scheduler.Start(ctx)
}

// Stop stops the execution scheduler and waits for its workers to exit.
func (m *Manager) Stop() error {
	return m.scheduler.Stop()
}

// Process delegates one collected event to the internally assembled processor.
func (m *Manager) Process(ctx context.Context, envelope eventrule.Envelope) error {
	return m.processor.Process(ctx, envelope)
}

// GetByID looks in persisted rules and then built-ins.
func (m *Manager) GetByID(ctx context.Context, id uuid.UUID) (*eventrule.Rule, error) {
	if err := validateRuleID(id); err != nil {
		return nil, err
	}

	rule, err := m.store.GetByID(ctx, id)
	if err == nil {
		return rule, nil
	}

	if !errors.Is(err, eventrule.ErrRuleNotFound) {
		return nil, err
	}

	return m.builtIns.GetByID(ctx, id)
}

// List returns persisted and built-in rules through one read API.
func (m *Manager) List(ctx context.Context, filter eventrule.RuleFilter) ([]*eventrule.Rule, error) {
	persisted, err := m.store.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	builtIns, err := m.builtIns.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	return slices.Concat(persisted, builtIns), nil
}

// Create constructs and stores a disabled persisted rule. New rules remain
// disabled so callers can finish configuring and binding them before an
// explicit SetEnabled call makes them effective.
func (m *Manager) Create(
	ctx context.Context,
	input eventrule.RuleCreate,
) (*eventrule.Rule, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	rule := eventrule.Rule{
		ID:          uuid.New(),
		Origin:      eventrule.RuleOriginPersisted,
		Name:        input.Metadata.Name,
		Description: input.Metadata.Description,
		EventType:   input.EventType,
		Policy:      input.Policy.Clone(),
	}

	if err := m.validateRuntimeRule(&rule); err != nil {
		return nil, err
	}

	if err := m.rejectBuiltInID(ctx, rule.ID); err != nil {
		return nil, err
	}

	return m.store.Create(ctx, &rule)
}

// UpdateMetadata updates a persisted rule's descriptive fields.
func (m *Manager) UpdateMetadata(
	ctx context.Context,
	id uuid.UUID,
	metadata eventrule.RuleMetadata,
) error {
	if err := validateRuleID(id); err != nil {
		return err
	}

	if err := metadata.Validate(); err != nil {
		return err
	}

	if err := m.rejectBuiltInID(ctx, id); err != nil {
		return err
	}

	return m.store.UpdateMetadata(ctx, id, metadata)
}

// ReplaceActions replaces all actions belonging to a persisted rule.
func (m *Manager) ReplaceActions(
	ctx context.Context,
	id uuid.UUID,
	actions []eventrule.Action,
) error {
	if err := validateRuleID(id); err != nil {
		return err
	}

	if err := m.rejectBuiltInID(ctx, id); err != nil {
		return err
	}

	rule, err := m.store.GetByID(ctx, id)
	if err != nil {
		return err
	}

	candidate := rule.Clone()
	candidate.Actions = eventrule.CloneActions(actions)

	if err := m.validateRuntimeRule(&candidate); err != nil {
		return err
	}

	return m.store.ReplaceActions(ctx, id, candidate.Actions)
}

// Delete delegates deletion to the persisted store, which atomically deletes
// the rule and all of its bindings in one transaction.
func (m *Manager) Delete(ctx context.Context, id uuid.UUID) error {
	if err := validateRuleID(id); err != nil {
		return err
	}

	if err := m.rejectBuiltInID(ctx, id); err != nil {
		return err
	}

	return m.store.Delete(ctx, id)
}

// SetEnabled changes whether a persisted rule is enabled.
func (m *Manager) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	if err := validateRuleID(id); err != nil {
		return err
	}

	if err := m.rejectBuiltInID(ctx, id); err != nil {
		return err
	}

	if enabled {
		rule, err := m.store.GetByID(ctx, id)
		if err != nil {
			return err
		}

		if err := m.validateRuntimeRule(rule); err != nil {
			return err
		}
	}

	return m.store.SetEnabled(ctx, id, enabled)
}

// Bind associates a persisted rule with a scope and returns the new binding.
func (m *Manager) Bind(
	ctx context.Context,
	ruleID uuid.UUID,
	scope eventrule.Scope,
) (*eventrule.Binding, error) {
	if err := validateRuleID(ruleID); err != nil {
		return nil, err
	}

	if err := scope.Validate(); err != nil {
		return nil, err
	}

	if err := m.rejectBuiltInID(ctx, ruleID); err != nil {
		return nil, err
	}

	rule, err := m.store.GetByID(ctx, ruleID)
	if err != nil {
		return nil, err
	}

	binding := eventrule.Binding{
		ID:        uuid.New(),
		RuleID:    rule.ID,
		EventType: rule.EventType,
		Scope:     scope,
	}

	if err := binding.Validate(); err != nil {
		return nil, err
	}

	if err := m.store.Bind(ctx, binding); err != nil {
		return nil, err
	}

	return &binding, nil
}

// Unbind removes a persisted rule binding.
func (m *Manager) Unbind(ctx context.Context, bindingID uuid.UUID) error {
	if bindingID == uuid.Nil {
		return fmt.Errorf("event rule binding id is required")
	}

	return m.store.Unbind(ctx, bindingID)
}

func (m *Manager) rejectBuiltInID(ctx context.Context, id uuid.UUID) error {
	_, err := m.builtIns.GetByID(ctx, id)
	if err == nil {
		return fmt.Errorf("event rule %s is a built-in and cannot be mutated", id)
	}

	if !errors.Is(err, eventrule.ErrRuleNotFound) {
		return err
	}

	return nil
}

func (m *Manager) validateRuntimeRule(rule *eventrule.Rule) error {
	if err := m.executors.ValidateActions(rule.Actions); err != nil {
		return err
	}

	return m.targets.ValidateRule(rule)
}

func validateRuleID(id uuid.UUID) error {
	if id == uuid.Nil {
		return fmt.Errorf("event rule id is required")
	}

	return nil
}
