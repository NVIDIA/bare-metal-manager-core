// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package manager unifies immutable built-in and persisted event rules.
package manager

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
)

// Manager routes reads and mutations to stores with the appropriate capability.
type Manager struct {
	builtIns  eventrule.BuiltInRuleReader
	persisted eventrule.RuleStore
	bindings  eventrule.BindingStore
}

// New constructs an event-rule manager.
func New(
	builtIns eventrule.BuiltInRuleReader,
	persisted eventrule.RuleStore,
	bindings eventrule.BindingStore,
) (*Manager, error) {
	if builtIns == nil {
		return nil, fmt.Errorf("built-in event rule store is required")
	}

	if persisted == nil {
		return nil, fmt.Errorf("persisted event rule store is required")
	}

	if bindings == nil {
		return nil, fmt.Errorf("event rule binding store is required")
	}

	return &Manager{
		builtIns:  builtIns,
		persisted: persisted,
		bindings:  bindings,
	}, nil
}

// GetByID looks in persisted rules and then built-ins.
func (m *Manager) GetByID(ctx context.Context, id uuid.UUID) (*eventrule.Rule, error) {
	if err := validateRuleID(id); err != nil {
		return nil, err
	}

	rule, err := m.persisted.GetByID(ctx, id)
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
	persisted, err := m.persisted.List(ctx, filter)
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

	if err := m.rejectBuiltInID(ctx, rule.ID); err != nil {
		return nil, err
	}

	return m.persisted.Create(ctx, &rule)
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

	return m.persisted.UpdateMetadata(ctx, id, metadata)
}

// SetDedupe replaces or clears a persisted rule's deduplication policy.
func (m *Manager) SetDedupe(
	ctx context.Context,
	id uuid.UUID,
	dedupe *eventrule.Dedupe,
) error {
	if err := validateRuleID(id); err != nil {
		return err
	}

	if dedupe != nil {
		if err := dedupe.Validate(); err != nil {
			return fmt.Errorf("dedupe: %w", err)
		}
	}

	if err := m.rejectBuiltInID(ctx, id); err != nil {
		return err
	}

	if dedupe == nil {
		return m.persisted.SetDedupe(ctx, id, nil)
	}

	cloned := *dedupe
	return m.persisted.SetDedupe(ctx, id, &cloned)
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

	if err := eventrule.ValidateActions(actions); err != nil {
		return err
	}

	if err := m.rejectBuiltInID(ctx, id); err != nil {
		return err
	}

	return m.persisted.ReplaceActions(ctx, id, eventrule.CloneActions(actions))
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

	return m.persisted.Delete(ctx, id)
}

// SetEnabled changes whether a persisted rule is enabled.
func (m *Manager) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	if err := validateRuleID(id); err != nil {
		return err
	}

	if err := m.rejectBuiltInID(ctx, id); err != nil {
		return err
	}

	return m.persisted.SetEnabled(ctx, id, enabled)
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

	rule, err := m.persisted.GetByID(ctx, ruleID)
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

	if err := m.bindings.Bind(ctx, binding); err != nil {
		return nil, err
	}

	return &binding, nil
}

// Unbind removes a persisted rule binding.
func (m *Manager) Unbind(ctx context.Context, bindingID uuid.UUID) error {
	if bindingID == uuid.Nil {
		return fmt.Errorf("event rule binding id is required")
	}

	return m.bindings.Unbind(ctx, bindingID)
}

// GetEffective resolves rack, site, then built-in precedence. It returns
// (nil, nil) when no effective rule exists.
func (m *Manager) GetEffective(
	ctx context.Context,
	eventType eventrule.Type,
	rackID uuid.UUID,
) (*eventrule.Rule, error) {
	// Prefer an enabled persisted rule bound to the event's rack.
	if rackID != uuid.Nil {
		scope := eventrule.Scope{
			Type: eventrule.ScopeTypeRack,
			ID:   rackID,
		}

		rule, err := m.getForScope(ctx, eventType, scope)
		if err != nil {
			return nil, err
		}

		if rule != nil {
			return rule, nil
		}
	}

	// Fall back to an enabled persisted rule bound to the site.
	scope := eventrule.Scope{
		Type: eventrule.ScopeTypeSite,
		ID:   uuid.Nil,
	}

	rule, err := m.getForScope(ctx, eventType, scope)
	if err != nil {
		return nil, err
	}

	if rule != nil {
		return rule, nil
	}

	// Use the immutable built-in when no persisted scope supplies a rule.
	rule, err = m.builtIns.GetByEventType(ctx, eventType)
	if errors.Is(err, eventrule.ErrRuleNotFound) {
		return nil, nil
	}

	return rule, err
}

func (m *Manager) getForScope(
	ctx context.Context,
	eventType eventrule.Type,
	scope eventrule.Scope,
) (*eventrule.Rule, error) {
	binding, err := m.bindings.GetForScope(ctx, eventType, scope)
	if err != nil || binding == nil {
		return nil, err
	}

	rule, err := m.persisted.GetByID(ctx, binding.RuleID)
	if err != nil {
		return nil, err
	}

	if !rule.Enabled {
		return nil, nil
	}

	return rule, nil
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

func validateRuleID(id uuid.UUID) error {
	if id == uuid.Nil {
		return fmt.Errorf("event rule id is required")
	}

	return nil
}
