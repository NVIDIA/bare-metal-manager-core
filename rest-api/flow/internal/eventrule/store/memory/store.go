// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package memory implements event-rule stores using versioned persistence
// models held in memory.
package memory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	converterdao "github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/dao"
	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
)

// Store implements rule and binding persistence over in-memory model records.
type Store struct {
	mu       sync.RWMutex
	rules    map[uuid.UUID]dbmodel.EventRule
	bindings map[uuid.UUID]dbmodel.EventRuleBinding
	now      func() time.Time
}

// New constructs an empty in-memory store.
func New() *Store {
	return &Store{
		rules:    make(map[uuid.UUID]dbmodel.EventRule),
		bindings: make(map[uuid.UUID]dbmodel.EventRuleBinding),
		now:      time.Now,
	}
}

// GetByID returns one persisted rule.
func (s *Store) GetByID(_ context.Context, id uuid.UUID) (*eventrule.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	persisted, ok := s.rules[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", eventrule.ErrRuleNotFound, id)
	}
	return converterdao.EventRuleFrom(&persisted)
}

// List returns persisted rules matching the filter.
func (s *Store) List(
	_ context.Context,
	filter eventrule.RuleFilter,
) ([]*eventrule.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rules := make([]*eventrule.Rule, 0, len(s.rules))
	for _, persisted := range s.rules {
		rule, err := converterdao.EventRuleFrom(&persisted)
		if err != nil {
			return nil, err
		}
		if filter.Matches(rule) {
			rules = append(rules, rule)
		}
	}
	slices.SortFunc(rules, func(a, b *eventrule.Rule) int {
		return cmp.Compare(a.ID.String(), b.ID.String())
	})
	return rules, nil
}

// Create stores a new persisted rule.
func (s *Store) Create(
	_ context.Context,
	rule *eventrule.Rule,
) (*eventrule.Rule, error) {
	if rule == nil {
		return nil, errors.New("event rule is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.rules[rule.ID]; ok {
		return nil, fmt.Errorf("event rule %s already exists", rule.ID)
	}
	canonical := rule.Clone()
	now := s.now().UTC()
	canonical.CreatedAt = now
	canonical.UpdatedAt = now
	persisted, err := converterdao.EventRuleTo(&canonical)
	if err != nil {
		return nil, err
	}
	s.rules[canonical.ID] = *persisted
	return &canonical, nil
}

// UpdateMetadata updates one persisted rule's metadata.
func (s *Store) UpdateMetadata(
	_ context.Context,
	id uuid.UUID,
	metadata eventrule.RuleMetadata,
) error {
	return s.updateRule(id, func(rule *eventrule.Rule) {
		rule.Name = metadata.Name
		rule.Description = metadata.Description
	})
}

// SetDedupe replaces or clears one persisted rule's deduplication policy.
func (s *Store) SetDedupe(
	_ context.Context,
	id uuid.UUID,
	dedupe *eventrule.Dedupe,
) error {
	return s.updateRule(id, func(rule *eventrule.Rule) {
		if dedupe == nil {
			rule.Dedupe = nil
			return
		}
		cloned := *dedupe
		rule.Dedupe = &cloned
	})
}

// ReplaceActions replaces all actions belonging to one persisted rule.
func (s *Store) ReplaceActions(
	_ context.Context,
	id uuid.UUID,
	actions []eventrule.Action,
) error {
	return s.updateRule(id, func(rule *eventrule.Rule) {
		rule.Actions = eventrule.CloneActions(actions)
	})
}

// Delete atomically deletes a persisted rule and all of its bindings.
func (s *Store) Delete(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.rules[id]; !ok {
		return fmt.Errorf("%w: %s", eventrule.ErrRuleNotFound, id)
	}
	bindingIDs := make([]uuid.UUID, 0)
	for bindingID, persisted := range s.bindings {
		if persisted.RuleID == id {
			bindingIDs = append(bindingIDs, bindingID)
		}
	}
	delete(s.rules, id)
	for _, bindingID := range bindingIDs {
		delete(s.bindings, bindingID)
	}
	return nil
}

// SetEnabled changes one persisted rule's enabled state.
func (s *Store) SetEnabled(_ context.Context, id uuid.UUID, enabled bool) error {
	return s.updateRule(id, func(rule *eventrule.Rule) {
		rule.Enabled = enabled
	})
}

// Bind stores a rule-to-scope association.
func (s *Store) Bind(_ context.Context, binding eventrule.Binding) error {
	if err := binding.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.bindings[binding.ID]; ok {
		return fmt.Errorf("event rule binding %s already exists", binding.ID)
	}

	ruleRecord, ok := s.rules[binding.RuleID]
	if !ok {
		return fmt.Errorf("%w: %s", eventrule.ErrRuleNotFound, binding.RuleID)
	}

	if string(binding.EventType) != ruleRecord.EventType {
		return fmt.Errorf(
			"event rule binding event type %q does not match rule event type %q",
			binding.EventType,
			ruleRecord.EventType,
		)
	}

	for _, persisted := range s.bindings {
		if persisted.RuleID == binding.RuleID &&
			persisted.ScopeType != string(binding.Scope.Type) {
			return fmt.Errorf("event rule %s cannot mix site and rack bindings", binding.RuleID)
		}

		if bindingRecordMatchesScope(persisted, binding.EventType, binding.Scope) {
			return fmt.Errorf(
				"event type %q already has a binding for scope %q",
				binding.EventType,
				binding.Scope.Type,
			)
		}
	}

	now := s.now().UTC()
	persisted, err := converterdao.EventRuleBindingTo(binding, now, now)
	if err != nil {
		return err
	}
	s.bindings[binding.ID] = *persisted
	return nil
}

// Unbind deletes one binding.
func (s *Store) Unbind(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.bindings[id]; !ok {
		return fmt.Errorf("%w: binding %s", eventrule.ErrRuleNotFound, id)
	}
	delete(s.bindings, id)
	return nil
}

// GetForScope returns the binding for an event type and scope.
func (s *Store) GetForScope(
	_ context.Context,
	eventType eventrule.Type,
	scope eventrule.Scope,
) (*eventrule.Binding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, persisted := range s.bindings {
		if bindingRecordMatchesScope(persisted, eventType, scope) {
			return converterdao.EventRuleBindingFrom(&persisted)
		}
	}
	return nil, nil
}

func bindingRecordMatchesScope(
	binding dbmodel.EventRuleBinding,
	eventType eventrule.Type,
	scope eventrule.Scope,
) bool {
	if binding.EventType != string(eventType) ||
		binding.ScopeType != string(scope.Type) {
		return false
	}

	switch scope.Type {
	case eventrule.ScopeTypeSite:
		return binding.ScopeID == nil
	case eventrule.ScopeTypeRack:
		return binding.ScopeID != nil && *binding.ScopeID == scope.ID
	default:
		return false
	}
}

func (s *Store) updateRule(id uuid.UUID, mutate func(*eventrule.Rule)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	persisted, ok := s.rules[id]
	if !ok {
		return fmt.Errorf("%w: %s", eventrule.ErrRuleNotFound, id)
	}
	rule, err := converterdao.EventRuleFrom(&persisted)
	if err != nil {
		return err
	}
	mutate(rule)
	rule.UpdatedAt = s.now().UTC()
	if err := rule.Validate(); err != nil {
		return err
	}
	updated, err := converterdao.EventRuleTo(rule)
	if err != nil {
		return err
	}
	s.rules[id] = *updated
	return nil
}

var (
	_ eventrule.RuleStore    = (*Store)(nil)
	_ eventrule.BindingStore = (*Store)(nil)
)
