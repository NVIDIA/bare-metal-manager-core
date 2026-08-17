// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/registry"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerUnifiedReadsAndMutationRouting(t *testing.T) {
	builtIn := testRule(uuid.New(), eventrule.RuleOriginBuiltIn, "test.event")
	persisted := testRule(uuid.New(), eventrule.RuleOriginPersisted, "other.event")
	builtIns, err := registry.New(builtIn)
	require.NoError(t, err)
	store := newTestStore(persisted)
	bindings := newTestBindingStore()
	manager, err := New(builtIns, store, bindings)
	require.NoError(t, err)

	for _, id := range []uuid.UUID{persisted.ID, builtIn.ID} {
		rule, err := manager.GetByID(context.Background(), id)
		require.NoError(t, err)
		assert.Equal(t, id, rule.ID)
	}
	rules, err := manager.List(context.Background(), eventrule.RuleFilter{})
	require.NoError(t, err)
	assert.Len(t, rules, 2)

	input := eventrule.RuleCreate{
		Metadata:  eventrule.RuleMetadata{Name: "new rule"},
		EventType: "new.event",
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
		}},
	}
	created, err := manager.Create(context.Background(), input)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, created.ID)
	assert.Equal(t, eventrule.RuleOriginPersisted, created.Origin)
	assert.False(t, created.Enabled)
	assert.Equal(t, 1, store.creates)
	input.Policy.Actions[0].ID = "changed"
	assert.Equal(t, "noop", created.Actions[0].ID)

	_, err = manager.Create(context.Background(), eventrule.RuleCreate{})
	require.Error(t, err)
	assert.Equal(t, 1, store.creates)

	require.Error(t, manager.UpdateMetadata(
		context.Background(),
		persisted.ID,
		eventrule.RuleMetadata{},
	))
	assert.Equal(t, "test", persisted.Name)

	require.Error(t, manager.SetDedupe(
		context.Background(),
		persisted.ID,
		&eventrule.Dedupe{},
	))
	assert.Nil(t, persisted.Dedupe)

	require.Error(t, manager.ReplaceActions(context.Background(), persisted.ID, nil))
	assert.Len(t, persisted.Actions, 1)

	metadata := eventrule.RuleMetadata{Name: "updated", Description: "updated description"}
	require.NoError(t, manager.UpdateMetadata(context.Background(), persisted.ID, metadata))
	assert.Equal(t, metadata.Name, persisted.Name)
	assert.Equal(t, metadata.Description, persisted.Description)

	dedupe := &eventrule.Dedupe{Window: time.Minute}
	require.NoError(t, manager.SetDedupe(context.Background(), persisted.ID, dedupe))
	assert.Equal(t, dedupe, persisted.Dedupe)
	dedupe.Window = 2 * time.Minute
	assert.Equal(t, time.Minute, persisted.Dedupe.Window)

	actions := []eventrule.Action{
		eventrule.NewAction("replacement", eventrule.ActionCondition{}, eventrule.Noop{}),
	}
	require.NoError(t, manager.ReplaceActions(context.Background(), persisted.ID, actions))
	assert.Equal(t, actions, persisted.Actions)
	actions[0].ID = "changed"
	assert.Equal(t, "replacement", persisted.Actions[0].ID)

	require.NoError(t, manager.SetEnabled(context.Background(), persisted.ID, false))
	assert.False(t, persisted.Enabled)

	scope := eventrule.Scope{Type: eventrule.ScopeTypeRack, ID: uuid.New()}
	binding, err := manager.Bind(context.Background(), persisted.ID, scope)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, binding.ID)
	assert.Equal(t, persisted.ID, binding.RuleID)
	assert.Equal(t, persisted.EventType, binding.EventType)
	assert.Equal(t, scope, binding.Scope)
	require.Len(t, bindings.bound, 1)
	assert.Equal(t, persisted.EventType, bindings.bound[0].EventType)
}

func TestManagerEffectiveRulePrecedence(t *testing.T) {
	eventType := eventrule.Type("test.event")
	rackID := uuid.New()
	builtIn := testRule(uuid.New(), eventrule.RuleOriginBuiltIn, eventType)
	site := testRule(uuid.New(), eventrule.RuleOriginPersisted, eventType)
	rack := testRule(uuid.New(), eventrule.RuleOriginPersisted, eventType)
	builtIns, err := registry.New(builtIn)
	require.NoError(t, err)
	store := newTestStore()
	bindings := newTestBindingStore()
	manager, err := New(builtIns, store, bindings)
	require.NoError(t, err)

	rule, err := manager.GetEffective(context.Background(), eventType, rackID)
	require.NoError(t, err)
	assert.Equal(t, builtIn.ID, rule.ID)

	store.byID[site.ID] = site
	bindings.add(eventType, eventrule.Scope{Type: eventrule.ScopeTypeSite}, site.ID)
	rule, err = manager.GetEffective(context.Background(), eventType, rackID)
	require.NoError(t, err)
	assert.Equal(t, site.ID, rule.ID)

	site.Enabled = false
	rule, err = manager.GetEffective(context.Background(), eventType, rackID)
	require.NoError(t, err)
	assert.Equal(t, builtIn.ID, rule.ID)
	site.Enabled = true

	store.byID[rack.ID] = rack
	bindings.add(eventType, eventrule.Scope{Type: eventrule.ScopeTypeRack, ID: rackID}, rack.ID)
	rule, err = manager.GetEffective(context.Background(), eventType, rackID)
	require.NoError(t, err)
	assert.Equal(t, rack.ID, rule.ID)

	rack.Enabled = false
	rule, err = manager.GetEffective(context.Background(), eventType, rackID)
	require.NoError(t, err)
	assert.Equal(t, site.ID, rule.ID)

	rule, err = manager.GetEffective(context.Background(), "unknown.event", rackID)
	require.NoError(t, err)
	assert.Nil(t, rule)
}

func TestManagerRejectsMissingIDs(t *testing.T) {
	builtIns, err := registry.New()
	require.NoError(t, err)
	manager, err := New(builtIns, newTestStore(), newTestBindingStore())
	require.NoError(t, err)

	_, err = manager.GetByID(context.Background(), uuid.Nil)
	require.ErrorContains(t, err, "event rule id is required")

	require.ErrorContains(t, manager.UpdateMetadata(
		context.Background(),
		uuid.Nil,
		eventrule.RuleMetadata{Name: "test"},
	), "event rule id is required")
	require.ErrorContains(t, manager.SetDedupe(
		context.Background(),
		uuid.Nil,
		&eventrule.Dedupe{Window: time.Minute},
	), "event rule id is required")
	require.ErrorContains(t, manager.ReplaceActions(
		context.Background(),
		uuid.Nil,
		[]eventrule.Action{
			eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
		},
	), "event rule id is required")
	require.ErrorContains(t, manager.Delete(context.Background(), uuid.Nil), "event rule id is required")
	require.ErrorContains(
		t,
		manager.SetEnabled(context.Background(), uuid.Nil, true),
		"event rule id is required",
	)
	_, err = manager.Bind(
		context.Background(),
		uuid.Nil,
		eventrule.Scope{Type: eventrule.ScopeTypeSite},
	)
	require.ErrorContains(t, err, "event rule id is required")
	require.ErrorContains(
		t,
		manager.Unbind(context.Background(), uuid.Nil),
		"event rule binding id is required",
	)
}

func TestManagerRejectsBuiltInRuleMutations(t *testing.T) {
	builtIn := testRule(uuid.New(), eventrule.RuleOriginBuiltIn, "test.event")
	builtIns, err := registry.New(builtIn)
	require.NoError(t, err)
	manager, err := New(builtIns, newTestStore(), newTestBindingStore())
	require.NoError(t, err)

	tests := map[string]func(context.Context) error{
		"update metadata": func(ctx context.Context) error {
			return manager.UpdateMetadata(
				ctx,
				builtIn.ID,
				eventrule.RuleMetadata{Name: "updated"},
			)
		},
		"set dedupe": func(ctx context.Context) error {
			return manager.SetDedupe(
				ctx,
				builtIn.ID,
				&eventrule.Dedupe{Window: time.Minute},
			)
		},
		"replace actions": func(ctx context.Context) error {
			return manager.ReplaceActions(
				ctx,
				builtIn.ID,
				[]eventrule.Action{
					eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
				},
			)
		},
		"delete": func(ctx context.Context) error {
			return manager.Delete(ctx, builtIn.ID)
		},
		"bind": func(ctx context.Context) error {
			_, err := manager.Bind(
				ctx,
				builtIn.ID,
				eventrule.Scope{Type: eventrule.ScopeTypeSite},
			)
			return err
		},
		"set enabled": func(ctx context.Context) error {
			return manager.SetEnabled(ctx, builtIn.ID, false)
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			err := mutate(context.Background())
			require.ErrorContains(t, err, "is a built-in and cannot be mutated")
		})
	}
}

type scopeKey struct {
	eventType eventrule.Type
	scope     eventrule.Scope
}

type testStore struct {
	byID    map[uuid.UUID]*eventrule.Rule
	creates int
}

func newTestStore(rules ...*eventrule.Rule) *testStore {
	store := &testStore{
		byID: make(map[uuid.UUID]*eventrule.Rule, len(rules)),
	}
	for _, rule := range rules {
		store.byID[rule.ID] = rule
	}
	return store
}

func (s *testStore) GetByID(_ context.Context, id uuid.UUID) (*eventrule.Rule, error) {
	if rule, ok := s.byID[id]; ok {
		return rule, nil
	}
	return nil, fmt.Errorf("%w: %s", eventrule.ErrRuleNotFound, id)
}

func (s *testStore) List(context.Context, eventrule.RuleFilter) ([]*eventrule.Rule, error) {
	rules := make([]*eventrule.Rule, 0, len(s.byID))
	for _, rule := range s.byID {
		rules = append(rules, rule)
	}
	return rules, nil
}

func (s *testStore) Create(_ context.Context, rule *eventrule.Rule) (*eventrule.Rule, error) {
	s.creates++
	s.byID[rule.ID] = rule
	return rule, nil
}

func (s *testStore) UpdateMetadata(
	_ context.Context,
	id uuid.UUID,
	metadata eventrule.RuleMetadata,
) error {
	rule, err := s.ruleForMutation(id)
	if err != nil {
		return err
	}
	rule.Name = metadata.Name
	rule.Description = metadata.Description
	return nil
}

func (s *testStore) SetDedupe(_ context.Context, id uuid.UUID, dedupe *eventrule.Dedupe) error {
	rule, err := s.ruleForMutation(id)
	if err != nil {
		return err
	}
	rule.Dedupe = dedupe
	return nil
}

func (s *testStore) ReplaceActions(
	_ context.Context,
	id uuid.UUID,
	actions []eventrule.Action,
) error {
	rule, err := s.ruleForMutation(id)
	if err != nil {
		return err
	}
	rule.Actions = actions
	return nil
}

func (s *testStore) Delete(_ context.Context, id uuid.UUID) error {
	if _, err := s.ruleForMutation(id); err != nil {
		return err
	}
	delete(s.byID, id)
	return nil
}

func (s *testStore) SetEnabled(_ context.Context, id uuid.UUID, enabled bool) error {
	rule, err := s.ruleForMutation(id)
	if err != nil {
		return err
	}
	rule.Enabled = enabled
	return nil
}

func (s *testStore) ruleForMutation(id uuid.UUID) (*eventrule.Rule, error) {
	rule, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", eventrule.ErrRuleNotFound, id)
	}
	return rule, nil
}

type testBindingStore struct {
	byScope map[scopeKey]*eventrule.Binding
	bound   []eventrule.Binding
}

func newTestBindingStore() *testBindingStore {
	return &testBindingStore{byScope: make(map[scopeKey]*eventrule.Binding)}
}

func (s *testBindingStore) add(
	eventType eventrule.Type,
	scope eventrule.Scope,
	ruleID uuid.UUID,
) {
	s.byScope[scopeKey{eventType: eventType, scope: scope}] = &eventrule.Binding{
		ID:        uuid.New(),
		RuleID:    ruleID,
		EventType: eventType,
		Scope:     scope,
	}
}

func (s *testBindingStore) Bind(_ context.Context, binding eventrule.Binding) error {
	s.bound = append(s.bound, binding)
	return nil
}

func (s *testBindingStore) Unbind(context.Context, uuid.UUID) error { return nil }

func (s *testBindingStore) GetForScope(
	_ context.Context,
	eventType eventrule.Type,
	scope eventrule.Scope,
) (*eventrule.Binding, error) {
	if binding, ok := s.byScope[scopeKey{eventType: eventType, scope: scope}]; ok {
		return binding, nil
	}
	return nil, nil
}

func testRule(id uuid.UUID, origin eventrule.RuleOrigin, eventType eventrule.Type) *eventrule.Rule {
	return &eventrule.Rule{
		ID:        id,
		Origin:    origin,
		Name:      "test",
		Enabled:   true,
		EventType: eventType,
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
		}},
	}
}
