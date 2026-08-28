// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	eventexecutor "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/executor"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/leakage"
	eventscheduler "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/scheduler"
	identifier "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/Identifier"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/inventoryobjects/component"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/inventoryobjects/rack"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestNewArrangesBuiltInRules(t *testing.T) {
	manager, err := New(testManagerConfig())
	require.NoError(t, err)

	expected := leakage.DefaultRule()
	actual, err := manager.GetByID(context.Background(), expected.ID)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func TestManagerUnifiedReadsAndMutationRouting(t *testing.T) {
	ctx := context.Background()
	manager, err := New(testManagerConfig())
	require.NoError(t, err)

	input := testRuleCreate("other.event", "new rule")
	created, err := manager.Create(ctx, input)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, created.ID)
	require.Equal(t, eventrule.RuleOriginPersisted, created.Origin)
	require.False(t, created.Enabled)

	input.Policy.Actions[0].Name = "changed"
	require.Equal(t, "noop", created.Actions[0].Name)

	builtIn := leakage.DefaultRule()
	for _, id := range []uuid.UUID{created.ID, builtIn.ID} {
		rule, err := manager.GetByID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, id, rule.ID)
	}

	rules, err := manager.List(ctx, eventrule.RuleFilter{})
	require.NoError(t, err)
	require.Len(t, rules, 2)

	_, err = manager.Create(ctx, eventrule.RuleCreate{})
	require.Error(t, err)

	require.Error(t, manager.UpdateMetadata(
		ctx,
		created.ID,
		eventrule.RuleMetadata{},
	))
	require.Error(t, manager.ReplaceActions(ctx, created.ID, nil))

	metadata := eventrule.RuleMetadata{
		Name:        "updated",
		Description: "updated description",
	}
	require.NoError(t, manager.UpdateMetadata(ctx, created.ID, metadata))

	updated, err := manager.GetByID(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, metadata.Name, updated.Name)
	require.Equal(t, metadata.Description, updated.Description)

	actions := []eventrule.Action{
		{Name: "replacement", Spec: &eventrule.Noop{}},
	}
	require.NoError(t, manager.ReplaceActions(ctx, created.ID, actions))

	actions[0].Name = "changed"
	updated, err = manager.GetByID(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "replacement", updated.Actions[0].Name)

	require.NoError(t, manager.SetEnabled(ctx, created.ID, true))
	updated, err = manager.GetByID(ctx, created.ID)
	require.NoError(t, err)
	require.True(t, updated.Enabled)

	scope := eventrule.Scope{Type: eventrule.ScopeTypeRack, ID: uuid.New()}
	binding, err := manager.Bind(ctx, created.ID, scope)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, binding.ID)
	require.Equal(t, created.ID, binding.RuleID)
	require.Equal(t, created.EventType, binding.EventType)
	require.Equal(t, scope, binding.Scope)
}

func TestRuleResolver_GetEffective(t *testing.T) {
	ctx := context.Background()
	eventType := leakage.TypeHardwareLeakDetected
	rackID := uuid.New()
	manager, err := New(testManagerConfig())
	require.NoError(t, err)
	resolver := &ruleResolver{builtIns: manager.builtIns, store: manager.store}

	builtIn := leakage.DefaultRule()
	rule, err := resolver.GetEffective(ctx, eventType, rackID)
	require.NoError(t, err)
	require.Equal(t, builtIn.ID, rule.ID)

	site, err := manager.Create(ctx, testRuleCreate(eventType, "site"))
	require.NoError(t, err)
	_, err = manager.Bind(ctx, site.ID, eventrule.Scope{Type: eventrule.ScopeTypeSite})
	require.NoError(t, err)
	require.NoError(t, manager.SetEnabled(ctx, site.ID, true))

	rule, err = resolver.GetEffective(ctx, eventType, rackID)
	require.NoError(t, err)
	require.Equal(t, site.ID, rule.ID)

	rackRule, err := manager.Create(ctx, testRuleCreate(eventType, "rack"))
	require.NoError(t, err)
	_, err = manager.Bind(ctx, rackRule.ID, eventrule.Scope{
		Type: eventrule.ScopeTypeRack,
		ID:   rackID,
	})
	require.NoError(t, err)
	require.NoError(t, manager.SetEnabled(ctx, rackRule.ID, true))

	rule, err = resolver.GetEffective(ctx, eventType, rackID)
	require.NoError(t, err)
	require.Equal(t, rackRule.ID, rule.ID)

	require.NoError(t, manager.SetEnabled(ctx, rackRule.ID, false))
	rule, err = resolver.GetEffective(ctx, eventType, rackID)
	require.NoError(t, err)
	require.Equal(t, site.ID, rule.ID)

	require.NoError(t, manager.SetEnabled(ctx, site.ID, false))
	rule, err = resolver.GetEffective(ctx, eventType, rackID)
	require.NoError(t, err)
	require.Equal(t, builtIn.ID, rule.ID)

	rule, err = resolver.GetEffective(ctx, "unknown.event", rackID)
	require.NoError(t, err)
	require.Nil(t, rule)
}

func TestManagerRejectsMissingIDs(t *testing.T) {
	manager, err := New(testManagerConfig())
	require.NoError(t, err)

	_, err = manager.GetByID(context.Background(), uuid.Nil)
	require.ErrorContains(t, err, "event rule id is required")
	require.ErrorContains(t, manager.UpdateMetadata(
		context.Background(),
		uuid.Nil,
		eventrule.RuleMetadata{Name: "test"},
	), "event rule id is required")
	require.ErrorContains(t, manager.ReplaceActions(
		context.Background(),
		uuid.Nil,
		[]eventrule.Action{
			{Name: "noop", Spec: &eventrule.Noop{}},
		},
	), "event rule id is required")
	require.ErrorContains(
		t,
		manager.Delete(context.Background(), uuid.Nil),
		"event rule id is required",
	)
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
	builtIn := leakage.DefaultRule()
	manager, err := New(testManagerConfig())
	require.NoError(t, err)

	tests := map[string]func(context.Context) error{
		"update metadata": func(ctx context.Context) error {
			return manager.UpdateMetadata(
				ctx,
				builtIn.ID,
				eventrule.RuleMetadata{Name: "updated"},
			)
		},
		"replace actions": func(ctx context.Context) error {
			return manager.ReplaceActions(
				ctx,
				builtIn.ID,
				[]eventrule.Action{
					{Name: "noop", Spec: &eventrule.Noop{}},
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

func TestManagerValidatesConfiguredActionExecutors(t *testing.T) {
	tests := map[string]struct {
		alertSender *testAlertSender
		wantErr     string
	}{
		"rejects alert without sender": {
			wantErr: "no executor registered for action type \"send_alert\"",
		},
		"accepts alert with sender": {
			alertSender: &testAlertSender{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := testManagerConfig()
			if test.alertSender != nil {
				config.AlertSender = test.alertSender
			}

			manager, err := New(config)
			require.NoError(t, err)

			_, err = manager.Create(context.Background(), eventrule.RuleCreate{
				Metadata:  eventrule.RuleMetadata{Name: "alert"},
				EventType: "test.event",
				Policy: eventrule.Policy{Actions: []eventrule.Action{
					{
						Name: "send",
						Spec: &eventrule.SendAlert{
							Severity: eventrule.SeverityWarning,
							Message:  "test alert",
						},
					},
				}},
			})
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func testManagerConfig() Config {
	return Config{
		Store: StoreConfig{Backend: StoreBackendMemory},
		Scheduler: SchedulerConfig{
			InstanceID: "event-rule-manager-test",
			Runtime:    eventscheduler.DefaultRuntimeConfig(),
			Policy:     eventscheduler.DefaultPolicyConfig(),
		},
		Inventory:   testInventory{},
		TaskManager: configTaskManager{},
	}
}

func testRuleCreate(
	eventType eventrule.Type,
	name string,
) eventrule.RuleCreate {
	return eventrule.RuleCreate{
		Metadata:  eventrule.RuleMetadata{Name: name},
		EventType: eventType,
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			{Name: "noop", Spec: &eventrule.Noop{}},
		}},
	}
}

type testInventory struct{}

func (testInventory) GetComponentByID(
	context.Context,
	uuid.UUID,
) (*component.Component, error) {
	return nil, nil
}

func (testInventory) GetComponentsByExternalIDs(
	context.Context,
	[]string,
) ([]*component.Component, error) {
	return nil, nil
}

func (testInventory) GetRackByIdentifier(
	context.Context,
	identifier.Identifier,
	bool,
) (*rack.Rack, error) {
	return nil, nil
}

type testAlertSender struct{}

func (*testAlertSender) SendAlert(
	context.Context,
	eventexecutor.AlertRequest,
) (string, error) {
	return uuid.NewString(), nil
}
