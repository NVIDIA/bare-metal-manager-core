// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRegistry_Resolve(t *testing.T) {
	componentID := uuid.New()
	rackID := uuid.New()
	tests := []struct {
		name    string
		request ResolveRequest
		want    []Target
		wantErr string
	}{
		{
			name: "component",
			request: targetRequest(
				eventrule.TargetStrategyComponent,
				eventrule.ResolvedResource{
					Kind:          eventrule.ResourceKindComponent,
					ID:            componentID,
					RackID:        rackID,
					ComponentType: flowtypes.ComponentTypeCompute,
				},
			),
			want: []Target{{
				Kind: eventrule.ResourceKindComponent,
				ID:   componentID,
			}},
		},
		{
			name: "component rejects rack resource",
			request: targetRequest(
				eventrule.TargetStrategyComponent,
				eventrule.ResolvedResource{
					Kind:   eventrule.ResourceKindRack,
					ID:     rackID,
					RackID: rackID,
				},
			),
			wantErr: "requires a component resource",
		},
		{
			name: "component requires identity",
			request: targetRequest(
				eventrule.TargetStrategyComponent,
				eventrule.ResolvedResource{Kind: eventrule.ResourceKindComponent},
			),
			wantErr: "resolved resource id is required",
		},
		{
			name: "rack from component",
			request: targetRequest(
				eventrule.TargetStrategyRack,
				eventrule.ResolvedResource{
					Kind:          eventrule.ResourceKindComponent,
					ID:            componentID,
					RackID:        rackID,
					ComponentType: flowtypes.ComponentTypeCompute,
				},
			),
			want: []Target{{Kind: eventrule.ResourceKindRack, ID: rackID}},
		},
		{
			name: "rack requires identity",
			request: targetRequest(
				eventrule.TargetStrategyRack,
				eventrule.ResolvedResource{Kind: eventrule.ResourceKindRack},
			),
			wantErr: "resolved resource id is required",
		},
		{
			name: "affected components from component",
			request: targetRequest(
				eventrule.TargetStrategyAffectedComponents,
				eventrule.ResolvedResource{
					Kind:          eventrule.ResourceKindComponent,
					ID:            componentID,
					RackID:        rackID,
					ComponentType: flowtypes.ComponentTypeCompute,
				},
			),
			want: []Target{{Kind: eventrule.ResourceKindComponent, ID: componentID}},
		},
		{
			name: "affected components from rack",
			request: targetRequest(
				eventrule.TargetStrategyAffectedComponents,
				eventrule.ResolvedResource{
					Kind:   eventrule.ResourceKindRack,
					ID:     rackID,
					RackID: rackID,
				},
			),
			want: []Target{{Kind: eventrule.ResourceKindRack, ID: rackID}},
		},
		{
			name: "unregistered event-specific strategy",
			request: targetRequest(
				eventrule.TargetStrategy("unknown"),
				eventrule.ResolvedResource{
					Kind:          eventrule.ResourceKindComponent,
					ID:            componentID,
					RackID:        rackID,
					ComponentType: flowtypes.ComponentTypeCompute,
				},
			),
			wantErr: "no target resolver",
		},
	}

	registry := New()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := registry.Resolve(context.Background(), test.request)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				require.Nil(t, resolved)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, resolved)
		})
	}

	t.Run("event-specific resolver overrides generic resolver", func(t *testing.T) {
		want := []Target{{Kind: eventrule.ResourceKindRack, ID: uuid.New()}}
		registry := New()
		require.NoError(t, registry.Register(
			"hardware.leak.detected",
			eventrule.TargetStrategyComponent,
			func(context.Context, ResolveRequest) ([]Target, error) {
				return want, nil
			},
		))

		resolved, err := registry.Resolve(context.Background(), targetRequest(
			eventrule.TargetStrategyComponent,
			eventrule.ResolvedResource{
				Kind:          eventrule.ResourceKindComponent,
				ID:            componentID,
				RackID:        rackID,
				ComponentType: flowtypes.ComponentTypeCompute,
			},
		))
		require.NoError(t, err)
		require.Equal(t, want, resolved)
	})

	t.Run("invalid resolver result is unresolvable", func(t *testing.T) {
		registry := New()
		require.NoError(t, registry.Register(
			"hardware.leak.detected",
			eventrule.TargetStrategyComponent,
			func(context.Context, ResolveRequest) ([]Target, error) {
				return []Target{{Kind: eventrule.ResourceKindComponent}}, nil
			},
		))

		resolved, err := registry.Resolve(context.Background(), targetRequest(
			eventrule.TargetStrategyComponent,
			eventrule.ResolvedResource{
				Kind:          eventrule.ResourceKindComponent,
				ID:            componentID,
				RackID:        rackID,
				ComponentType: flowtypes.ComponentTypeCompute,
			},
		))
		require.ErrorIs(t, err, ErrUnresolvable)
		require.Nil(t, resolved)
	})
}

func TestRegistry_Register(t *testing.T) {
	resolver := ResolverFunc(func(
		context.Context,
		ResolveRequest,
	) ([]Target, error) {
		return nil, nil
	})

	t.Run("event-specific strategy", func(t *testing.T) {
		require.NoError(t, New().Register(
			"hardware.leak.detected",
			eventrule.TargetStrategyAffectedComponents,
			resolver,
		))
	})
	t.Run("duplicate", func(t *testing.T) {
		registry := New()
		require.NoError(t, registry.Register(
			"hardware.leak.detected",
			eventrule.TargetStrategyAffectedComponents,
			resolver,
		))
		require.Error(t, registry.Register(
			"hardware.leak.detected",
			eventrule.TargetStrategyAffectedComponents,
			resolver,
		))
	})
	t.Run("override generic strategy", func(t *testing.T) {
		require.NoError(t, New().Register(
			"hardware.leak.detected",
			eventrule.TargetStrategyComponent,
			resolver,
		))
	})
	t.Run("nil resolver", func(t *testing.T) {
		require.Error(t, New().Register(
			"hardware.leak.detected",
			eventrule.TargetStrategyAffectedComponents,
			nil,
		))
	})
	t.Run("strategy without resolution", func(t *testing.T) {
		require.Error(t, New().Register(
			"hardware.leak.detected",
			eventrule.TargetStrategyNone,
			resolver,
		))
	})
}

func TestRegistry_ValidateRule(t *testing.T) {
	t.Run("registered event-specific resolver", func(t *testing.T) {
		rule := targetRule(eventrule.TargetStrategyAffectedComponents)
		registry := New()
		require.NoError(t, registry.Register(
			rule.EventType,
			eventrule.TargetStrategyAffectedComponents,
			func(context.Context, ResolveRequest) ([]Target, error) {
				return nil, nil
			},
		))
		require.NoError(t, registry.ValidateRule(rule))
	})
	t.Run("generic resolver", func(t *testing.T) {
		for _, strategy := range []eventrule.TargetStrategy{
			eventrule.TargetStrategyComponent,
			eventrule.TargetStrategyRack,
			eventrule.TargetStrategyAffectedComponents,
		} {
			require.NoError(t, New().ValidateRule(targetRule(strategy)))
		}
	})
	t.Run("task pointer", func(t *testing.T) {
		rule := targetRule(eventrule.TargetStrategyComponent)
		task := rule.Actions[0].Spec.(eventrule.SubmitTask)
		rule.Actions[0].Spec = &task
		require.NoError(t, New().ValidateRule(rule))
	})
	t.Run("actions without targets", func(t *testing.T) {
		tests := []struct {
			name string
			spec eventrule.ActionSpec
		}{
			{name: "send alert", spec: eventrule.SendAlert{Severity: eventrule.SeverityWarning}},
			{name: "noop", spec: eventrule.Noop{}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				rule := targetRule(eventrule.TargetStrategyComponent)
				rule.Actions[0] = eventrule.NewAction(
					"action",
					eventrule.ActionCondition{},
					test.spec,
				)
				require.NoError(t, New().ValidateRule(rule))
			})
		}
	})
}

func targetRequest(
	strategy eventrule.TargetStrategy,
	resource eventrule.ResolvedResource,
) ResolveRequest {
	return ResolveRequest{
		Envelope: eventrule.Envelope{Type: "hardware.leak.detected"},
		Resource: resource,
		Strategy: strategy,
	}
}

func targetRule(strategy eventrule.TargetStrategy) *eventrule.Rule {
	return &eventrule.Rule{
		ID:        uuid.New(),
		Origin:    eventrule.RuleOriginPersisted,
		Name:      "target rule",
		Enabled:   true,
		EventType: "hardware.leak.detected",
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			eventrule.NewAction("task", eventrule.ActionCondition{}, eventrule.SubmitTask{
				OperationType:    taskcommon.TaskTypePowerControl,
				OperationCode:    taskcommon.OpCodePowerControlForcePowerOff,
				TargetStrategy:   strategy,
				ConflictStrategy: eventrule.ConflictStrategyQueue,
			}),
		}},
	}
}
