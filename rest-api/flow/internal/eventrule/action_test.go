// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"slices"
	"testing"
	"time"

	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionsValidate(t *testing.T) {
	conditions := []ActionCondition{
		{},
		{Severities: []Severity{SeverityWarning, SeverityCritical}},
		{ComponentTypes: []flowtypes.ComponentType{flowtypes.ComponentTypeCompute}},
		{
			Severities:     []Severity{SeverityCritical},
			ComponentTypes: []flowtypes.ComponentType{flowtypes.ComponentTypeNVSwitch},
		},
	}
	strategies := []TargetStrategy{
		TargetStrategyComponent,
		TargetStrategyRack,
		TargetStrategyAffectedComponents,
	}

	actions := make([]Action, 0, len(strategies)+2)
	for i, strategy := range strategies {
		actions = append(actions, NewAction(
			[]string{"component", "rack", "affected"}[i],
			conditions[i],
			SubmitTask{
				OperationType:    taskcommon.TaskTypePowerControl,
				OperationCode:    taskcommon.OpCodePowerControlForcePowerOff,
				TargetStrategy:   strategy,
				ConflictStrategy: ConflictStrategyQueue,
			},
		))
	}
	actions = append(actions,
		NewAction("alert", conditions[3], SendAlert{
			Severity: SeverityCritical,
			Message:  "Leak detected",
		}),
		NewAction("noop", ActionCondition{}, Noop{Reason: "record only"}),
	)
	wantStrategies := append(
		slices.Clone(strategies),
		TargetStrategyNone,
		TargetStrategyNone,
	)

	for i := range actions {
		require.NoError(t, actions[i].Validate())
		require.Equal(
			t,
			wantStrategies[i],
			actions[i].Spec.TargetResolutionStrategy(),
		)
	}
}

func TestActionRejectsInvalidDomainValues(t *testing.T) {
	validTaskSpec := SubmitTask{
		OperationType:    taskcommon.TaskTypePowerControl,
		OperationCode:    taskcommon.OpCodePowerControlForcePowerOff,
		TargetStrategy:   TargetStrategyComponent,
		ConflictStrategy: ConflictStrategyQueue,
	}
	unknownStrategySpec := validTaskSpec
	unknownStrategySpec.TargetStrategy = "unknown"
	noneStrategySpec := validTaskSpec
	noneStrategySpec.TargetStrategy = TargetStrategyNone
	mismatchedOperationSpec := validTaskSpec
	mismatchedOperationSpec.OperationCode = taskcommon.OpCodeFirmwareControlUpgrade
	tests := map[string]Action{
		"empty condition list": NewAction(
			"noop", ActionCondition{Severities: []Severity{}}, Noop{},
		),
		"unspecified severity": NewAction(
			"noop", ActionCondition{Severities: []Severity{SeverityUnspecified}}, Noop{},
		),
		"unspecified alert severity": NewAction(
			"alert", ActionCondition{}, SendAlert{Severity: SeverityUnspecified},
		),
		"unknown strategy": NewAction(
			"task", ActionCondition{}, unknownStrategySpec,
		),
		"task without target resolution": NewAction(
			"task", ActionCondition{}, noneStrategySpec,
		),
		"mismatched operation": NewAction(
			"task", ActionCondition{}, mismatchedOperationSpec,
		),
		"missing spec": {ID: "task"},
	}

	for name, action := range tests {
		t.Run(name, func(t *testing.T) {
			require.Error(t, action.Validate())
		})
	}
}

func TestTargetStrategy_RequiresResolution(t *testing.T) {
	tests := map[string]struct {
		strategy TargetStrategy
		want     bool
	}{
		"none":                {strategy: TargetStrategyNone},
		"component":           {strategy: TargetStrategyComponent, want: true},
		"rack":                {strategy: TargetStrategyRack, want: true},
		"affected components": {strategy: TargetStrategyAffectedComponents, want: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, test.strategy.Validate())
			require.Equal(t, test.want, test.strategy.RequiresResolution())
		})
	}
}

func TestRuleValidatesPolicy(t *testing.T) {
	action := NewAction("noop", ActionCondition{}, Noop{})
	rule := Rule{
		ID:        uuid.New(),
		Origin:    RuleOriginPersisted,
		Name:      "test rule",
		Enabled:   true,
		EventType: "test.event",
		Policy: Policy{
			Dedupe:  &Dedupe{Window: 5 * time.Minute},
			Actions: []Action{action},
		},
	}
	require.NoError(t, rule.Validate())

	rule.Actions = nil
	require.ErrorContains(t, rule.Validate(), "actions are required")
	rule.Actions = []Action{action, action}
	require.ErrorContains(t, rule.Validate(), "duplicate action id")
	rule.Actions = []Action{action}
	rule.Origin = ""
	require.ErrorContains(t, rule.Validate(), "unknown rule origin")
}

func TestActionConditionAppliesTo(t *testing.T) {
	condition := ActionCondition{
		Severities:     []Severity{SeverityWarning, SeverityCritical},
		ComponentTypes: []flowtypes.ComponentType{flowtypes.ComponentTypeCompute},
	}

	tests := map[string]struct {
		condition ActionCondition
		envelope  Envelope
		resource  ResolvedResource
		want      bool
	}{
		"matches severity and component type": {
			condition: condition,
			envelope:  Envelope{Severity: SeverityCritical},
			resource: ResolvedResource{
				Kind:          ResourceKindComponent,
				ComponentType: flowtypes.ComponentTypeCompute,
			},
			want: true,
		},
		"rejects severity": {
			condition: condition,
			envelope:  Envelope{Severity: SeverityInfo},
			resource: ResolvedResource{
				Kind:          ResourceKindComponent,
				ComponentType: flowtypes.ComponentTypeCompute,
			},
		},
		"rejects component type": {
			condition: condition,
			envelope:  Envelope{Severity: SeverityCritical},
			resource: ResolvedResource{
				Kind:          ResourceKindComponent,
				ComponentType: flowtypes.ComponentTypeNVSwitch,
			},
		},
		"component type condition rejects rack": {
			condition: condition,
			envelope:  Envelope{Severity: SeverityCritical},
			resource: ResolvedResource{
				Kind:          ResourceKindRack,
				ComponentType: flowtypes.ComponentTypeCompute,
			},
		},
		"empty severity set matches nothing": {
			condition: ActionCondition{Severities: []Severity{}},
			envelope:  Envelope{Severity: SeverityCritical},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, test.condition.AppliesTo(
				test.envelope,
				test.resource,
			))
		})
	}
}
