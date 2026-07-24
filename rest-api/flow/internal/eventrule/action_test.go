// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
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

	for i := range actions {
		require.NoError(t, actions[i].Validate())
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
	mismatchedOperationSpec := validTaskSpec
	mismatchedOperationSpec.OperationCode = taskcommon.OpCodeFirmwareControlUpgrade
	tests := map[string]Action{
		"empty condition list": NewAction(
			"noop", ActionCondition{Severities: []Severity{}}, Noop{},
		),
		"unspecified severity": NewAction(
			"noop", ActionCondition{Severities: []Severity{SeverityUnspecified}}, Noop{},
		),
		"unknown strategy": NewAction(
			"task", ActionCondition{}, unknownStrategySpec,
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

	assert.True(t, condition.AppliesTo(Envelope{
		Severity: SeverityCritical,
		Resource: Resource{ComponentType: flowtypes.ComponentTypeCompute},
	}))
	assert.False(t, condition.AppliesTo(Envelope{
		Severity: SeverityInfo,
		Resource: Resource{ComponentType: flowtypes.ComponentTypeCompute},
	}))
	assert.False(t, condition.AppliesTo(Envelope{
		Severity: SeverityCritical,
		Resource: Resource{ComponentType: flowtypes.ComponentTypeNVSwitch},
	}))
	assert.False(t, ActionCondition{Severities: []Severity{}}.AppliesTo(Envelope{
		Severity: SeverityCritical,
	}))
}
