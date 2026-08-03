// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package policycodec

import (
	"os"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestPolicyV1Fixture(t *testing.T) {
	data, err := os.ReadFile("testdata/policy_v1_all_actions.json")
	require.NoError(t, err)

	policy, err := Unmarshal(data)
	require.NoError(t, err)
	require.Equal(t, fullPolicy(), policy)
}

func TestPolicyV1WithoutDedupeFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/policy_v1_without_dedupe.json")
	require.NoError(t, err)

	policy, err := Unmarshal(data)
	require.NoError(t, err)
	require.Nil(t, policy.Dedupe)
	require.Len(t, policy.Actions, 1)
	require.Equal(t, "noop", policy.Actions[0].ID)
}

func TestPolicyRoundTrip(t *testing.T) {
	policy := fullPolicy()
	encoded, err := Marshal(policy)
	require.NoError(t, err)
	roundTripped, err := Unmarshal(encoded)
	require.NoError(t, err)
	require.Equal(t, policy, roundTripped)
}

func TestPolicyRejectsUnknownVersionsAndFields(t *testing.T) {
	tests := map[string]string{
		"policy version": `{"version":2,"actions":[]}`,
		"dedupe version": `{
			"version":1,
			"dedupe":{"version":2,"window":1},
			"actions":[]
		}`,
		"action version": `{
			"version":1,
			"actions":[
				{"version":2,"id":"noop","type":"noop","condition":{},"spec":{}}
			]
		}`,
		"policy field": `{"version":1,"actions":[],"unknown":true}`,
		"action field": `{
			"version":1,
			"actions":[
				{
					"version":1,
					"id":"noop",
					"type":"noop",
					"condition":{},
					"spec":{},
					"unknown":true
				}
			]
		}`,
		"invalid action severity": `{
			"version":1,
			"actions":[
				{
					"version":1,
					"id":"noop",
					"type":"noop",
					"condition":{"severities":["urgent"]},
					"spec":{}
				}
			]
		}`,
		"invalid action component type": `{
			"version":1,
			"actions":[
				{
					"version":1,
					"id":"noop",
					"type":"noop",
					"condition":{"componentTypes":["GPU"]},
					"spec":{}
				}
			]
		}`,
		"invalid send alert severity": `{
			"version":1,
			"actions":[
				{
					"version":1,
					"id":"alert",
					"type":"send_alert",
					"condition":{},
					"spec":{"severity":"urgent"}
				}
			]
		}`,
		"unspecified send alert severity": `{
			"version":1,
			"actions":[
				{
					"version":1,
					"id":"alert",
					"type":"send_alert",
					"condition":{},
					"spec":{"severity":""}
				}
			]
		}`,
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Unmarshal([]byte(data))
			require.Error(t, err)
		})
	}
}

func fullPolicy() eventrule.Policy {
	return eventrule.Policy{
		Dedupe: &eventrule.Dedupe{Window: 5 * time.Minute},
		Actions: []eventrule.Action{
			eventrule.NewAction(
				"submit",
				eventrule.ActionCondition{
					Severities:     []eventrule.Severity{eventrule.SeverityCritical},
					ComponentTypes: []flowtypes.ComponentType{flowtypes.ComponentTypeCompute},
				},
				eventrule.SubmitTask{
					OperationType:    taskcommon.TaskTypePowerControl,
					OperationCode:    taskcommon.OpCodePowerControlForcePowerOff,
					TargetStrategy:   eventrule.TargetStrategyComponent,
					ConflictStrategy: eventrule.ConflictStrategyQueue,
					Description:      "power off",
				},
			),
			eventrule.NewAction(
				"alert",
				eventrule.ActionCondition{},
				eventrule.SendAlert{
					Severity: eventrule.SeverityWarning,
					Message:  "leak detected",
				},
			),
			eventrule.NewAction(
				"noop",
				eventrule.ActionCondition{},
				eventrule.Noop{Reason: "audit only"},
			),
		},
	}
}
