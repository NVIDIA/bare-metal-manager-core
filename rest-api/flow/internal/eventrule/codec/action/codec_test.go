// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package action_test

import (
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	actioncodec "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/codec/action"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestMarshal(t *testing.T) {
	tests := map[string]eventrule.Action{
		"submit task": {
			Name: "submit",
			Condition: eventrule.ActionCondition{
				Severities:     []eventrule.Severity{eventrule.SeverityCritical},
				ComponentTypes: []flowtypes.ComponentType{flowtypes.ComponentTypeCompute},
			},
			Spec: &eventrule.SubmitTask{
				Operation: &operations.FirmwareControlTaskInfo{
					Operation:              operations.FirmwareOperationUpgrade,
					TargetVersion:          "1.2.3",
					StartTime:              123,
					EndTime:                456,
					SubTargets:             []string{"bmc", "bios"},
					OverrideReadinessCheck: true,
				},
				TargetStrategy:   eventrule.TargetStrategyComponent,
				ConflictStrategy: eventrule.ConflictStrategyQueue,
				Description:      "power off",
			},
		},
		"send alert": {
			Name: "alert",
			Spec: &eventrule.SendAlert{
				Severity: eventrule.SeverityWarning,
				Message:  "leak detected",
			},
		},
		"noop": {Name: "noop", Spec: &eventrule.Noop{Reason: "audit only"}},
	}

	for name, action := range tests {
		t.Run(name, func(t *testing.T) {
			encoded, err := actioncodec.Marshal(action)
			require.NoError(t, err)

			roundTripped, err := actioncodec.Unmarshal(encoded)
			require.NoError(t, err)
			require.Equal(t, action, roundTripped)
		})
	}
}

func TestMarshalRejectsInvalidAction(t *testing.T) {
	_, err := actioncodec.Marshal(eventrule.Action{})
	require.Error(t, err)
}

func TestUnmarshal(t *testing.T) {
	tests := map[string]string{
		"unknown version": `{
			"version":2,
			"name":"noop",
			"type":"noop",
			"condition":{},
			"spec":{}
		}`,
		"unknown action field": `{
			"version":1,
			"name":"noop",
			"type":"noop",
			"condition":{},
			"spec":{},
			"unknown":true
		}`,
		"invalid condition severity": `{
			"version":1,
			"name":"noop",
			"type":"noop",
			"condition":{"severities":["urgent"]},
			"spec":{}
		}`,
		"invalid condition component type": `{
			"version":1,
			"name":"noop",
			"type":"noop",
			"condition":{"componentTypes":["GPU"]},
			"spec":{}
		}`,
		"invalid send alert severity": `{
			"version":1,
			"name":"alert",
			"type":"send_alert",
			"condition":{},
			"spec":{"severity":"urgent"}
		}`,
		"unspecified send alert severity": `{
			"version":1,
			"name":"alert",
			"type":"send_alert",
			"condition":{},
			"spec":{"severity":""}
		}`,
		"unknown action type": `{
			"version":1,
			"name":"unknown",
			"type":"unknown",
			"condition":{},
			"spec":{}
		}`,
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := actioncodec.Unmarshal([]byte(data))
			require.Error(t, err)
		})
	}
}
