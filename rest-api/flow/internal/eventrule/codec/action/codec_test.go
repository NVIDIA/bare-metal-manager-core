// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package action_test

import (
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	actioncodec "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/codec/action"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestMarshal(t *testing.T) {
	tests := map[string]eventrule.Action{
		"submit task": eventrule.NewAction(
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
		"send alert": eventrule.NewAction(
			"alert",
			eventrule.ActionCondition{},
			eventrule.SendAlert{
				Severity: eventrule.SeverityWarning,
				Message:  "leak detected",
			},
		),
		"noop": eventrule.NewAction(
			"noop",
			eventrule.ActionCondition{},
			eventrule.Noop{Reason: "audit only"},
		),
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
			"id":"noop",
			"type":"noop",
			"condition":{},
			"spec":{}
		}`,
		"unknown action field": `{
			"version":1,
			"id":"noop",
			"type":"noop",
			"condition":{},
			"spec":{},
			"unknown":true
		}`,
		"invalid condition severity": `{
			"version":1,
			"id":"noop",
			"type":"noop",
			"condition":{"severities":["urgent"]},
			"spec":{}
		}`,
		"invalid condition component type": `{
			"version":1,
			"id":"noop",
			"type":"noop",
			"condition":{"componentTypes":["GPU"]},
			"spec":{}
		}`,
		"invalid send alert severity": `{
			"version":1,
			"id":"alert",
			"type":"send_alert",
			"condition":{},
			"spec":{"severity":"urgent"}
		}`,
		"unspecified send alert severity": `{
			"version":1,
			"id":"alert",
			"type":"send_alert",
			"condition":{},
			"spec":{"severity":""}
		}`,
		"unknown action type": `{
			"version":1,
			"id":"unknown",
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
