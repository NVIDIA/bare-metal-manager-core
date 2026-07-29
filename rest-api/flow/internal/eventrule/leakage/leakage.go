// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package leakage

import (
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	"github.com/google/uuid"
)

// TypeHardwareLeakDetected identifies an observed hardware coolant leak.
const TypeHardwareLeakDetected eventrule.Type = "hardware.leak.detected"

// defaultRuleID is the stable identity of the immutable leakage fallback.
var defaultRuleID = uuid.MustParse("f34b87f7-cb1b-4b08-aa51-30c0b3b58680")

// DefaultRule returns the immutable safety fallback for leakage events.
func DefaultRule() eventrule.Rule {
	return eventrule.Rule{
		ID:          defaultRuleID,
		Origin:      eventrule.RuleOriginBuiltIn,
		Name:        "Default leakage response",
		Description: "Power off components affected by a detected hardware leak.",
		Enabled:     true,
		EventType:   TypeHardwareLeakDetected,
		Policy: eventrule.Policy{
			Actions: []eventrule.Action{
				eventrule.NewAction(
					"power_off_affected_components",
					eventrule.ActionCondition{},
					eventrule.SubmitTask{
						OperationType:    taskcommon.TaskTypePowerControl,
						OperationCode:    taskcommon.OpCodePowerControlForcePowerOff,
						TargetStrategy:   eventrule.TargetStrategyAffectedComponents,
						ConflictStrategy: eventrule.ConflictStrategyQueue,
						Description:      "Leakage response",
					},
				),
			},
		},
	}
}
