// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package leakage

import (
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultRuleValidates(t *testing.T) {
	rule := DefaultRule()
	require.NoError(t, rule.Validate())
	assert.Equal(t, uuid.MustParse("f34b87f7-cb1b-4b08-aa51-30c0b3b58680"), rule.ID)
	assert.Equal(t, eventrule.RuleOriginBuiltIn, rule.Origin)
	assert.Equal(t, TypeHardwareLeakDetected, rule.EventType)
	require.Len(t, rule.Actions, 1)
	spec, ok := rule.Actions[0].Spec.(eventrule.SubmitTask)
	require.True(t, ok)
	assert.Equal(t, taskcommon.TaskTypePowerControl, spec.OperationType)
	assert.Equal(t, taskcommon.OperationCode(taskcommon.OpCodePowerControlForcePowerOff), spec.OperationCode)
	assert.Equal(t, eventrule.TargetStrategyAffectedComponents, spec.TargetStrategy)
}
