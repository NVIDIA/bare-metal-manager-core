// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operationrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

func TestBuildRackRulePower(t *testing.T) {
	t.Parallel()

	rd := BuildRackRule(common.TaskTypePowerControl)
	require.NotNil(t, rd)
	require.NoError(t, rd.Validate())
	require.Len(t, rd.Steps, 1)

	step := rd.Steps[0]
	assert.Equal(t, devicetypes.ComponentTypeRack, step.ComponentType)
	assert.Equal(t, 1, step.Stage)
	assert.Equal(t, ActionPowerControl, step.MainOperation.Name)
	assert.Empty(t, step.PostOperation)
}

func TestBuildRackRuleFirmware(t *testing.T) {
	t.Parallel()

	rd := BuildRackRule(common.TaskTypeFirmwareControl)
	require.NotNil(t, rd)
	require.NoError(t, rd.Validate())
	require.Len(t, rd.Steps, 1)

	step := rd.Steps[0]
	assert.Equal(t, devicetypes.ComponentTypeRack, step.ComponentType)
	assert.Equal(t, 1, step.Stage)
	assert.Equal(t, ActionFirmwareControl, step.MainOperation.Name)
	assert.Contains(t, step.MainOperation.Parameters, ParamPollInterval)
	assert.Contains(t, step.MainOperation.Parameters, ParamPollTimeout)
}

func TestBuildRackRuleUnsupported(t *testing.T) {
	t.Parallel()

	assert.Nil(t, BuildRackRule(common.TaskTypeBringUp))
	assert.Nil(t, BuildRackRule(common.TaskType("nonsense")))
}
