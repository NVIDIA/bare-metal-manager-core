// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operation"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	taskdef "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/task"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

func TestIsRMSOperation(t *testing.T) {
	t.Parallel()

	assert.True(t, isRMSOperation(taskcommon.TaskTypePowerControl))
	assert.True(t, isRMSOperation(taskcommon.TaskTypeFirmwareControl))
	assert.False(t, isRMSOperation(taskcommon.TaskTypeBringUp))
}

func rmsTask(opType taskcommon.TaskType, code string) *taskdef.Task {
	return &taskdef.Task{
		ID:     uuid.New(),
		RackID: uuid.New(),
		Operation: operation.Wrapper{
			Type: opType,
			Code: code,
		},
	}
}

func TestPlanExecutionRMSPower(t *testing.T) {
	t.Parallel()

	m := &ManagerImpl{wholeRackUseRMS: true}
	task := rmsTask(taskcommon.TaskTypePowerControl, "power_on")

	ruleDef, components, err := m.planExecution(context.Background(), task, nil)
	require.NoError(t, err)
	require.NotNil(t, ruleDef)
	require.Len(t, ruleDef.Steps, 1)
	assert.Equal(t, devicetypes.ComponentTypeRack, ruleDef.Steps[0].ComponentType)

	require.Len(t, components, 1)
	assert.Equal(t, devicetypes.ComponentTypeRack, components[0].Type)
	assert.Equal(t, task.RackID.String(), components[0].ComponentID)
}

func TestPlanExecutionRMSFirmware(t *testing.T) {
	t.Parallel()

	m := &ManagerImpl{wholeRackUseRMS: true}
	task := rmsTask(taskcommon.TaskTypeFirmwareControl, "upgrade")

	ruleDef, components, err := m.planExecution(context.Background(), task, nil)
	require.NoError(t, err)
	require.NotNil(t, ruleDef)
	require.Len(t, components, 1)
	assert.Equal(t, devicetypes.ComponentTypeRack, components[0].Type)
}
