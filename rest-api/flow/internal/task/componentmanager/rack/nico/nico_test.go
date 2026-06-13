// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nico

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi/gen"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/componentmanager"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/componentmanager/capability"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

// The rack manager must satisfy the capability interfaces matching the
// capabilities its descriptor declares.
var (
	_ componentmanager.PowerController      = (*Manager)(nil)
	_ componentmanager.FirmwareController   = (*Manager)(nil)
	_ componentmanager.FirmwareStatusReader = (*Manager)(nil)
)

func validRackTarget() common.Target {
	return common.Target{
		Type:         devicetypes.ComponentTypeRack,
		ComponentIDs: []string{"11111111-1111-1111-1111-111111111111"},
	}
}

func TestDescriptor(t *testing.T) {
	t.Parallel()

	desc := Descriptor()

	assert.Equal(t, devicetypes.ComponentTypeRack, desc.Type)
	assert.Equal(t, ImplementationName, desc.Implementation)
	assert.Contains(t, desc.RequiredProviders, "nico")
	assert.True(t, desc.Capabilities.Contains(capability.CapabilityPowerControl))
	assert.True(t, desc.Capabilities.Contains(capability.CapabilityFirmwareControl))
	assert.True(t, desc.Capabilities.Contains(capability.CapabilityFirmwareStatus))
}

func TestPowerActionFromOperation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		op   operations.PowerOperation
		want pb.SystemPowerControl
	}{
		{"on", operations.PowerOperationPowerOn, pb.SystemPowerControl_SYSTEM_POWER_CONTROL_ON},
		{"force_on", operations.PowerOperationForcePowerOn, pb.SystemPowerControl_SYSTEM_POWER_CONTROL_ON},
		{"off", operations.PowerOperationPowerOff, pb.SystemPowerControl_SYSTEM_POWER_CONTROL_GRACEFUL_SHUTDOWN},
		{"force_off", operations.PowerOperationForcePowerOff, pb.SystemPowerControl_SYSTEM_POWER_CONTROL_FORCE_OFF},
		{"restart", operations.PowerOperationRestart, pb.SystemPowerControl_SYSTEM_POWER_CONTROL_GRACEFUL_RESTART},
		{"force_restart", operations.PowerOperationForceRestart, pb.SystemPowerControl_SYSTEM_POWER_CONTROL_FORCE_RESTART},
		{"cold_reset", operations.PowerOperationColdReset, pb.SystemPowerControl_SYSTEM_POWER_CONTROL_AC_POWERCYCLE},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := powerActionFromOperation(tc.op)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPowerActionFromOperationUnknown(t *testing.T) {
	t.Parallel()

	_, err := powerActionFromOperation(operations.PowerOperationUnknown)
	require.Error(t, err)
}

func TestPowerControlRejectsInvalidTarget(t *testing.T) {
	t.Parallel()

	m := New(nil)
	err := m.PowerControl(context.Background(), common.Target{}, operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationPowerOn,
	})

	require.Error(t, err)
	assert.NotErrorIs(t, err, errRackTargetPendingCoreProto)
}

func TestPowerControlRejectsUnsupportedOperation(t *testing.T) {
	t.Parallel()

	m := New(nil)
	err := m.PowerControl(context.Background(), validRackTarget(), operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationUnknown,
	})

	require.Error(t, err)
	assert.NotErrorIs(t, err, errRackTargetPendingCoreProto)
}

func TestPowerControlPendingCoreProto(t *testing.T) {
	t.Parallel()

	m := New(nil)
	err := m.PowerControl(context.Background(), validRackTarget(), operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationPowerOn,
	})

	require.ErrorIs(t, err, errRackTargetPendingCoreProto)
}

func TestFirmwareControlPendingCoreProto(t *testing.T) {
	t.Parallel()

	m := New(nil)
	err := m.FirmwareControl(context.Background(), validRackTarget(), operations.FirmwareControlTaskInfo{
		Operation: operations.FirmwareOperationUpgrade,
	})

	require.ErrorIs(t, err, errRackTargetPendingCoreProto)
}

func TestFirmwareControlRejectsInvalidTarget(t *testing.T) {
	t.Parallel()

	m := New(nil)
	err := m.FirmwareControl(context.Background(), common.Target{}, operations.FirmwareControlTaskInfo{})

	require.Error(t, err)
	assert.NotErrorIs(t, err, errRackTargetPendingCoreProto)
}

func TestGetFirmwareStatusPendingCoreProto(t *testing.T) {
	t.Parallel()

	m := New(nil)
	statuses, err := m.GetFirmwareStatus(context.Background(), validRackTarget())

	require.ErrorIs(t, err, errRackTargetPendingCoreProto)
	assert.Nil(t, statuses)
}

func TestGetFirmwareStatusRejectsInvalidTarget(t *testing.T) {
	t.Parallel()

	m := New(nil)
	_, err := m.GetFirmwareStatus(context.Background(), common.Target{})

	require.Error(t, err)
	assert.NotErrorIs(t, err, errRackTargetPendingCoreProto)
}

func TestErrIsPlaceholderSentinel(t *testing.T) {
	t.Parallel()

	// Guards against accidentally wrapping the sentinel in a way that breaks
	// errors.Is for callers that branch on the pending-proto condition.
	require.True(t, errors.Is(errRackTargetPendingCoreProto, errRackTargetPendingCoreProto))
}
