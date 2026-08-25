// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type powerProvisionerStub struct {
	calls  []string
	failAt map[string]error
}

func (s *powerProvisionerStub) call(value string) error {
	s.calls = append(s.calls, value)
	return s.failAt[value]
}

func (s *powerProvisionerStub) ListPowerProfiles(context.Context) ([]string, error) {
	return nil, s.call("list")
}

func (s *powerProvisionerStub) ValidateAllocation(_ context.Context, machineIDs []string, powerProfile string) error {
	return s.call("validate:" + powerProfile + ":" + joinMachineIDs(machineIDs))
}

func (s *powerProvisionerStub) CreateResourceGroup(_ context.Context, resourceGroup string, _ int64) error {
	return s.call("create:" + resourceGroup)
}

func (s *powerProvisionerStub) DeleteResourceGroup(_ context.Context, resourceGroup string) error {
	return s.call("delete:" + resourceGroup)
}

func (s *powerProvisionerStub) AddMachine(_ context.Context, resourceGroup, machineID, powerProfile string) error {
	return s.call("add:" + resourceGroup + ":" + machineID + ":" + powerProfile)
}

func (s *powerProvisionerStub) UpdateMachineProfile(_ context.Context, resourceGroup, machineID, powerProfile string) error {
	return s.call("update:" + resourceGroup + ":" + machineID + ":" + powerProfile)
}

func (s *powerProvisionerStub) RemoveMachine(_ context.Context, resourceGroup, machineID string) error {
	return s.call("remove:" + resourceGroup + ":" + machineID)
}

func (s *powerProvisionerStub) ActivateResourceGroup(_ context.Context, resourceGroup string) error {
	return s.call("activate:" + resourceGroup)
}

func joinMachineIDs(machineIDs []string) string {
	result := ""
	for i, machineID := range machineIDs {
		if i > 0 {
			result += ","
		}
		result += machineID
	}
	return result
}

func TestProvisionMachinePower(t *testing.T) {
	t.Run("authorizes before mutation and compensates", func(t *testing.T) {
		stub := &powerProvisionerStub{}
		rollback, err := provisionMachinePower(context.Background(), stub, "group-a", machinePowerAssignment{
			machineID:    "machine-a",
			powerProfile: "performance",
		})
		require.NoError(t, err)
		require.NotNil(t, rollback)
		require.NoError(t, rollback())
		assert.Equal(t, []string{
			"validate:performance:machine-a",
			"add:group-a:machine-a:performance",
			"activate:group-a",
			"remove:group-a:machine-a",
		}, stub.calls)
	})

	t.Run("cleans up failed activation", func(t *testing.T) {
		stub := &powerProvisionerStub{failAt: map[string]error{"activate:group-a": errors.New("denied")}}
		rollback, err := provisionMachinePower(context.Background(), stub, "group-a", machinePowerAssignment{machineID: "machine-a"})
		require.ErrorContains(t, err, "activate DPS resource group")
		assert.Nil(t, rollback)
		assert.Equal(t, []string{
			"add:group-a:machine-a:",
			"activate:group-a",
			"remove:group-a:machine-a",
		}, stub.calls)
	})
}

func TestProvisionMachineBatchPower(t *testing.T) {
	t.Run("authorizes before mutation and compensates", func(t *testing.T) {
		stub := &powerProvisionerStub{}
		rollback, err := provisionMachineBatchPower(context.Background(), stub, "group-a", []machinePowerAssignment{
			{machineID: "machine-a", powerProfile: "performance"},
			{machineID: "machine-b", powerProfile: "performance"},
		})
		require.NoError(t, err)
		require.NotNil(t, rollback)
		require.NoError(t, rollback())
		assert.Equal(t, []string{
			"validate:performance:machine-a,machine-b",
			"add:group-a:machine-a:performance",
			"add:group-a:machine-b:performance",
			"activate:group-a",
			"remove:group-a:machine-b",
			"remove:group-a:machine-a",
		}, stub.calls)
	})

	t.Run("does not mutate after rejected preflight", func(t *testing.T) {
		stub := &powerProvisionerStub{failAt: map[string]error{
			"validate:performance:machine-a,machine-b": errors.New("denied"),
		}}
		rollback, err := provisionMachineBatchPower(context.Background(), stub, "group-a", []machinePowerAssignment{
			{machineID: "machine-a", powerProfile: "performance"},
			{machineID: "machine-b", powerProfile: "performance"},
		})
		require.ErrorContains(t, err, "validate DPS batch allocation")
		assert.Nil(t, rollback)
		assert.Equal(t, []string{"validate:performance:machine-a,machine-b"}, stub.calls)
	})
}

func TestUpdateMachinePowerTreatsClearAsDPSAuthorizedMutation(t *testing.T) {
	stub := &powerProvisionerStub{}
	rollback, err := updateMachinePower(context.Background(), stub, "group-a", machinePowerAssignment{machineID: "machine-a"}, "performance")
	require.NoError(t, err)
	require.NoError(t, rollback())
	assert.Equal(t, []string{
		"update:group-a:machine-a:",
		"update:group-a:machine-a:performance",
	}, stub.calls)
}

func TestPreparePowerResourceGroupChange(t *testing.T) {
	t.Run("migrates and completes", func(t *testing.T) {
		stub := &powerProvisionerStub{}
		change, err := preparePowerResourceGroupChange(context.Background(), stub, 42, "group-a", "group-b", []machinePowerAssignment{
			{machineID: "machine-a", powerProfile: "performance"},
			{machineID: "machine-b"},
		})
		require.NoError(t, err)
		require.NoError(t, change.complete())
		assert.Equal(t, []string{
			"validate:performance:machine-a",
			"create:group-b",
			"remove:group-a:machine-a",
			"add:group-b:machine-a:performance",
			"remove:group-a:machine-b",
			"add:group-b:machine-b:",
			"activate:group-b",
			"delete:group-a",
		}, stub.calls)
	})

	t.Run("rolls back prepared migration", func(t *testing.T) {
		stub := &powerProvisionerStub{}
		change, err := preparePowerResourceGroupChange(context.Background(), stub, 42, "group-a", "group-b", []machinePowerAssignment{{machineID: "machine-a", powerProfile: "performance"}})
		require.NoError(t, err)
		require.NoError(t, change.rollback())
		assert.Equal(t, []string{
			"validate:performance:machine-a",
			"create:group-b",
			"remove:group-a:machine-a",
			"add:group-b:machine-a:performance",
			"activate:group-b",
			"remove:group-b:machine-a",
			"add:group-a:machine-a:performance",
			"activate:group-a",
			"delete:group-b",
		}, stub.calls)
	})

	t.Run("validates profiles deterministically", func(t *testing.T) {
		stub := &powerProvisionerStub{failAt: map[string]error{
			"validate:balanced:machine-b": errors.New("denied"),
		}}
		change, err := preparePowerResourceGroupChange(context.Background(), stub, 42, "group-a", "group-b", []machinePowerAssignment{
			{machineID: "machine-a", powerProfile: "performance"},
			{machineID: "machine-b", powerProfile: "balanced"},
		})
		require.ErrorContains(t, err, "validate DPS resource-group migration")
		assert.Nil(t, change)
		assert.Equal(t, []string{"validate:balanced:machine-b"}, stub.calls)
	})

	t.Run("clears before commit and can roll back", func(t *testing.T) {
		stub := &powerProvisionerStub{}
		change, err := preparePowerResourceGroupChange(context.Background(), stub, 42, "group-a", "", []machinePowerAssignment{
			{machineID: "machine-a", powerProfile: "performance"},
		})
		require.NoError(t, err)
		require.NoError(t, change.rollback())
		assert.Equal(t, []string{
			"remove:group-a:machine-a",
			"add:group-a:machine-a:performance",
			"activate:group-a",
		}, stub.calls)

		stub.calls = nil
		change, err = preparePowerResourceGroupChange(context.Background(), stub, 42, "group-a", "", []machinePowerAssignment{
			{machineID: "machine-a", powerProfile: "performance"},
		})
		require.NoError(t, err)
		require.NoError(t, change.complete())
		assert.Equal(t, []string{
			"remove:group-a:machine-a",
			"delete:group-a",
		}, stub.calls)
	})
}
