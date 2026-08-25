// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	dpsclient "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/dps"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
)

type machinePowerAssignment struct {
	machineID    string
	powerProfile string
}

type powerChange struct {
	rollback func() error
	complete func() error
}

func acquireVPCPowerLock(ctx context.Context, tx *cdb.Tx, vpcID uuid.UUID) error {
	return tx.TryAcquireAdvisoryLock(ctx, cdb.GetAdvisoryLockIDFromString("dps-vpc:"+vpcID.String()), nil)
}

func provisionMachinePower(ctx context.Context, provisioner dpsclient.PowerProvisioner, resourceGroup string, assignment machinePowerAssignment) (func() error, error) {
	if provisioner == nil {
		return nil, fmt.Errorf("DPS power provisioner is unavailable")
	}
	resourceGroup = strings.TrimSpace(resourceGroup)
	if resourceGroup == "" {
		return nil, fmt.Errorf("VPC power resource group is required")
	}
	assignment.machineID = strings.TrimSpace(assignment.machineID)
	assignment.powerProfile = strings.TrimSpace(assignment.powerProfile)

	if assignment.powerProfile != "" {
		err := provisioner.ValidateAllocation(ctx, []string{assignment.machineID}, assignment.powerProfile)
		if err != nil {
			return nil, fmt.Errorf("validate DPS allocation: %w", err)
		}
	}
	err := provisioner.AddMachine(ctx, resourceGroup, assignment.machineID, assignment.powerProfile)
	if err != nil {
		return nil, fmt.Errorf("add machine to DPS resource group: %w", err)
	}
	err = provisioner.ActivateResourceGroup(ctx, resourceGroup)
	if err != nil {
		cleanupErr := provisioner.RemoveMachine(context.WithoutCancel(ctx), resourceGroup, assignment.machineID)
		return nil, errors.Join(fmt.Errorf("activate DPS resource group: %w", err), cleanupErr)
	}

	return func() error {
		return provisioner.RemoveMachine(context.WithoutCancel(ctx), resourceGroup, assignment.machineID)
	}, nil
}

func provisionMachineBatchPower(ctx context.Context, provisioner dpsclient.PowerProvisioner, resourceGroup string, assignments []machinePowerAssignment) (func() error, error) {
	if provisioner == nil {
		return nil, fmt.Errorf("DPS power provisioner is unavailable")
	}
	resourceGroup = strings.TrimSpace(resourceGroup)
	if resourceGroup == "" {
		return nil, fmt.Errorf("VPC power resource group is required")
	}
	if len(assignments) == 0 {
		return nil, nil
	}

	machineIDs := make([]string, 0, len(assignments))
	powerProfile := strings.TrimSpace(assignments[0].powerProfile)
	for i := range assignments {
		assignments[i].machineID = strings.TrimSpace(assignments[i].machineID)
		assignments[i].powerProfile = strings.TrimSpace(assignments[i].powerProfile)
		if assignments[i].powerProfile != powerProfile {
			return nil, fmt.Errorf("DPS batch assignments must use one power profile")
		}
		machineIDs = append(machineIDs, assignments[i].machineID)
	}
	if powerProfile != "" {
		err := provisioner.ValidateAllocation(ctx, machineIDs, powerProfile)
		if err != nil {
			return nil, fmt.Errorf("validate DPS batch allocation: %w", err)
		}
	}

	added := make([]machinePowerAssignment, 0, len(assignments))
	rollback := func() error {
		var rollbackErr error
		rollbackCtx := context.WithoutCancel(ctx)
		for _, assignment := range slices.Backward(added) {
			rollbackErr = errors.Join(rollbackErr, provisioner.RemoveMachine(rollbackCtx, resourceGroup, assignment.machineID))
		}
		return rollbackErr
	}
	for _, assignment := range assignments {
		err := provisioner.AddMachine(ctx, resourceGroup, assignment.machineID, assignment.powerProfile)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("add machine to DPS resource group: %w", err), rollback())
		}
		added = append(added, assignment)
	}
	err := provisioner.ActivateResourceGroup(ctx, resourceGroup)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("activate DPS resource group: %w", err), rollback())
	}
	return rollback, nil
}

func updateMachinePower(ctx context.Context, provisioner dpsclient.PowerProvisioner, resourceGroup string, assignment machinePowerAssignment, previousProfile string) (func() error, error) {
	if provisioner == nil {
		return nil, fmt.Errorf("DPS power provisioner is unavailable")
	}
	resourceGroup = strings.TrimSpace(resourceGroup)
	if resourceGroup == "" {
		return nil, fmt.Errorf("VPC power resource group is required")
	}
	assignment.machineID = strings.TrimSpace(assignment.machineID)
	assignment.powerProfile = strings.TrimSpace(assignment.powerProfile)
	previousProfile = strings.TrimSpace(previousProfile)

	if assignment.powerProfile != "" {
		err := provisioner.ValidateAllocation(ctx, []string{assignment.machineID}, assignment.powerProfile)
		if err != nil {
			return nil, fmt.Errorf("validate DPS allocation: %w", err)
		}
	}
	err := provisioner.UpdateMachineProfile(ctx, resourceGroup, assignment.machineID, assignment.powerProfile)
	if err != nil {
		return nil, fmt.Errorf("update DPS machine profile: %w", err)
	}

	return func() error {
		return provisioner.UpdateMachineProfile(context.WithoutCancel(ctx), resourceGroup, assignment.machineID, previousProfile)
	}, nil
}

func preparePowerResourceGroupChange(ctx context.Context, provisioner dpsclient.PowerProvisioner, externalID int64, oldGroup, newGroup string, assignments []machinePowerAssignment) (*powerChange, error) {
	if provisioner == nil {
		return nil, fmt.Errorf("DPS power provisioner is unavailable")
	}
	oldGroup = strings.TrimSpace(oldGroup)
	newGroup = strings.TrimSpace(newGroup)
	if oldGroup == newGroup {
		return &powerChange{}, nil
	}

	profiles := make(map[string][]string)
	for i := range assignments {
		assignments[i].machineID = strings.TrimSpace(assignments[i].machineID)
		assignments[i].powerProfile = strings.TrimSpace(assignments[i].powerProfile)
		if newGroup != "" && assignments[i].powerProfile != "" {
			profiles[assignments[i].powerProfile] = append(profiles[assignments[i].powerProfile], assignments[i].machineID)
		}
	}
	profileNames := make([]string, 0, len(profiles))
	for profile := range profiles {
		profileNames = append(profileNames, profile)
	}
	slices.Sort(profileNames)
	for _, profile := range profileNames {
		machineIDs := profiles[profile]
		err := provisioner.ValidateAllocation(ctx, machineIDs, profile)
		if err != nil {
			return nil, fmt.Errorf("validate DPS resource-group migration: %w", err)
		}
	}

	createdNewGroup := false
	if newGroup != "" {
		err := provisioner.CreateResourceGroup(ctx, newGroup, externalID)
		if err != nil {
			return nil, fmt.Errorf("create replacement DPS resource group: %w", err)
		}
		createdNewGroup = true
	}

	moved := make([]machinePowerAssignment, 0, len(assignments))
	rollback := func() error {
		var rollbackErr error
		rollbackCtx := context.WithoutCancel(ctx)
		for _, assignment := range slices.Backward(moved) {
			if newGroup != "" {
				rollbackErr = errors.Join(rollbackErr, provisioner.RemoveMachine(rollbackCtx, newGroup, assignment.machineID))
			}
			if oldGroup != "" {
				rollbackErr = errors.Join(rollbackErr, provisioner.AddMachine(rollbackCtx, oldGroup, assignment.machineID, assignment.powerProfile))
			}
		}
		if oldGroup != "" && len(moved) > 0 {
			rollbackErr = errors.Join(rollbackErr, provisioner.ActivateResourceGroup(rollbackCtx, oldGroup))
		}
		if createdNewGroup {
			rollbackErr = errors.Join(rollbackErr, provisioner.DeleteResourceGroup(rollbackCtx, newGroup))
		}
		return rollbackErr
	}

	for _, assignment := range assignments {
		if oldGroup != "" {
			err := provisioner.RemoveMachine(ctx, oldGroup, assignment.machineID)
			if err != nil {
				return nil, errors.Join(fmt.Errorf("remove machine from previous DPS resource group: %w", err), rollback())
			}
		}
		if newGroup != "" {
			err := provisioner.AddMachine(ctx, newGroup, assignment.machineID, assignment.powerProfile)
			if err != nil {
				var restoreErr error
				if oldGroup != "" {
					restoreErr = provisioner.AddMachine(context.WithoutCancel(ctx), oldGroup, assignment.machineID, assignment.powerProfile)
				}
				return nil, errors.Join(fmt.Errorf("add machine to replacement DPS resource group: %w", err), restoreErr, rollback())
			}
		}
		moved = append(moved, assignment)
	}

	if newGroup != "" && len(assignments) > 0 {
		err := provisioner.ActivateResourceGroup(ctx, newGroup)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("activate replacement DPS resource group: %w", err), rollback())
		}
	}

	complete := func() error {
		if oldGroup == "" {
			return nil
		}
		return provisioner.DeleteResourceGroup(context.WithoutCancel(ctx), oldGroup)
	}
	return &powerChange{rollback: rollback, complete: complete}, nil
}
