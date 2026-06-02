// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package leakdetection

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/operation"
	taskmanager "github.com/NVIDIA/infra-controller-rest/flow/internal/task/manager"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

// Query core to get IDs of leaking machines and submit power-off tasks for each
func runLeakDetectionOneMachine(
	ctx context.Context,
	nicoClient nicoapi.Client,
	taskMgr taskmanager.Manager,
) {
	log.Info().Msg("Running leak detection for machines")

	leakingMachineIds, err := nicoClient.GetLeakingMachineIds(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Unable to retrieve leaking machine IDs from NICo")
		return
	}

	log.Info().Msgf("Found %d leaking machine IDs", len(leakingMachineIds))

	for _, machineID := range leakingMachineIds {
		log.Info().Msgf("Leaking machine ID: %s, submitting force power-off task", machineID)

		err := submitPowerOffTask(ctx, taskMgr, machineID, devicetypes.ComponentTypeCompute)
		if err != nil {
			log.Error().Err(err).Str("machine_id", machineID).
				Msg("Failed to submit power-off task for leaking machine")
		}
	}
}

// Query core to get IDs of leaking switches and submit power-off tasks for each
func runLeakDetectionOneSwitch(
	ctx context.Context,
	nicoClient nicoapi.Client,
	taskMgr taskmanager.Manager,
) {
	log.Info().Msg("Running leak detection for switches")

	leakingSwitchIds, err := nicoClient.GetLeakingSwitchIds(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Unable to retrieve leaking switch IDs from NICo")
		return
	}

	log.Info().Msgf("Found %d leaking switch IDs", len(leakingSwitchIds))

	for _, switchID := range leakingSwitchIds {
		log.Info().Msgf("Leaking switch ID: %s, submitting force power-off task", switchID)

		err := submitPowerOffTask(ctx, taskMgr, switchID, devicetypes.ComponentTypeNVSwitch)
		if err != nil {
			log.Error().Err(err).Str("switch_id", switchID).
				Msg("Failed to submit power-off task for leaking switch")
		}
	}
}

func runLeakDetectionOne(
	ctx context.Context,
	nicoClient nicoapi.Client,
	taskMgr taskmanager.Manager,
) {
	log.Info().Msg("Running leak detection")

	runLeakDetectionOneMachine(ctx, nicoClient, taskMgr)
	runLeakDetectionOneSwitch(ctx, nicoClient, taskMgr)
}

func submitPowerOffTask(
	ctx context.Context,
	taskMgr taskmanager.Manager,
	componentExternalId string,
	componentType devicetypes.ComponentType,
) error {
	info := &operations.PowerControlTaskInfo{
		Operation: operations.PowerOperationForcePowerOff,
		Forced:    true,
	}

	raw, err := info.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal power control info: %w", err)
	}

	req := &operation.Request{
		Operation: operation.Wrapper{
			Type: info.Type(),
			Code: info.CodeString(),
			Info: raw,
		},
		TargetSpec: operation.TargetSpec{
			Components: []operation.ComponentTarget{
				{
					External: &operation.ExternalRef{
						Type: componentType,
						ID:   componentExternalId,
					},
				},
			},
		},
		Description:      fmt.Sprintf("Leak detection: force power-off component %s of type %s", componentExternalId, componentType.String()),
		ConflictStrategy: operation.ConflictStrategyQueue,
	}

	taskIDs, err := taskMgr.SubmitTask(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to submit task: %w", err)
	}

	if len(taskIDs) == 0 {
		return fmt.Errorf("failed to create any power-off tasks for leaking component %s of type %s", componentExternalId, componentType.String())
	}

	log.Info().
		Str("component_external_id", componentExternalId).
		Str("component_type", componentType.String()).
		Int("task_count", len(taskIDs)).
		Msg("Power-off task submitted for leaking component")

	return nil
}
