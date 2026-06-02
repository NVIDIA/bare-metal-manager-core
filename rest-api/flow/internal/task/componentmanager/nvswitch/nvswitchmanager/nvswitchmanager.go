// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nvswitchmanager

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/nsmapi"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/capability"
	cmcatalog "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/catalog"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providerapi"
	nsmprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/nvswitchmanager"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/firmwarecomponents"
)

const (
	// ImplementationName is the name used to identify this implementation.
	ImplementationName = "nvswitchmanager"
)

// Manager manages NVLink switch components via the NV-Switch Manager gRPC API.
type Manager struct {
	nsmClient nsmapi.Client
}

// New creates a new NV-Switch Manager-based NVSwitch Manager instance.
func New(nsmClient nsmapi.Client) *Manager {
	return &Manager{
		nsmClient: nsmClient,
	}
}

// Factory creates a new Manager from the provided providers.
// It retrieves the NVSwitchManager provider from the registry and uses its client.
func Factory(providerRegistry *providerapi.ProviderRegistry) (componentmanager.ComponentManager, error) {
	provider, err := providerapi.GetTyped[*nsmprovider.Provider](
		providerRegistry,
		nsmprovider.ProviderName,
	)
	if err != nil {
		return nil, fmt.Errorf("nvswitch/nvswitchmanager requires nvswitchmanager provider: %w", err)
	}

	return New(provider.Client()), nil
}

// Descriptor returns the NV-Switch Manager NVSwitch manager descriptor.
func Descriptor() cmcatalog.Descriptor {
	return cmcatalog.Descriptor{
		DescriptorIdentity: cmcatalog.DescriptorIdentity{
			Type:           devicetypes.ComponentTypeNVSwitch,
			Implementation: ImplementationName,
		},
		RequiredProviders: []string{nsmprovider.ProviderName},
		Capabilities: capability.CapabilitySet{
			capability.CapabilityFirmwareControl,
			capability.CapabilityFirmwareStatus,
			capability.CapabilityPowerControl,
		},
	}
}

// FactorySpec returns the NV-Switch Manager NVSwitch manager runtime factory
// spec.
func FactorySpec() componentmanager.FactorySpec {
	return componentmanager.FactorySpec{
		Descriptor: Descriptor(),
		Factory:    Factory,
	}
}

// Descriptor returns the NV-Switch Manager NVSwitch manager descriptor.
func (m *Manager) Descriptor() cmcatalog.Descriptor {
	return Descriptor()
}

// PowerControl performs power operations on NVLink switches via the NV-Switch Manager API.
func (m *Manager) PowerControl(
	ctx context.Context,
	target common.Target,
	info operations.PowerControlTaskInfo,
) error {
	log.Debug().Msgf(
		"NVSwitch (nvswitchmanager) power control %s op %s activity received",
		target.String(),
		info.Operation.String(),
	)

	if m.nsmClient == nil {
		return fmt.Errorf("NV-Switch Manager client is not configured")
	}

	if err := target.Validate(); err != nil {
		return fmt.Errorf("target is invalid: %w", err)
	}

	action, err := mapPowerOperation(info.Operation)
	if err != nil {
		return err
	}

	results, err := m.nsmClient.PowerControl(ctx, target.ComponentIDs, action)
	if err != nil {
		return fmt.Errorf("failed to perform power control via NV-Switch Manager: %w", err)
	}

	for _, result := range results {
		if result.Status != nsmapi.StatusSuccess {
			return fmt.Errorf("power control failed for switch %s: %s", result.UUID, result.Error)
		}
	}

	log.Info().Msgf("power control %s on %s completed via NV-Switch Manager",
		info.Operation.String(), target.String())

	return nil
}

// mapPowerOperation maps Flow's PowerOperation to NV-Switch Manager's PowerAction.
func mapPowerOperation(op operations.PowerOperation) (nsmapi.PowerAction, error) {
	switch op {
	case operations.PowerOperationPowerOn:
		return nsmapi.PowerActionOn, nil
	case operations.PowerOperationForcePowerOn:
		return nsmapi.PowerActionForceOn, nil
	case operations.PowerOperationPowerOff:
		return nsmapi.PowerActionGracefulShutdown, nil
	case operations.PowerOperationForcePowerOff:
		return nsmapi.PowerActionForceOff, nil
	case operations.PowerOperationRestart:
		return nsmapi.PowerActionGracefulRestart, nil
	case operations.PowerOperationForceRestart:
		return nsmapi.PowerActionForceRestart, nil
	case operations.PowerOperationWarmReset:
		log.Warn().Msg("NV-Switch Manager does not distinguish warm/cold reset; using PowerCycle")
		return nsmapi.PowerActionPowerCycle, nil
	case operations.PowerOperationColdReset:
		log.Warn().Msg("NV-Switch Manager does not distinguish warm/cold reset; using PowerCycle")
		return nsmapi.PowerActionPowerCycle, nil
	default:
		return nsmapi.PowerActionUnknown, fmt.Errorf("unknown power operation: %v", op)
	}
}

// FirmwareControl initiates firmware update without waiting for completion.
// Returns immediately after the update request is accepted.
//
// info.SubTargets, when non-empty, restricts the update to the selected
// firmware sub-parts (e.g. ["bmc", "nvos"]). Empty means "all components
// in the bundle" (NSM's historical default).
func (m *Manager) FirmwareControl(ctx context.Context, target common.Target, info operations.FirmwareControlTaskInfo) error {
	log.Debug().
		Str("components", target.String()).
		Str("operation", fmt.Sprintf("%v", info.Operation)).
		Str("target_version", info.TargetVersion).
		Strs("sub_targets", info.SubTargets).
		Msg("Starting firmware update")

	if m.nsmClient == nil {
		return fmt.Errorf("nsm client is not configured")
	}

	if err := target.Validate(); err != nil {
		return fmt.Errorf("target is invalid: %w", err)
	}

	subComponents, err := firmwarecomponents.ParseNSMNVSwitch(info.SubTargets)
	if err != nil {
		return err
	}

	updates, err := m.nsmClient.QueueUpdates(ctx, target.ComponentIDs, info.TargetVersion, subComponents)
	if err != nil {
		return fmt.Errorf("firmware update request failed: %w", err)
	}

	for _, update := range updates {
		if update.ErrorMessage != "" {
			return fmt.Errorf("firmware update request failed for switch %s: %s", update.SwitchUUID, update.ErrorMessage)
		}
		log.Info().
			Str("switch_uuid", update.SwitchUUID).
			Str("update_id", update.ID).
			Str("target_version", info.TargetVersion).
			Msg("Firmware update initiated successfully")
	}

	return nil
}

// GetFirmwareStatus returns the current status of firmware updates for the target components.
// Returns a map of component ID (switch UUID) to FirmwareUpdateStatus.
func (m *Manager) GetFirmwareStatus(ctx context.Context, target common.Target) (map[string]operations.FirmwareUpdateStatus, error) {
	log.Debug().
		Str("components", target.String()).
		Msg("Getting firmware update status")

	if m.nsmClient == nil {
		return nil, fmt.Errorf("nsm client is not configured")
	}

	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("target is invalid: %w", err)
	}

	result := make(map[string]operations.FirmwareUpdateStatus, len(target.ComponentIDs))
	for _, switchUUID := range target.ComponentIDs {
		updates, err := m.nsmClient.GetUpdates(ctx, switchUUID)
		if err != nil {
			return nil, fmt.Errorf("failed to get firmware update status for switch %s: %w", switchUUID, err)
		}

		aggregatedUpdateStatus := aggregateUpdateStatuses(switchUUID, updates)
		result[switchUUID] = aggregatedUpdateStatus
	}

	log.Info().
		Int("count", len(result)).
		Msg("Retrieved firmware update statuses")

	return result, nil
}

// aggregateUpdateStatuses examines all sub-component firmware updates for a switch
// and produces a single FirmwareUpdateStatus. If any sub-component failed or was
// cancelled the overall status is Failed with a message listing each one.
func aggregateUpdateStatuses(switchUUID string, updates []nsmapi.FirmwareUpdateInfo) operations.FirmwareUpdateStatus {
	if len(updates) == 0 {
		return operations.FirmwareUpdateStatus{
			ComponentID: switchUUID,
			State:       operations.FirmwareUpdateStateUnknown,
		}
	}

	allCompleted := true
	var failures []string

	for _, u := range updates {
		mapped := mapUpdateState(u.State)
		switch mapped {
		case operations.FirmwareUpdateStateFailed:
			if u.State == nsmapi.UpdateStateCancelled {
				failures = append(failures, fmt.Sprintf("%s: cancelled", u.Component.String()))
			} else {
				failures = append(failures, fmt.Sprintf("%s: %s", u.Component.String(), u.ErrorMessage))
			}
		case operations.FirmwareUpdateStateCompleted:
			// ok
		default:
			allCompleted = false
		}
	}

	if len(failures) > 0 {
		return operations.FirmwareUpdateStatus{
			ComponentID: switchUUID,
			State:       operations.FirmwareUpdateStateFailed,
			Error:       fmt.Sprintf("firmware update failed for components: %s", strings.Join(failures, "; ")),
		}
	}

	if allCompleted {
		return operations.FirmwareUpdateStatus{
			ComponentID: switchUUID,
			State:       operations.FirmwareUpdateStateCompleted,
		}
	}

	return operations.FirmwareUpdateStatus{
		ComponentID: switchUUID,
		State:       operations.FirmwareUpdateStateQueued,
	}
}

func mapUpdateState(state nsmapi.UpdateState) operations.FirmwareUpdateState {
	switch state {
	case nsmapi.UpdateStateQueued, nsmapi.UpdateStatePowerCycle, nsmapi.UpdateStateWaitReachable,
		nsmapi.UpdateStateCopy, nsmapi.UpdateStateUpload, nsmapi.UpdateStateInstall,
		nsmapi.UpdateStatePollCompletion, nsmapi.UpdateStateCleanup:
		return operations.FirmwareUpdateStateQueued
	case nsmapi.UpdateStateVerify:
		return operations.FirmwareUpdateStateVerifying
	case nsmapi.UpdateStateCompleted:
		return operations.FirmwareUpdateStateCompleted
	case nsmapi.UpdateStateFailed, nsmapi.UpdateStateCancelled:
		return operations.FirmwareUpdateStateFailed
	default:
		return operations.FirmwareUpdateStateUnknown
	}
}
