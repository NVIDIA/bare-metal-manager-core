// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nico is the rack manager implementation. It drives a whole rack as a
// single unit through NICo Core's Component Manager dispatch, handing Core the
// rack id instead of Flow expanding the rack into per-component (compute /
// nvswitch / powershelf) targets. It is selected for rack-scoped power and
// firmware operations when whole-rack RMS mode is enabled.
//
// The Core Component Manager RPCs (ComponentPowerControl,
// UpdateComponentFirmware, GetComponentFirmwareStatus) do not yet carry a
// rack-ids target variant in their oneof; that variant lands in a future Core
// proto release. The operation mapping (power operation -> SystemPowerControl,
// firmware sub-target handling) is wired here so that enabling the rack target
// after the proto update is a one-line change at each dispatch point plus a
// gRPC regeneration. Until then the rack dispatch points return
// errRackTargetPendingCoreProto so the RMS path fails loudly rather than
// silently sending a target-less request.
package nico

import (
	"context"
	"errors"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
	pb "github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi/gen"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/componentmanager"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/componentmanager/capability"
	cmcatalog "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/componentmanager/catalog"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/componentmanager/providerapi"
	nicoprovider "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/componentmanager/providers/nico"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

// ImplementationName is the name used to identify this implementation in the
// component manager catalog and in YAML / env configuration.
const ImplementationName = "nico"

// errRackTargetPendingCoreProto is returned by the rack dispatch points until
// Core's Component Manager RPCs gain a rack-ids target variant. See the
// package doc for the migration step.
var errRackTargetPendingCoreProto = errors.New(
	"rack component manager dispatch pending Core Component Manager rack target",
)

// Manager drives a whole rack through NICo Core's Component Manager RPCs.
// Unlike the per-component managers it does not consult a readiness gate:
// rack readiness is owned by Core when the rack is handed over as a unit.
type Manager struct {
	nicoClient nicoapi.Client
}

// New creates a rack Manager backed by the supplied NICo client.
func New(nicoClient nicoapi.Client) *Manager {
	return &Manager{nicoClient: nicoClient}
}

// Factory returns a factory that resolves the NICo provider's client.
func Factory() componentmanager.ManagerFactory {
	return func(
		providerRegistry *providerapi.ProviderRegistry,
	) (componentmanager.ComponentManager, error) {
		provider, err := providerapi.GetTyped[*nicoprovider.Provider](
			providerRegistry,
			nicoprovider.ProviderName,
		)
		if err != nil {
			return nil, fmt.Errorf("rack/nico requires nico provider: %w", err)
		}
		return New(provider.Client()), nil
	}
}

// Descriptor returns the rack/nico manager descriptor.
func Descriptor() cmcatalog.Descriptor {
	return cmcatalog.Descriptor{
		DescriptorIdentity: cmcatalog.DescriptorIdentity{
			Type:           devicetypes.ComponentTypeRack,
			Implementation: ImplementationName,
		},
		RequiredProviders: []string{nicoprovider.ProviderName},
		Capabilities: capability.CapabilitySet{
			capability.CapabilityFirmwareControl,
			capability.CapabilityFirmwareStatus,
			capability.CapabilityPowerControl,
		},
	}
}

// FactorySpec returns the rack/nico runtime factory spec.
func FactorySpec() componentmanager.FactorySpec {
	return componentmanager.FactorySpec{
		Descriptor: Descriptor(),
		Factory:    Factory(),
	}
}

// Descriptor returns the rack/nico manager descriptor.
func (m *Manager) Descriptor() cmcatalog.Descriptor {
	return Descriptor()
}

// powerActionFromOperation maps a Flow power operation to the Core
// SystemPowerControl enum. The mapping mirrors the per-component managers so
// rack power control follows the same semantics.
func powerActionFromOperation(op operations.PowerOperation) (pb.SystemPowerControl, error) {
	switch op {
	case operations.PowerOperationPowerOn, operations.PowerOperationForcePowerOn:
		return pb.SystemPowerControl_SYSTEM_POWER_CONTROL_ON, nil
	case operations.PowerOperationPowerOff:
		return pb.SystemPowerControl_SYSTEM_POWER_CONTROL_GRACEFUL_SHUTDOWN, nil
	case operations.PowerOperationForcePowerOff:
		return pb.SystemPowerControl_SYSTEM_POWER_CONTROL_FORCE_OFF, nil
	case operations.PowerOperationRestart, operations.PowerOperationWarmReset:
		return pb.SystemPowerControl_SYSTEM_POWER_CONTROL_GRACEFUL_RESTART, nil
	case operations.PowerOperationForceRestart:
		return pb.SystemPowerControl_SYSTEM_POWER_CONTROL_FORCE_RESTART, nil
	case operations.PowerOperationColdReset:
		return pb.SystemPowerControl_SYSTEM_POWER_CONTROL_AC_POWERCYCLE, nil
	default:
		return 0, fmt.Errorf("unsupported power operation for rack: %v", op)
	}
}

// PowerControl performs a power operation on the whole rack via Core's
// ComponentPowerControl RPC with a rack target.
func (m *Manager) PowerControl(
	ctx context.Context,
	target common.Target,
	info operations.PowerControlTaskInfo,
) error {
	if err := target.Validate(); err != nil {
		return fmt.Errorf("target is invalid: %w", err)
	}

	if _, err := powerActionFromOperation(info.Operation); err != nil {
		return err
	}

	// TODO: once Core's ComponentPowerControlRequest target oneof gains a
	// rack-ids variant, build the request with the rack id(s) in
	// target.ComponentIDs, set Action to powerActionFromOperation(info.Operation),
	// set BypassStateController from info.OverrideReadinessCheck, call
	// m.nicoClient.ComponentPowerControl, and check the per-result status the
	// same way compute/nvswitch/powershelf do. Remove the sentinel below.
	return errRackTargetPendingCoreProto
}

// FirmwareControl schedules a firmware update for the whole rack via Core's
// UpdateComponentFirmware RPC with a rack target.
func (m *Manager) FirmwareControl(
	ctx context.Context,
	target common.Target,
	info operations.FirmwareControlTaskInfo,
) error {
	if err := target.Validate(); err != nil {
		return fmt.Errorf("target is invalid: %w", err)
	}

	// TODO: once Core's UpdateComponentFirmwareRequest target oneof gains a
	// rack variant, build the request with the rack id(s) and
	// info.TargetVersion, call m.nicoClient.UpdateComponentFirmware, and check
	// the per-result status. Remove the sentinel below.
	return errRackTargetPendingCoreProto
}

// GetFirmwareStatus returns the firmware update status for the rack. The
// rule-driven firmware action polls this after FirmwareControl, so the rack
// manager must expose it.
func (m *Manager) GetFirmwareStatus(
	ctx context.Context,
	target common.Target,
) (map[string]operations.FirmwareUpdateStatus, error) {
	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("target is invalid: %w", err)
	}

	// TODO: once Core's GetComponentFirmwareStatusRequest target oneof gains a
	// rack variant, query m.nicoClient.GetComponentFirmwareStatus and aggregate
	// the per-rack statuses. Remove the sentinel below.
	return nil, errRackTargetPendingCoreProto
}
