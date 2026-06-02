// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package psm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/psmapi"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/capability"
	cmcatalog "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/catalog"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providerapi"
	psmprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/psm"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/firmwarecomponents"
)

const (
	// ImplementationName is the name used to identify this implementation.
	ImplementationName = "psm"
)

// Manager manages power shelf components via the PSM service.
type Manager struct {
	psmClient psmapi.Client
}

// New creates a new PSM-based PowerShelf Manager instance.
func New(psmClient psmapi.Client) *Manager {
	return &Manager{
		psmClient: psmClient,
	}
}

// Factory creates a new Manager from the provided providers.
// It retrieves the PSMProvider from the registry and uses its client.
func Factory(
	providerRegistry *providerapi.ProviderRegistry,
) (componentmanager.ComponentManager, error) {
	provider, err := providerapi.GetTyped[*psmprovider.Provider](
		providerRegistry,
		psmprovider.ProviderName,
	)
	if err != nil {
		return nil, fmt.Errorf("powershelf/psm requires psm provider: %w", err)
	}

	return New(provider.Client()), nil
}

// Descriptor returns the PSM PowerShelf manager descriptor.
func Descriptor() cmcatalog.Descriptor {
	return cmcatalog.Descriptor{
		DescriptorIdentity: cmcatalog.DescriptorIdentity{
			Type:           devicetypes.ComponentTypePowerShelf,
			Implementation: ImplementationName,
		},
		RequiredProviders: []string{psmprovider.ProviderName},
		Capabilities: capability.CapabilitySet{
			capability.CapabilityFirmwareControl,
			capability.CapabilityFirmwareStatus,
			capability.CapabilityInjectExpectation,
			capability.CapabilityPowerControl,
			capability.CapabilityPowerStatus,
		},
	}
}

// FactorySpec returns the PSM PowerShelf manager runtime factory spec.
func FactorySpec() componentmanager.FactorySpec {
	return componentmanager.FactorySpec{
		Descriptor: Descriptor(),
		Factory:    Factory,
	}
}

// Descriptor returns the PSM PowerShelf manager descriptor.
func (m *Manager) Descriptor() cmcatalog.Descriptor {
	return Descriptor()
}

// InjectExpectation injects expected information for a power shelf.
func (m *Manager) InjectExpectation(
	ctx context.Context,
	target common.Target,
	info operations.InjectExpectationTaskInfo,
) error {
	// InjectExpectation is used to register expected powershelves
	// The Info field should contain registration details
	var regReq psmapi.RegisterPowershelfRequest
	if err := json.Unmarshal(info.Info, &regReq); err != nil {
		return fmt.Errorf("failed to unmarshal RegisterPowershelfRequest: %w", err)
	}

	if m.psmClient == nil {
		return fmt.Errorf("psm client is not configured")
	}

	responses, err := m.psmClient.RegisterPowershelves(ctx, []psmapi.RegisterPowershelfRequest{regReq})
	if err != nil {
		return fmt.Errorf("failed to register powershelf: %w", err)
	}

	for _, response := range responses {
		if response.Status != psmapi.StatusSuccess {
			return fmt.Errorf("failed to register powershelf: %s", response.Error)
		} else {
			log.Info().
				Str("pmc_mac", regReq.PMCMACAddress).
				Bool("is_new", response.IsNew).
				Msg("Successfully registered powershelf")
		}
	}

	return nil
}

// PowerControl performs power operations on a power shelf via PSM API.
func (m *Manager) PowerControl(
	ctx context.Context,
	target common.Target,
	info operations.PowerControlTaskInfo,
) error {
	log.Debug().
		Str("components", target.String()).
		Str("operation", info.Operation.String()).
		Msg("Power control request received")

	if m.psmClient == nil {
		return fmt.Errorf("psm client is not configured")
	}

	if err := target.Validate(); err != nil {
		return fmt.Errorf("target is invalid: %w", err)
	}

	// The component IDs are the PMC MAC addresses for Powershelves.
	pmcMacs := target.ComponentIDs

	var results []psmapi.PowerControlResult
	var err error
	switch info.Operation {
	// Powershelves do not distinguish between a graceful & forced power on
	// Other component make this distinction (e.g. compute nodes)
	case operations.PowerOperationPowerOn, operations.PowerOperationForcePowerOn:
		results, err = m.psmClient.PowerOn(ctx, pmcMacs)
	// Powershelves do not distinguish between a graceful & forced power off
	// Other component make this distinction (e.g. compute nodes)
	case operations.PowerOperationPowerOff, operations.PowerOperationForcePowerOff:
		results, err = m.psmClient.PowerOff(ctx, pmcMacs)
	default:
		return fmt.Errorf("unsupported power operation: %v", info.Operation)
	}

	if err != nil {
		return fmt.Errorf("power control operation failed: %w", err)
	}

	for _, result := range results {
		if result.Status != psmapi.StatusSuccess {
			return fmt.Errorf("power control operation failed for %s: %s", result.PMCMACAddress, result.Error)
		} else {
			log.Info().
				Str("pmc_mac", result.PMCMACAddress).
				Str("operation", info.Operation.String()).
				Msg("Power control operation completed successfully")
		}
	}

	return nil
}

// GetPowerStatus retrieves the power status of power shelves via PSM API.
func (m *Manager) GetPowerStatus(
	ctx context.Context,
	target common.Target,
) (map[string]operations.PowerStatus, error) {
	log.Debug().
		Str("components", target.String()).
		Msg("Get power status request received")

	if m.psmClient == nil {
		return nil, fmt.Errorf("psm client is not configured")
	}

	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("target is invalid: %w", err)
	}

	// The component IDs are the PMC MAC addresses for Powershelves.
	pmcMacs := target.ComponentIDs

	powershelves, err := m.psmClient.GetPowershelves(ctx, pmcMacs)
	if err != nil {
		return nil, fmt.Errorf("failed to get powershelves: %w", err)
	}

	result := make(map[string]operations.PowerStatus, len(powershelves))
	for _, ps := range powershelves {
		result[ps.PMC.MACAddress] = powerShelfToPowerStatus(ps)
	}

	log.Info().
		Str("components", target.String()).
		Int("result_count", len(result)).
		Msg("Get power status completed")

	return result, nil
}

// powerShelfToPowerStatus determines the power status of a powershelf based on its PSU states.
func powerShelfToPowerStatus(ps psmapi.PowerShelf) operations.PowerStatus {
	if len(ps.PSUs) == 0 {
		return operations.PowerStatusUnknown
	}

	// Check PSU power states
	allOn := true
	allOff := true
	for _, psu := range ps.PSUs {
		if psu.PowerState {
			allOff = false
		} else {
			allOn = false
		}
	}

	// All PSUs are on
	if allOn {
		return operations.PowerStatusOn
	}

	// All PSUs are off
	if allOff {
		return operations.PowerStatusOff
	}

	// Mix of on/off PSUs
	return operations.PowerStatusUnknown
}

// GetPowershelf retrieves detailed powershelf information by PMC MAC address.
func (m *Manager) GetPowershelf(ctx context.Context, pmcMac string) (*psmapi.PowerShelf, error) {
	if m.psmClient == nil {
		return nil, fmt.Errorf("psm client is not configured")
	}

	powershelves, err := m.psmClient.GetPowershelves(ctx, []string{pmcMac})
	if err != nil {
		return nil, fmt.Errorf("failed to get powershelf: %w", err)
	}

	if len(powershelves) == 0 {
		return nil, fmt.Errorf("powershelf not found: %s", pmcMac)
	}

	return &powershelves[0], nil
}

// GetAllPowershelves retrieves all registered powershelves.
func (m *Manager) GetAllPowershelves(ctx context.Context) ([]psmapi.PowerShelf, error) {
	if m.psmClient == nil {
		return nil, fmt.Errorf("psm client is not configured")
	}

	return m.psmClient.GetPowershelves(ctx, nil)
}

// ListAvailableFirmware returns available firmware versions for the specified powershelves.
func (m *Manager) ListAvailableFirmware(ctx context.Context, pmcMacs []string) ([]psmapi.AvailableFirmware, error) {
	if m.psmClient == nil {
		return nil, fmt.Errorf("psm client is not configured")
	}

	return m.psmClient.ListAvailableFirmware(ctx, pmcMacs)
}

// FirmwareControl initiates firmware update without waiting for completion.
// Returns immediately after the update request is accepted.
//
// info.SubTargets, when non-empty, restricts the update to the selected
// firmware sub-parts (e.g. ["pmc", "psu"]). Empty defaults to ["pmc"],
// which preserves the historical PSM behavior.
func (m *Manager) FirmwareControl(ctx context.Context, target common.Target, info operations.FirmwareControlTaskInfo) error {
	log.Debug().
		Str("components", target.String()).
		Str("operation", fmt.Sprintf("%v", info.Operation)).
		Str("target_version", info.TargetVersion).
		Strs("sub_targets", info.SubTargets).
		Msg("Starting firmware update")

	if m.psmClient == nil {
		return fmt.Errorf("psm client is not configured")
	}

	if err := target.Validate(); err != nil {
		return fmt.Errorf("target is invalid: %w", err)
	}

	subComponents, err := firmwarecomponents.ParsePSMPowerShelf(info.SubTargets)
	if err != nil {
		return err
	}
	if len(subComponents) == 0 {
		subComponents = []psmapi.PowershelfComponent{psmapi.PowershelfComponentPMC}
	}

	pmcMacs := target.ComponentIDs

	componentReqs := make([]psmapi.UpdateComponentFirmwareRequest, 0, len(subComponents))
	for _, c := range subComponents {
		componentReqs = append(componentReqs, psmapi.UpdateComponentFirmwareRequest{
			Component: c,
			UpgradeTo: psmapi.FirmwareVersion{Version: info.TargetVersion},
		})
	}

	updateReqs := make([]psmapi.UpdatePowershelfFirmwareRequest, 0, len(pmcMacs))
	for _, componentID := range pmcMacs {
		updateReqs = append(
			updateReqs,
			psmapi.UpdatePowershelfFirmwareRequest{
				PMCMACAddress: componentID,
				Components:    componentReqs,
			},
		)
	}

	responses, err := m.psmClient.UpdateFirmware(ctx, updateReqs)
	if err != nil {
		return fmt.Errorf("firmware update request failed: %w", err)
	}

	// Check if the request was accepted
	for _, response := range responses {
		for _, component := range response.Components {
			if component.Status != psmapi.StatusSuccess {
				return fmt.Errorf("firmware update request failed for %s: %s", response.PMCMACAddress, component.Error)
			}
			log.Info().
				Str("pmc_mac", response.PMCMACAddress).
				Str("component", component.Component.String()).
				Str("target_version", info.TargetVersion).
				Msg("Firmware update initiated successfully")
		}
	}

	return nil
}

// GetFirmwareStatus returns the current status of firmware updates for the target components.
// Returns a map of component ID to FirmwareUpdateStatus.
func (m *Manager) GetFirmwareStatus(ctx context.Context, target common.Target) (map[string]operations.FirmwareUpdateStatus, error) {
	log.Debug().
		Str("components", target.String()).
		Msg("Getting firmware update status")

	if m.psmClient == nil {
		return nil, fmt.Errorf("psm client is not configured")
	}

	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("target is invalid: %w", err)
	}

	pmcMacs := target.ComponentIDs

	// Query firmware update status for each component
	queries := make([]psmapi.FirmwareUpdateQuery, 0, len(pmcMacs))
	for _, componentID := range pmcMacs {
		queries = append(queries, psmapi.FirmwareUpdateQuery{
			PMCMACAddress: componentID,
			Component:     psmapi.PowershelfComponentPMC,
		})
	}

	statuses, err := m.psmClient.GetFirmwareUpdateStatus(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf("failed to get firmware update status: %w", err)
	}

	// Convert PSM statuses to operations.FirmwareUpdateStatus
	result := make(map[string]operations.FirmwareUpdateStatus, len(statuses))
	for _, status := range statuses {
		state := operations.FirmwareUpdateStateUnknown
		errorMsg := ""

		switch status.State {
		case psmapi.FirmwareUpdateStateQueued:
			state = operations.FirmwareUpdateStateQueued
		case psmapi.FirmwareUpdateStateVerifying:
			state = operations.FirmwareUpdateStateVerifying
		case psmapi.FirmwareUpdateStateCompleted:
			state = operations.FirmwareUpdateStateCompleted
		case psmapi.FirmwareUpdateStateFailed:
			state = operations.FirmwareUpdateStateFailed
			errorMsg = status.Error
		case psmapi.FirmwareUpdateStateUnknown:
			state = operations.FirmwareUpdateStateUnknown
		}

		result[status.PMCMACAddress] = operations.FirmwareUpdateStatus{
			ComponentID: status.PMCMACAddress,
			State:       state,
			Error:       errorMsg,
		}
	}

	log.Info().
		Int("count", len(result)).
		Msg("Retrieved firmware update statuses")

	return result, nil
}
