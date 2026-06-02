// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nicoapi abstracts the GRPC interface used to communicate with nico-core-api.  New connection pools can be created with
// NewClient to create a real client or NewMockClient which fakes everything for unit tests.

package nicoapi

import (
	"context"
	"time"

	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
)

// Client allow us to have both a real implemenation and a mock implementation for unit tests which can be switched transparently
type Client interface {
	Version(ctx context.Context) (string, error)
	GetMachines(ctx context.Context) ([]MachineDetail, error)
	GetLeakingMachineIds(ctx context.Context) ([]string, error)
	GetLeakingSwitchIds(ctx context.Context) ([]string, error)
	GetPowerStates(ctx context.Context, machineIds []string) (ret []MachinePowerState, err error)
	SetFirmwareUpdateTimeWindow(ctx context.Context, machineIds []string, startTime, endTime time.Time) error
	// FindInterfaces returns all machine interfaces known by nico-core-api, keyed by MAC address
	FindInterfaces(ctx context.Context) (map[string]MachineInterface, error)

	// AdminPowerControl performs power control operations on a machine
	AdminPowerControl(ctx context.Context, machineID string, action SystemPowerControl) error

	// UpdatePowerOption sets the desired power state for a machine in NICo's power manager.
	// This controls NICo's power-on gate: setting desired state to On allows
	// the machine to power on, while Off or Disabled prevents it.
	UpdatePowerOption(ctx context.Context, machineID string, desiredState PowerState) error

	// FindMachinesByIds returns detailed machine information for the given machine IDs
	FindMachinesByIds(ctx context.Context, machineIds []string) ([]MachineDetail, error)

	// GetMachinePositionInfo returns position information for the given machine IDs
	GetMachinePositionInfo(ctx context.Context, machineIds []string) ([]MachinePosition, error)

	// AllowIngestionAndPowerOn opens NICo's power-on gate for a BMC endpoint,
	// allowing the machine to be ingested and powered on.
	AllowIngestionAndPowerOn(ctx context.Context, bmcIP string, bmcMAC string) error

	// DetermineMachineIngestionState returns the bring-up state of a machine
	// relative to NICo's power-on gate.
	DetermineMachineIngestionState(ctx context.Context, bmcIP string, bmcMAC string) (BringUpState, error) //nolint

	// AddExpectedMachine registers an expected machine with NICo for ingestion.
	AddExpectedMachine(ctx context.Context, req AddExpectedMachineRequest) error

	// GetAllExpectedSwitches returns all expected switches registered with NICo,
	// keyed by BMC MAC address, including metadata (e.g., "host_mac_address" for the NVOS MAC).
	GetAllExpectedSwitches(ctx context.Context) (map[string]ExpectedSwitchInfo, error)

	// AddExpectedSwitch registers an expected switch with NICo for ingestion.
	AddExpectedSwitch(ctx context.Context, req AddExpectedSwitchRequest) error

	// AddExpectedPowerShelf registers an expected power shelf with NICo for ingestion.
	AddExpectedPowerShelf(ctx context.Context, req AddExpectedPowerShelfRequest) error

	// InsertHealthReportOverride inserts a health-report override for a machine
	// (replaces the deprecated SetMaintenance RPC).
	InsertHealthReportOverride(ctx context.Context, machineID string, source string) error

	// RemoveHealthReportOverride removes a previously inserted health-report override.
	RemoveHealthReportOverride(ctx context.Context, machineID string, source string) error

	// ComponentPowerControl performs power control on component targets (switches, power shelves).
	ComponentPowerControl(ctx context.Context, req *pb.ComponentPowerControlRequest) (*pb.ComponentPowerControlResponse, error)

	// UpdateComponentFirmware queues firmware updates for component targets.
	UpdateComponentFirmware(ctx context.Context, req *pb.UpdateComponentFirmwareRequest) (*pb.UpdateComponentFirmwareResponse, error)

	// GetComponentFirmwareStatus returns firmware update status for component targets.
	GetComponentFirmwareStatus(ctx context.Context, req *pb.GetComponentFirmwareStatusRequest) (*pb.GetComponentFirmwareStatusResponse, error)

	// ListComponentFirmwareVersions lists available firmware versions for component targets.
	ListComponentFirmwareVersions(ctx context.Context, req *pb.ListComponentFirmwareVersionsRequest) (*pb.ListComponentFirmwareVersionsResponse, error)

	// GetComponentInventory retrieves inventory (including site exploration reports) for component targets.
	GetComponentInventory(ctx context.Context, req *pb.GetComponentInventoryRequest) (*pb.GetComponentInventoryResponse, error)

	// GetAllExpectedSwitchesLinked returns expected switches linked to their
	// explored endpoints and live Switch resources. Each entry includes the
	// BMC MAC, Core's SwitchId (if the switch has been created), and the
	// expected switch UUID.
	GetAllExpectedSwitchesLinked(ctx context.Context) ([]LinkedExpectedSwitch, error)

	// GetAllExpectedPowerShelvesLinked returns expected power shelves linked
	// to their explored endpoints and live PowerShelf resources. Each entry
	// includes the BMC/PMC MAC, Core's PowerShelfId (if the shelf has been
	// created), and the expected power shelf UUID.
	GetAllExpectedPowerShelvesLinked(ctx context.Context) ([]LinkedExpectedPowerShelf, error)

	// GetDesiredFirmwareVersions returns a slice of desired firmware version
	// entries configured in Core. Each entry carries vendor and model fields;
	// iterate the slice to find matching entries.
	GetDesiredFirmwareVersions(ctx context.Context) ([]*pb.DesiredFirmwareVersionEntry, error)

	// FindExploredEndpointsByIds returns explored endpoint data (including
	// firmware_versions) for the given BMC IP addresses.
	FindExploredEndpointsByIds(ctx context.Context, bmcIPs []string) ([]*pb.ExploredEndpoint, error)

	// SetMachineAutoUpdate enables or disables firmware auto-update for a machine.
	SetMachineAutoUpdate(ctx context.Context, machineID string, enable bool) error

	// The following are only valid in the mock environment and should only be called by unit tests
	AddMachine(MachineDetail)
	AddPowerState(machineID string, state PowerState)
	SetFirmwareUpdateTimeWindowError(err error)
	SetAdminPowerControlError(err error)
	AddMachineInterface(iface MachineInterface)
	AddExpectedSwitchInfo(info ExpectedSwitchInfo)
	SetLeakingMachineIds(ids []string)
	SetLeakingSwitchIds([]string)
}
