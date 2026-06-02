// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoapi

import (
	"context"
	"time"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/common/utils"
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
)

type mockClient struct {
	machines                    map[string]MachineDetail
	powerStates                 map[string]PowerState
	machineInterfaces           map[string]MachineInterface
	expectedSwitches            map[string]ExpectedSwitchInfo // keyed by BMC MAC
	leakingMachineIds           []string
	leakingSwitchIds            []string
	firmwareUpdateTimeWindowErr error // If set, SetFirmwareUpdateTimeWindow will return this error
	adminPowerControlErr        error // If set, AdminPowerControl will return this error
	desiredFirmwareVersions     []*pb.DesiredFirmwareVersionEntry
}

// NewMockClient returns a "GRPC" client that returns mock values so it can be used in unit tests.
func NewMockClient() Client {
	return &mockClient{
		machines:          map[string]MachineDetail{},
		powerStates:       map[string]PowerState{},
		machineInterfaces: map[string]MachineInterface{},
		expectedSwitches:  map[string]ExpectedSwitchInfo{},
	}
}

func (c *mockClient) Version(ctx context.Context) (string, error) {
	return "1.2.3", nil
}

func (c *mockClient) GetMachines(ctx context.Context) ([]MachineDetail, error) {
	var result []MachineDetail
	for _, m := range c.machines {
		result = append(result, m)
	}
	return result, nil
}

func (c *mockClient) GetLeakingMachineIds(ctx context.Context) ([]string, error) {
	return c.leakingMachineIds, nil
}

func (c *mockClient) GetLeakingSwitchIds(ctx context.Context) ([]string, error) {
	return c.leakingSwitchIds, nil
}

func (c *mockClient) SetLeakingMachineIds(ids []string) {
	c.leakingMachineIds = ids
}

func (c *mockClient) SetLeakingSwitchIds(ids []string) {
	c.leakingSwitchIds = ids
}

func (c *mockClient) GetPowerStates(ctx context.Context, machineIds []string) (ret []MachinePowerState, err error) {
	for _, cur := range machineIds {
		if state, ok := c.powerStates[cur]; ok {
			ret = append(ret, MachinePowerState{MachineID: cur, PowerState: state})
		}
	}

	return ret, nil
}

func (c *mockClient) SetFirmwareUpdateTimeWindow(ctx context.Context, machineIds []string, startTime, endTime time.Time) error {
	return c.firmwareUpdateTimeWindowErr
}

func (c *mockClient) AdminPowerControl(ctx context.Context, machineID string, action SystemPowerControl) error {
	return c.adminPowerControlErr
}

func (c *mockClient) UpdatePowerOption(ctx context.Context, machineID string, desiredState PowerState) error {
	return nil
}

func (c *mockClient) AddMachine(machine MachineDetail) {
	c.machines[machine.MachineID] = machine
}

func (c *mockClient) AddPowerState(machineID string, state PowerState) {
	c.powerStates[machineID] = state
}

func (c *mockClient) SetFirmwareUpdateTimeWindowError(err error) {
	c.firmwareUpdateTimeWindowErr = err
}

func (c *mockClient) SetAdminPowerControlError(err error) {
	c.adminPowerControlErr = err
}

func (c *mockClient) FindInterfaces(ctx context.Context) (map[string]MachineInterface, error) {
	interfaces := make(map[string]MachineInterface)
	for mac, iface := range c.machineInterfaces {
		interfaces[mac] = iface
	}
	return interfaces, nil
}

func (c *mockClient) AddMachineInterface(iface MachineInterface) {
	c.machineInterfaces[utils.NormalizeMAC(iface.MacAddress)] = iface
}

func (c *mockClient) FindMachinesByIds(ctx context.Context, machineIds []string) ([]MachineDetail, error) {
	var result []MachineDetail
	for _, id := range machineIds {
		if m, ok := c.machines[id]; ok {
			result = append(result, m)
		}
	}
	return result, nil
}

func (c *mockClient) GetMachinePositionInfo(ctx context.Context, machineIds []string) ([]MachinePosition, error) {
	// Mock implementation returns empty for now
	return nil, nil
}

func (c *mockClient) AllowIngestionAndPowerOn(
	ctx context.Context,
	bmcIP string,
	bmcMAC string,
) error {
	return nil
}

func (c *mockClient) DetermineMachineIngestionState(
	ctx context.Context,
	bmcIP string,
	bmcMAC string,
) (BringUpState, error) {
	return BringUpStateMachineCreated, nil
}

func (c *mockClient) AddExpectedMachine(ctx context.Context, req AddExpectedMachineRequest) error {
	return nil
}

func (c *mockClient) GetAllExpectedSwitches(_ context.Context) (map[string]ExpectedSwitchInfo, error) {
	results := make(map[string]ExpectedSwitchInfo)
	for mac, es := range c.expectedSwitches {
		results[mac] = es
	}
	return results, nil
}

func (c *mockClient) AddExpectedSwitch(ctx context.Context, req AddExpectedSwitchRequest) error {
	return nil
}

func (c *mockClient) AddExpectedPowerShelf(ctx context.Context, req AddExpectedPowerShelfRequest) error {
	return nil
}

func (c *mockClient) InsertHealthReportOverride(ctx context.Context, machineID string, source string) error {
	return nil
}

func (c *mockClient) RemoveHealthReportOverride(ctx context.Context, machineID string, source string) error {
	return nil
}

func (c *mockClient) ComponentPowerControl(ctx context.Context, req *pb.ComponentPowerControlRequest) (*pb.ComponentPowerControlResponse, error) {
	return &pb.ComponentPowerControlResponse{}, nil
}

func (c *mockClient) UpdateComponentFirmware(ctx context.Context, req *pb.UpdateComponentFirmwareRequest) (*pb.UpdateComponentFirmwareResponse, error) {
	return &pb.UpdateComponentFirmwareResponse{}, nil
}

func (c *mockClient) GetComponentFirmwareStatus(ctx context.Context, req *pb.GetComponentFirmwareStatusRequest) (*pb.GetComponentFirmwareStatusResponse, error) {
	return &pb.GetComponentFirmwareStatusResponse{}, nil
}

func (c *mockClient) ListComponentFirmwareVersions(ctx context.Context, req *pb.ListComponentFirmwareVersionsRequest) (*pb.ListComponentFirmwareVersionsResponse, error) {
	return &pb.ListComponentFirmwareVersionsResponse{}, nil
}

func (c *mockClient) GetComponentInventory(ctx context.Context, req *pb.GetComponentInventoryRequest) (*pb.GetComponentInventoryResponse, error) {
	return &pb.GetComponentInventoryResponse{}, nil
}

func (c *mockClient) GetAllExpectedSwitchesLinked(_ context.Context) ([]LinkedExpectedSwitch, error) {
	return nil, nil
}

func (c *mockClient) GetAllExpectedPowerShelvesLinked(_ context.Context) ([]LinkedExpectedPowerShelf, error) {
	return nil, nil
}

func (c *mockClient) GetDesiredFirmwareVersions(_ context.Context) ([]*pb.DesiredFirmwareVersionEntry, error) {
	return c.desiredFirmwareVersions, nil
}

func (c *mockClient) FindExploredEndpointsByIds(_ context.Context, _ []string) ([]*pb.ExploredEndpoint, error) {
	return nil, nil
}

func (c *mockClient) SetMachineAutoUpdate(_ context.Context, _ string, _ bool) error {
	return nil
}

func (c *mockClient) AddExpectedSwitchInfo(info ExpectedSwitchInfo) {
	c.expectedSwitches[utils.NormalizeMAC(info.BMCMACAddress)] = info
}
