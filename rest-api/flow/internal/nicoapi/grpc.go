// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/certs"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/common/utils"
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	healthProbeIDMaintenance               = "Maintenance"
	classificationSuppressExternalAlerting = "SuppressExternalAlerting"
)

type grpcClient struct {
	gclient     pb.ForgeClient
	grpcTimeout time.Duration
}

var testingMsgOnce sync.Once

// NewClient creates a GRPC connection pool to nico-core-api.  Returning success does not mean that we have yet made an actual connection;
// that happens when making an actual request.
func NewClient(grpcTimeout time.Duration) (Client, error) {
	if testing.Testing() {
		testingMsgOnce.Do(func() {
			log.Info().Msg("Running unit tests, forcing mock GRPC client")
		})
		return NewMockClient(), nil
	}

	nicoURL := os.Getenv("NICO_CORE_API_URL")
	if nicoURL == "" {
		return nil, errors.New("NICO_CORE_API_URL not set, cannot make connections to NICo Core")
	}

	tlsConfig, _, err := certs.TLSConfig()
	if err != nil {
		if err == certs.ErrNotPresent {
			return nil, errors.New("Certificates not present, unable to authenticate with nico-core-api")
		}
		return nil, err
	}

	conn, err := grpc.NewClient(nicoURL, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to nico-core-api: %w", err)
	}

	return &grpcClient{gclient: pb.NewForgeClient(conn), grpcTimeout: grpcTimeout}, nil
}

// GetMachines retrieves all machines known by nico-core-api
// (FindMachineIds + FindMachinesByIds).
func (c *grpcClient) GetMachines(ctx context.Context) ([]MachineDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	machineIDs, err := c.gclient.FindMachineIds(ctx, &pb.MachineSearchConfig{})
	if err != nil {
		return nil, err
	}

	req := &pb.MachinesByIdsRequest{}
	for _, machineID := range machineIDs.MachineIds {
		req.MachineIds = append(req.MachineIds, machineID)
	}

	if len(req.MachineIds) == 0 {
		return nil, nil
	}

	machines, err := c.gclient.FindMachinesByIds(ctx, req)
	if err != nil {
		return nil, err
	}

	var result []MachineDetail
	for _, machine := range machines.Machines {
		result = append(result, machineDetailFromPb(machine))
	}
	return result, nil
}

// GetLeakingMachineIds retrieves IDs of all machines which are leaking and are powered on.
// The search filter passed in to FindMachineIds limits the results to these two conditions.
func (c *grpcClient) GetLeakingMachineIds(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	alert := "hardware-health.tray-leak-detection"
	powerState := "on"
	searchConfig := pb.MachineSearchConfig{
		OnlyWithHealthAlert: &alert,
		OnlyWithPowerState:  &powerState,
	}

	machineIDs, err := c.gclient.FindMachineIds(ctx, &searchConfig)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(machineIDs.GetMachineIds()))
	for _, machineID := range machineIDs.GetMachineIds() {
		ids = append(ids, machineID.GetId())
	}
	return ids, nil
}

// GetLeakingSwitchIds retrieves IDs of all switches which are leaking.
// The search filter passed in to FindSwitchIds limits the results to this condition.
// Once we have the ability to limit the results to powered on switches,
// we can add that condition to the search filter.
func (c *grpcClient) GetLeakingSwitchIds(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	alert := "hardware-health.tray-leak-detection"
	searchConfig := pb.SwitchSearchFilter{
		OnlyWithHealthAlert: &alert,
	}

	switchIDs, err := c.gclient.FindSwitchIds(ctx, &searchConfig)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(switchIDs.GetIds()))
	for _, switchID := range switchIDs.GetIds() {
		ids = append(ids, switchID.GetId())
	}
	return ids, nil
}

// Version returns the version string of nico-core-api, mainly as a "ping"
func (c *grpcClient) Version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	res, err := c.gclient.Version(ctx, &pb.VersionRequest{})
	if err != nil {
		return "", err
	}
	return res.GetBuildVersion(), nil
}

// GetPowerStates returns the power states of the given machines (all machines if given an empty machineIds)
func (c *grpcClient) GetPowerStates(ctx context.Context, machineIds []string) (ret []MachinePowerState, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	req := &pb.PowerOptionRequest{MachineId: stringsToMachineIds(machineIds)}
	res, err := c.gclient.GetPowerOptions(ctx, req)
	if err != nil {
		return nil, err
	}
	for _, cur := range res.Response {
		ret = append(ret, machinePowerStateFromPb(cur))
	}

	return ret, nil
}

// SetFirmwareUpdateTimeWindow sets the firmware update time window for the given machines
func (c *grpcClient) SetFirmwareUpdateTimeWindow(ctx context.Context, machineIds []string, startTime, endTime time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	req := &pb.SetFirmwareUpdateTimeWindowRequest{
		MachineIds:     stringsToMachineIds(machineIds),
		StartTimestamp: timestamppb.New(startTime),
		EndTimestamp:   timestamppb.New(endTime),
	}

	_, err := c.gclient.SetFirmwareUpdateTimeWindow(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to set firmware update time window: %w", err)
	}

	return nil
}

// AdminPowerControl performs power control operations on a machine
func (c *grpcClient) AdminPowerControl(ctx context.Context, machineID string, action SystemPowerControl) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	req := &pb.AdminPowerControlRequest{
		MachineId: &machineID,
		Action:    action.toPb(),
	}

	_, err := c.gclient.AdminPowerControl(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to perform power control on machine %s: %w", machineID, err)
	}

	return nil
}

// UpdatePowerOption sets the desired power state for a machine in NICo's power manager.
func (c *grpcClient) UpdatePowerOption(ctx context.Context, machineID string, desiredState PowerState) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	req := &pb.PowerOptionUpdateRequest{
		MachineId:  &pb.MachineId{Id: machineID},
		PowerState: powerStateToPb(desiredState),
	}

	_, err := c.gclient.UpdatePowerOption(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to update power option for machine %s: %w", machineID, err)
	}

	return nil
}

// FindInterfaces returns all machine interfaces known by nico-core-api, keyed by MAC address
func (c *grpcClient) FindInterfaces(ctx context.Context) (map[string]MachineInterface, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	// Empty query returns all interfaces
	req := &pb.InterfaceSearchQuery{}
	res, err := c.gclient.FindInterfaces(ctx, req)
	if err != nil {
		return nil, err
	}

	interfaces := make(map[string]MachineInterface)
	for _, iface := range res.Interfaces {
		mi := machineInterfaceFromPb(iface)
		interfaces[utils.NormalizeMAC(mi.MacAddress)] = mi
	}
	return interfaces, nil
}

// FindMachinesByIds returns detailed machine information for the given machine IDs
func (c *grpcClient) FindMachinesByIds(ctx context.Context, machineIds []string) ([]MachineDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	if len(machineIds) == 0 {
		return nil, nil
	}

	req := &pb.MachinesByIdsRequest{
		MachineIds: stringsToMachineIds(machineIds),
	}

	res, err := c.gclient.FindMachinesByIds(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to find machines by IDs: %w", err)
	}

	var result []MachineDetail
	for _, machine := range res.Machines {
		result = append(result, machineDetailFromPb(machine))
	}
	return result, nil
}

// GetMachinePositionInfo returns position information for the given machine IDs
func (c *grpcClient) GetMachinePositionInfo(ctx context.Context, machineIds []string) ([]MachinePosition, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	if len(machineIds) == 0 {
		return nil, nil
	}

	req := &pb.MachinePositionQuery{
		MachineIds: stringsToMachineIds(machineIds),
	}

	res, err := c.gclient.GetMachinePositionInfo(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine position info: %w", err)
	}

	var result []MachinePosition
	for _, pos := range res.MachinePositionInfo {
		result = append(result, machinePositionFromPb(pos))
	}
	return result, nil
}

// AllowIngestionAndPowerOn opens NICo's power-on gate for a
// BMC endpoint.
func (c *grpcClient) AllowIngestionAndPowerOn(
	ctx context.Context,
	bmcIP string,
	bmcMAC string,
) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	req := &pb.BmcEndpointRequest{IpAddress: bmcIP}
	if bmcMAC != "" {
		req.MacAddress = &bmcMAC
	}

	_, err := c.gclient.AllowIngestionAndPowerOn(ctx, req)
	if err != nil {
		return fmt.Errorf(
			"failed to allow ingestion for BMC %s: %w",
			bmcIP, err,
		)
	}

	return nil
}

// DetermineMachineIngestionState queries the ingestion state of
// a machine relative to NICo's power-on gate.
func (c *grpcClient) DetermineMachineIngestionState(
	ctx context.Context,
	bmcIP string,
	bmcMAC string,
) (BringUpState, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	req := &pb.BmcEndpointRequest{IpAddress: bmcIP}
	if bmcMAC != "" {
		req.MacAddress = &bmcMAC
	}

	resp, err := c.gclient.DetermineMachineIngestionState(
		ctx, req,
	)
	if err != nil {
		return BringUpStateNotDiscovered, fmt.Errorf(
			"failed to get bring-up state for BMC %s: %w", //nolint
			bmcIP, err,
		)
	}

	return bringUpStateFromPb(
		resp.GetMachineIngestionState(),
	), nil
}

// AddExpectedMachine registers an expected machine with NICo.
func (c *grpcClient) AddExpectedMachine(ctx context.Context, req AddExpectedMachineRequest) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	pbReq := &pb.ExpectedMachine{
		BmcMacAddress:       req.BMCMACAddress,
		BmcUsername:         req.BMCUsername,
		BmcPassword:         req.BMCPassword,
		ChassisSerialNumber: req.ChassisSerialNumber,
	}

	if len(req.FallbackDPUSerialNumbers) > 0 {
		pbReq.FallbackDpuSerialNumbers = req.FallbackDPUSerialNumbers
	}

	if req.RackID != "" {
		pbReq.RackId = &pb.RackId{Id: req.RackID}
	}

	if req.PauseIngestionAndPowerOn != nil {
		pbReq.DefaultPauseIngestionAndPoweron = req.PauseIngestionAndPowerOn
	}

	_, err := c.gclient.AddExpectedMachine(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("failed to add expected machine (bmc_mac=%s): %w", req.BMCMACAddress, err)
	}

	return nil
}

// GetAllExpectedSwitches returns all expected switches from NICo, keyed by BMC MAC address.
func (c *grpcClient) GetAllExpectedSwitches(ctx context.Context) (map[string]ExpectedSwitchInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.gclient.GetAllExpectedSwitches(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to get all expected switches: %w", err)
	}

	results := make(map[string]ExpectedSwitchInfo)
	for _, es := range resp.GetExpectedSwitches() {
		info := expectedSwitchInfoFromPb(es)
		if info.BMCMACAddress != "" {
			results[utils.NormalizeMAC(info.BMCMACAddress)] = info
		}
	}
	return results, nil
}

// AddExpectedSwitch registers an expected switch with NICo.
func (c *grpcClient) AddExpectedSwitch(ctx context.Context, req AddExpectedSwitchRequest) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	pbReq := &pb.ExpectedSwitch{
		BmcMacAddress:      req.BMCMACAddress,
		BmcUsername:        req.BMCUsername,
		BmcPassword:        req.BMCPassword,
		SwitchSerialNumber: req.SwitchSerialNumber,
	}

	if req.RackID != "" {
		pbReq.RackId = &pb.RackId{Id: req.RackID}
	}

	if req.NVOSUsername != "" {
		pbReq.NvosUsername = &req.NVOSUsername
	}

	if req.NVOSPassword != "" {
		pbReq.NvosPassword = &req.NVOSPassword
	}

	_, err := c.gclient.AddExpectedSwitch(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("failed to add expected switch (bmc_mac=%s): %w", req.BMCMACAddress, err)
	}

	return nil
}

// AddExpectedPowerShelf registers an expected power shelf with NICo.
func (c *grpcClient) AddExpectedPowerShelf(ctx context.Context, req AddExpectedPowerShelfRequest) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	pbReq := &pb.ExpectedPowerShelf{
		BmcMacAddress:     req.BMCMACAddress,
		BmcUsername:       req.BMCUsername,
		BmcPassword:       req.BMCPassword,
		ShelfSerialNumber: req.ShelfSerialNumber,
		BmcIpAddress:      req.IPAddress,
	}

	if req.RackID != "" {
		pbReq.RackId = &pb.RackId{Id: req.RackID}
	}

	_, err := c.gclient.AddExpectedPowerShelf(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("failed to add expected power shelf (bmc_mac=%s): %w", req.BMCMACAddress, err)
	}

	return nil
}

func (c *grpcClient) InsertHealthReportOverride(ctx context.Context, machineID string, source string) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	req := &pb.InsertMachineHealthReportRequest{
		MachineId: &pb.MachineId{Id: machineID},
		HealthReportEntry: &pb.HealthReportEntry{
			Report: &pb.HealthReport{
				Source: source,
				Alerts: []*pb.HealthProbeAlert{{
					Id:              healthProbeIDMaintenance,
					Message:         "Machine under Flow-managed maintenance",
					Classifications: []string{classificationSuppressExternalAlerting},
				}},
			},
			Mode: pb.HealthReportApplyMode_Replace,
		},
	}

	_, err := c.gclient.InsertHealthReportOverride(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to insert health report override for machine %s: %w", machineID, err)
	}
	return nil
}

func (c *grpcClient) RemoveHealthReportOverride(ctx context.Context, machineID string, source string) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	req := &pb.RemoveMachineHealthReportRequest{
		MachineId: &pb.MachineId{Id: machineID},
		Source:    source,
	}

	_, err := c.gclient.RemoveHealthReportOverride(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to remove health report override for machine %s: %w", machineID, err)
	}
	return nil
}

func (c *grpcClient) ComponentPowerControl(ctx context.Context, req *pb.ComponentPowerControlRequest) (*pb.ComponentPowerControlResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()
	return c.gclient.ComponentPowerControl(ctx, req)
}

func (c *grpcClient) UpdateComponentFirmware(ctx context.Context, req *pb.UpdateComponentFirmwareRequest) (*pb.UpdateComponentFirmwareResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()
	return c.gclient.UpdateComponentFirmware(ctx, req)
}

func (c *grpcClient) GetComponentFirmwareStatus(ctx context.Context, req *pb.GetComponentFirmwareStatusRequest) (*pb.GetComponentFirmwareStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()
	return c.gclient.GetComponentFirmwareStatus(ctx, req)
}

func (c *grpcClient) ListComponentFirmwareVersions(ctx context.Context, req *pb.ListComponentFirmwareVersionsRequest) (*pb.ListComponentFirmwareVersionsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()
	return c.gclient.ListComponentFirmwareVersions(ctx, req)
}

func (c *grpcClient) GetComponentInventory(ctx context.Context, req *pb.GetComponentInventoryRequest) (*pb.GetComponentInventoryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()
	return c.gclient.GetComponentInventory(ctx, req)
}

func (c *grpcClient) GetAllExpectedSwitchesLinked(ctx context.Context) ([]LinkedExpectedSwitch, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.gclient.GetAllExpectedSwitchesLinked(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to get all expected switches linked: %w", err)
	}

	var results []LinkedExpectedSwitch
	for _, les := range resp.GetExpectedSwitches() {
		results = append(results, linkedExpectedSwitchFromPb(les))
	}
	return results, nil
}

func (c *grpcClient) GetAllExpectedPowerShelvesLinked(ctx context.Context) ([]LinkedExpectedPowerShelf, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.gclient.GetAllExpectedPowerShelvesLinked(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to get all expected power shelves linked: %w", err)
	}

	var results []LinkedExpectedPowerShelf
	for _, leps := range resp.GetExpectedPowerShelves() {
		results = append(results, linkedExpectedPowerShelfFromPb(leps))
	}
	return results, nil
}

func (c *grpcClient) GetDesiredFirmwareVersions(ctx context.Context) ([]*pb.DesiredFirmwareVersionEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.gclient.GetDesiredFirmwareVersions(ctx, &pb.GetDesiredFirmwareVersionsRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get desired firmware versions: %w", err)
	}
	return resp.GetEntries(), nil
}

func (c *grpcClient) FindExploredEndpointsByIds(ctx context.Context, bmcIPs []string) ([]*pb.ExploredEndpoint, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	if len(bmcIPs) == 0 {
		return nil, nil
	}

	resp, err := c.gclient.FindExploredEndpointsByIds(ctx, &pb.ExploredEndpointsByIdsRequest{
		EndpointIds: bmcIPs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find explored endpoints by IDs: %w", err)
	}
	return resp.GetEndpoints(), nil
}

func (c *grpcClient) SetMachineAutoUpdate(ctx context.Context, machineID string, enable bool) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	action := pb.MachineSetAutoUpdateRequest_Enable
	if !enable {
		action = pb.MachineSetAutoUpdateRequest_Disable
	}

	_, err := c.gclient.MachineSetAutoUpdate(ctx, &pb.MachineSetAutoUpdateRequest{
		MachineId: &pb.MachineId{Id: machineID},
		Action:    action,
	})
	if err != nil {
		return fmt.Errorf("failed to set auto-update for machine %s: %w", machineID, err)
	}
	return nil
}

func (c *grpcClient) AddMachine(machine MachineDetail) {
	panic("Not a unit test")
}

func (c *grpcClient) AddPowerState(machineID string, state PowerState) {
	panic("Not a unit test")
}

func (c *grpcClient) SetFirmwareUpdateTimeWindowError(err error) {
	panic("Not a unit test")
}

func (c *grpcClient) SetAdminPowerControlError(err error) {
	panic("Not a unit test")
}

func (c *grpcClient) AddMachineInterface(iface MachineInterface) {
	panic("Not a unit test")
}

func (c *grpcClient) AddExpectedSwitchInfo(info ExpectedSwitchInfo) {
	panic("Not a unit test")
}

func (c *grpcClient) SetLeakingMachineIds(ids []string) {
	panic("Not a unit test")
}

func (c *grpcClient) SetLeakingSwitchIds(ids []string) {
	panic("Not a unit test")
}
