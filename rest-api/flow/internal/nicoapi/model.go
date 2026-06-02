// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoapi

import (
	"time"

	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
)

// model.go abstracts the raw grpc definitions away.  Don't bother implementing fields you don't think you'll use.

func stringsToMachineIds(machineIds []string) (ret []*pb.MachineId) {
	if len(machineIds) == 0 {
		return nil
	}
	for _, cur := range machineIds {
		ret = append(ret, &pb.MachineId{Id: cur})
	}
	return ret
}

// MachineDetail represents detailed machine information from NICo
type MachineDetail struct {
	MachineID           string
	ChassisSerial       *string
	State               string
	MachineType         string
	BmcIP               string
	BmcMac              string
	FirmwareVersion     string
	UpdateComplete      bool
	HealthStatus        string
	LastObservationTime *time.Time
	FirmwareAutoupdate  *bool
}

// MachinePosition represents machine position information from NICo
type MachinePosition struct {
	MachineID        string
	PhysicalSlotNum  *int32
	ComputeTrayIndex *int32
	TopologyID       *int32
}

func machineDetailFromPb(machine *pb.Machine) MachineDetail {
	detail := MachineDetail{
		MachineID:      machine.Id.Id,
		State:          machine.State,
		MachineType:    machine.MachineType.String(),
		UpdateComplete: machine.UpdateComplete,
	}

	// Chassis serial
	if machine.DiscoveryInfo != nil && machine.DiscoveryInfo.DmiData != nil {
		serial := machine.DiscoveryInfo.DmiData.ChassisSerial
		detail.ChassisSerial = &serial
	}

	// BMC info
	if machine.BmcInfo != nil {
		if machine.BmcInfo.Ip != nil {
			detail.BmcIP = *machine.BmcInfo.Ip
		}
		if machine.BmcInfo.Mac != nil {
			detail.BmcMac = *machine.BmcInfo.Mac
		}
		if machine.BmcInfo.FirmwareVersion != nil {
			detail.FirmwareVersion = *machine.BmcInfo.FirmwareVersion
		}
	}

	// Health status - derived from alerts
	if machine.Health != nil {
		if len(machine.Health.Alerts) > 0 {
			detail.HealthStatus = "unhealthy"
		} else {
			detail.HealthStatus = "healthy"
		}
	}

	// Last observation time
	if machine.LastObservationTime != nil {
		t := machine.LastObservationTime.AsTime()
		detail.LastObservationTime = &t
	}

	if machine.FirmwareAutoupdate != nil {
		v := machine.GetFirmwareAutoupdate()
		detail.FirmwareAutoupdate = &v
	}

	return detail
}

func machinePositionFromPb(pos *pb.MachinePositionInfo) MachinePosition {
	return MachinePosition{
		MachineID:        pos.MachineId.Id,
		PhysicalSlotNum:  pos.PhysicalSlotNumber,
		ComputeTrayIndex: pos.ComputeTrayIndex,
		TopologyID:       pos.TopologyId,
	}
}

type PowerState int

const (
	PowerStateUnknown PowerState = iota
	PowerStateOff
	PowerStateOn
	PowerStateDisabled
)

// MachinePowerState is information about current and desired power states
type MachinePowerState struct {
	MachineID  string
	PowerState PowerState
}

func machinePowerStateFromPb(state *pb.PowerOptions) MachinePowerState {
	return MachinePowerState{MachineID: state.HostId.Id, PowerState: powerStateFromPb(state.ActualState)}
}

func powerStateFromPb(state pb.PowerState) (ret PowerState) {
	switch state {
	case pb.PowerState_Off:
		ret = PowerStateOff
	case pb.PowerState_On:
		ret = PowerStateOn
	case pb.PowerState_PowerManagerDisabled:
		ret = PowerStateDisabled
	default:
		ret = PowerStateUnknown
	}

	return ret
}

func powerStateToPb(state PowerState) pb.PowerState {
	switch state {
	case PowerStateOff:
		return pb.PowerState_Off
	case PowerStateOn:
		return pb.PowerState_On
	case PowerStateDisabled:
		return pb.PowerState_PowerManagerDisabled
	default:
		return pb.PowerState_Off
	}
}

// SystemPowerControl represents power control actions for AdminPowerControl
type SystemPowerControl int

const (
	// Power On
	PowerControlOn      SystemPowerControl = iota
	PowerControlForceOn                    // maps to On (NICo doesn't distinguish)
	// Power Off
	PowerControlGracefulShutdown
	PowerControlForceOff
	// Restart (OS level)
	PowerControlGracefulRestart
	PowerControlForceRestart
	// Reset (hardware level)
	PowerControlWarmReset // maps to GracefulRestart
	PowerControlColdReset // maps to ACPowercycle
)

func (s SystemPowerControl) String() string {
	switch s {
	case PowerControlOn:
		return "On"
	case PowerControlForceOn:
		return "ForceOn"
	case PowerControlGracefulShutdown:
		return "GracefulShutdown"
	case PowerControlForceOff:
		return "ForceOff"
	case PowerControlGracefulRestart:
		return "GracefulRestart"
	case PowerControlForceRestart:
		return "ForceRestart"
	case PowerControlWarmReset:
		return "WarmReset"
	case PowerControlColdReset:
		return "ColdReset"
	default:
		return "Unknown"
	}
}

func (s SystemPowerControl) toPb() pb.AdminPowerControlRequest_SystemPowerControl {
	switch s {
	case PowerControlOn, PowerControlForceOn:
		return pb.AdminPowerControlRequest_On
	case PowerControlGracefulShutdown:
		return pb.AdminPowerControlRequest_GracefulShutdown
	case PowerControlForceOff:
		return pb.AdminPowerControlRequest_ForceOff
	case PowerControlGracefulRestart, PowerControlWarmReset:
		return pb.AdminPowerControlRequest_GracefulRestart
	case PowerControlForceRestart:
		return pb.AdminPowerControlRequest_ForceRestart
	case PowerControlColdReset:
		return pb.AdminPowerControlRequest_ACPowercycle
	default:
		return pb.AdminPowerControlRequest_On
	}
}

// MachineInterface represents a network interface from nico-core-api
type MachineInterface struct {
	MacAddress string
	Addresses  []string // IP addresses assigned to this interface
}

func machineInterfaceFromPb(iface *pb.MachineInterface) MachineInterface {
	return MachineInterface{
		MacAddress: iface.MacAddress,
		Addresses:  iface.Address,
	}
}

// AddExpectedMachineRequest contains the parameters for registering
// an expected machine with NICo.
type AddExpectedMachineRequest struct {
	BMCMACAddress            string   `json:"bmc_mac_address"`
	BMCUsername              string   `json:"bmc_username"`
	BMCPassword              string   `json:"bmc_password"`
	ChassisSerialNumber      string   `json:"chassis_serial_number,omitempty"`
	FallbackDPUSerialNumbers []string `json:"fallback_dpu_serial_numbers,omitempty"`
	RackID                   string   `json:"rack_id,omitempty"`
	PauseIngestionAndPowerOn *bool    `json:"default_pause_ingestion_and_poweron,omitempty"`
}

// AddExpectedPowerShelfRequest contains the parameters for registering
// an expected power shelf with NICo.
type AddExpectedPowerShelfRequest struct {
	BMCMACAddress     string `json:"bmc_mac_address"`
	BMCUsername       string `json:"bmc_username"`
	BMCPassword       string `json:"bmc_password"`
	ShelfSerialNumber string `json:"shelf_serial_number,omitempty"`
	IPAddress         string `json:"ip_address,omitempty"`
	RackID            string `json:"rack_id,omitempty"`
}

// ExpectedSwitchInfo represents an expected switch retrieved from NICo,
// including metadata labels (e.g., "host_mac_address" for the NVOS MAC).
// Credentials are omitted; NICo configures them in Vault and NSM
// queries Vault by MAC address.
type ExpectedSwitchInfo struct {
	BMCMACAddress      string
	SwitchSerialNumber string
	Metadata           map[string]string
}

func expectedSwitchInfoFromPb(es *pb.ExpectedSwitch) ExpectedSwitchInfo {
	info := ExpectedSwitchInfo{
		BMCMACAddress:      es.GetBmcMacAddress(),
		SwitchSerialNumber: es.GetSwitchSerialNumber(),
		Metadata:           make(map[string]string),
	}
	if es.GetMetadata() != nil {
		for _, label := range es.GetMetadata().GetLabels() {
			if label.Value != nil {
				info.Metadata[label.GetKey()] = label.GetValue()
			}
		}
	}
	return info
}

// LinkedExpectedSwitch represents an expected switch linked to its
// explored endpoint and live Switch resource in Core.
type LinkedExpectedSwitch struct {
	BMCMACAddress      string
	SwitchID           string // Core's live Switch ID; empty if not yet created
	ExpectedSwitchID   string
	SwitchSerialNumber string
}

func linkedExpectedSwitchFromPb(les *pb.LinkedExpectedSwitch) LinkedExpectedSwitch {
	info := LinkedExpectedSwitch{
		BMCMACAddress:      les.GetBmcMacAddress(),
		SwitchSerialNumber: les.GetSwitchSerialNumber(),
	}
	if les.GetSwitchId() != nil {
		info.SwitchID = les.GetSwitchId().GetId()
	}
	if les.GetExpectedSwitchId() != nil {
		info.ExpectedSwitchID = les.GetExpectedSwitchId().GetValue()
	}
	return info
}

// LinkedExpectedPowerShelf represents an expected power shelf linked to its
// explored endpoint and live PowerShelf resource in Core.
type LinkedExpectedPowerShelf struct {
	BMCMACAddress        string
	PowerShelfID         string // Core's live PowerShelf ID; empty if not yet created
	ExpectedPowerShelfID string
	ShelfSerialNumber    string
}

func linkedExpectedPowerShelfFromPb(leps *pb.LinkedExpectedPowerShelf) LinkedExpectedPowerShelf {
	info := LinkedExpectedPowerShelf{
		BMCMACAddress:     leps.GetBmcMacAddress(),
		ShelfSerialNumber: leps.GetShelfSerialNumber(),
	}
	if leps.GetPowerShelfId() != nil {
		info.PowerShelfID = leps.GetPowerShelfId().GetId()
	}
	if leps.GetExpectedPowerShelfId() != nil {
		info.ExpectedPowerShelfID = leps.GetExpectedPowerShelfId().GetValue()
	}
	return info
}

// AddExpectedSwitchRequest contains the parameters for registering
// an expected switch with NICo.
type AddExpectedSwitchRequest struct {
	BMCMACAddress      string `json:"bmc_mac_address"`
	BMCUsername        string `json:"bmc_username"`
	BMCPassword        string `json:"bmc_password"`
	SwitchSerialNumber string `json:"switch_serial_number,omitempty"`
	RackID             string `json:"rack_id,omitempty"`
	NVOSUsername       string `json:"nvos_username,omitempty"`
	NVOSPassword       string `json:"nvos_password,omitempty"`
}

// BringUpState represents the bring-up state of a machine in
// relation to NICo's power-on gate.
type BringUpState int

const (
	BringUpStateNotDiscovered BringUpState = iota
	BringUpStateWaitingForIngestion
	BringUpStateMachineNotCreated
	BringUpStateMachineCreated
)

func (s BringUpState) String() string {
	switch s {
	case BringUpStateNotDiscovered:
		return "NotDiscovered"
	case BringUpStateWaitingForIngestion:
		return "WaitingForIngestion"
	case BringUpStateMachineNotCreated:
		return "IngestionMachineNotCreated"
	case BringUpStateMachineCreated:
		return "IngestionMachineCreated"
	default:
		return "Unknown"
	}
}

func bringUpStateFromPb(
	s pb.MachineIngestionState,
) BringUpState {
	switch s {
	case pb.MachineIngestionState_WaitingForIngestion:
		return BringUpStateWaitingForIngestion
	case pb.MachineIngestionState_IngestionMachineNotCreated:
		return BringUpStateMachineNotCreated
	case pb.MachineIngestionState_IngestionMachineCreated:
		return BringUpStateMachineCreated
	default:
		return BringUpStateNotDiscovered
	}
}
