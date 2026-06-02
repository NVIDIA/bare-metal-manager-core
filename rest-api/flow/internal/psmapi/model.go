// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package psmapi

import (
	"fmt"
	"time"

	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/psmapi/gen"
)

// PMCVendor enumerates supported PMC vendors.
type PMCVendor int

const (
	PMCVendorUnknown PMCVendor = 0
	PMCVendorLiteon  PMCVendor = 1
)

func pmcVendorFromPb(v pb.PMCVendor) PMCVendor {
	switch v {
	case pb.PMCVendor_PMC_TYPE_LITEON:
		return PMCVendorLiteon
	default:
		return PMCVendorUnknown
	}
}

func pmcVendorToPb(v PMCVendor) pb.PMCVendor {
	switch v {
	case PMCVendorLiteon:
		return pb.PMCVendor_PMC_TYPE_LITEON
	default:
		return pb.PMCVendor_PMC_TYPE_UNKNOWN
	}
}

// PowerManagementController contains PMC identity and metadata.
type PowerManagementController struct {
	MACAddress      string
	IPAddress       string
	Vendor          PMCVendor
	SerialNumber    string
	Model           string
	Manufacturer    string
	PartNumber      string
	FirmwareVersion string
	HardwareVersion string
}

func pmcFromPb(pmc *pb.PowerManagementController) PowerManagementController {
	if pmc == nil {
		return PowerManagementController{}
	}
	return PowerManagementController{
		MACAddress:      pmc.MacAddress,
		IPAddress:       pmc.IpAddress,
		Vendor:          pmcVendorFromPb(pmc.Vendor),
		SerialNumber:    pmc.SerialNumber,
		Model:           pmc.Model,
		Manufacturer:    pmc.Manufacturer,
		PartNumber:      pmc.PartNumber,
		FirmwareVersion: pmc.FirmwareVersion,
		HardwareVersion: pmc.HardwareVersion,
	}
}

// Chassis contains chassis identity and model/manufacturer fields.
type Chassis struct {
	SerialNumber string
	Model        string
	Manufacturer string
}

func chassisFromPb(chassis *pb.Chassis) Chassis {
	if chassis == nil {
		return Chassis{}
	}
	return Chassis{
		SerialNumber: chassis.SerialNumber,
		Model:        chassis.Model,
		Manufacturer: chassis.Manufacturer,
	}
}

// SensorThresholds contains threshold values for a sensor.
type SensorThresholds struct {
	LowerCaution  float32
	LowerCritical float32
	UpperCaution  float32
	UpperCritical float32
}

func sensorThresholdsFromPb(thresholds *pb.SensorThresholds) SensorThresholds {
	if thresholds == nil {
		return SensorThresholds{}
	}
	st := SensorThresholds{}
	if thresholds.LowerCaution != nil {
		st.LowerCaution = thresholds.LowerCaution.Reading
	}
	if thresholds.LowerCritical != nil {
		st.LowerCritical = thresholds.LowerCritical.Reading
	}
	if thresholds.UpperCaution != nil {
		st.UpperCaution = thresholds.UpperCaution.Reading
	}
	if thresholds.UpperCritical != nil {
		st.UpperCritical = thresholds.UpperCritical.Reading
	}
	return st
}

// Sensor captures a single sensor reading, thresholds, and units.
type Sensor struct {
	ID              string
	Name            string
	Reading         float32
	ReadingRangeMax float64
	ReadingRangeMin float32
	ReadingType     string
	ReadingUnits    string
	Thresholds      SensorThresholds
}

func sensorFromPb(sensor *pb.Sensor) Sensor {
	if sensor == nil {
		return Sensor{}
	}
	return Sensor{
		ID:              sensor.Id,
		Name:            sensor.Name,
		Reading:         sensor.Reading,
		ReadingRangeMax: sensor.ReadingRangeMax,
		ReadingRangeMin: sensor.ReadingRangeMin,
		ReadingType:     sensor.ReadingType,
		ReadingUnits:    sensor.ReadingUnits,
		Thresholds:      sensorThresholdsFromPb(sensor.Thresholds),
	}
}

// PowerSupplyUnit contains power supply hardware/firmware and sensor data.
type PowerSupplyUnit struct {
	ID              string
	Name            string
	Manufacturer    string
	Model           string
	SerialNumber    string
	CapacityWatts   string
	FirmwareVersion string
	HardwareVersion string
	PowerState      bool
	Sensors         []Sensor
}

func psuFromPb(psu *pb.PowerSupplyUnit) PowerSupplyUnit {
	if psu == nil {
		return PowerSupplyUnit{}
	}
	result := PowerSupplyUnit{
		ID:              psu.Id,
		Name:            psu.Name,
		Manufacturer:    psu.Manufacturer,
		Model:           psu.Model,
		SerialNumber:    psu.SerialNumber,
		CapacityWatts:   psu.CapacityWatts,
		FirmwareVersion: psu.FirmwareVersion,
		HardwareVersion: psu.HardwareVersion,
		PowerState:      psu.PowerState,
	}
	for _, sensor := range psu.Sensors {
		result.Sensors = append(result.Sensors, sensorFromPb(sensor))
	}
	return result
}

// PowerShelf represents a complete powershelf with its PMC, chassis, and PSUs.
type PowerShelf struct {
	PMC     PowerManagementController
	Chassis Chassis
	PSUs    []PowerSupplyUnit
}

func powerShelfFromPb(ps *pb.PowerShelf) PowerShelf {
	if ps == nil {
		return PowerShelf{}
	}
	result := PowerShelf{
		PMC:     pmcFromPb(ps.Pmc),
		Chassis: chassisFromPb(ps.Chassis),
	}
	for _, psu := range ps.Psus {
		result.PSUs = append(result.PSUs, psuFromPb(psu))
	}
	return result
}

// Credentials wraps around a username and password.
type Credentials struct {
	Username string
	Password string
}

func credentialsToPb(c Credentials) *pb.Credentials {
	return &pb.Credentials{
		Username: c.Username,
		Password: c.Password,
	}
}

// RegisterPowershelfRequest contains the information needed to register a powershelf.
type RegisterPowershelfRequest struct {
	PMCMACAddress  string
	PMCIPAddress   string
	PMCVendor      PMCVendor
	PMCCredentials Credentials
}

func registerPowershelfRequestToPb(req RegisterPowershelfRequest) *pb.RegisterPowershelfRequest {
	return &pb.RegisterPowershelfRequest{
		PmcMacAddress:  req.PMCMACAddress,
		PmcIpAddress:   req.PMCIPAddress,
		PmcVendor:      pmcVendorToPb(req.PMCVendor),
		PmcCredentials: credentialsToPb(req.PMCCredentials),
	}
}

// StatusCode represents the result of an operation.
type StatusCode int

const (
	StatusSuccess         StatusCode = 0
	StatusInvalidArgument StatusCode = 1
	StatusInternalError   StatusCode = 2
)

func statusCodeFromPb(sc pb.StatusCode) StatusCode {
	switch sc {
	case pb.StatusCode_SUCCESS:
		return StatusSuccess
	case pb.StatusCode_INVALID_ARGUMENT:
		return StatusInvalidArgument
	case pb.StatusCode_INTERNAL_ERROR:
		return StatusInternalError
	default:
		return StatusInternalError
	}
}

// RegisterPowershelfResponse contains the result of registering a powershelf.
type RegisterPowershelfResponse struct {
	PMCMACAddress string
	IsNew         bool
	Created       time.Time
	Status        StatusCode
	Error         string
}

func registerPowershelfResponseFromPb(resp *pb.RegisterPowershelfResponse) RegisterPowershelfResponse {
	result := RegisterPowershelfResponse{
		PMCMACAddress: resp.PmcMacAddress,
		IsNew:         resp.IsNew,
		Status:        statusCodeFromPb(resp.Status),
		Error:         resp.Error,
	}
	if resp.Created != nil {
		result.Created = resp.Created.AsTime()
	}
	return result
}

// PowerControlResult contains the result of a power control operation.
type PowerControlResult struct {
	PMCMACAddress string
	Status        StatusCode
	Error         string
}

func powerControlResultFromPb(resp *pb.PowershelfResponse) PowerControlResult {
	return PowerControlResult{
		PMCMACAddress: resp.PmcMacAddress,
		Status:        statusCodeFromPb(resp.Status),
		Error:         resp.Error,
	}
}

// PowershelfComponent represents a component type for firmware updates.
type PowershelfComponent int

const (
	PowershelfComponentPMC PowershelfComponent = 0
	PowershelfComponentPSU PowershelfComponent = 1
)

func (c PowershelfComponent) String() string {
	switch c {
	case PowershelfComponentPMC:
		return "PMC"
	case PowershelfComponentPSU:
		return "PSU"
	default:
		return fmt.Sprintf("Unknown: %d", c)
	}
}

func componentFromPb(c pb.PowershelfComponent) PowershelfComponent {
	switch c {
	case pb.PowershelfComponent_PMC:
		return PowershelfComponentPMC
	case pb.PowershelfComponent_PSU:
		return PowershelfComponentPSU
	default:
		return PowershelfComponentPMC
	}
}

func componentToPb(c PowershelfComponent) pb.PowershelfComponent {
	switch c {
	case PowershelfComponentPMC:
		return pb.PowershelfComponent_PMC
	case PowershelfComponentPSU:
		return pb.PowershelfComponent_PSU
	default:
		return pb.PowershelfComponent_PMC
	}
}

// FirmwareVersion represents a firmware version.
type FirmwareVersion struct {
	Version string
}

// UpdateComponentFirmwareRequest specifies a firmware update for a single component.
type UpdateComponentFirmwareRequest struct {
	Component PowershelfComponent
	UpgradeTo FirmwareVersion
}

// UpdatePowershelfFirmwareRequest specifies firmware updates for a powershelf.
type UpdatePowershelfFirmwareRequest struct {
	PMCMACAddress string
	Components    []UpdateComponentFirmwareRequest
}

func updatePowershelfFirmwareRequestToPb(req UpdatePowershelfFirmwareRequest) *pb.UpdatePowershelfFirmwareRequest {
	pbReq := &pb.UpdatePowershelfFirmwareRequest{
		PmcMacAddress: req.PMCMACAddress,
	}
	for _, comp := range req.Components {
		pbReq.Components = append(pbReq.Components, &pb.UpdateComponentFirmwareRequest{
			Component: componentToPb(comp.Component),
			UpgradeTo: &pb.FirmwareVersion{Version: comp.UpgradeTo.Version},
		})
	}
	return pbReq
}

// UpdateComponentFirmwareResponse contains the result of updating firmware for a component.
type UpdateComponentFirmwareResponse struct {
	Component PowershelfComponent
	Status    StatusCode
	Error     string
}

func updateComponentFirmwareResponseFromPb(resp *pb.UpdateComponentFirmwareResponse) UpdateComponentFirmwareResponse {
	return UpdateComponentFirmwareResponse{
		Component: componentFromPb(resp.Component),
		Status:    statusCodeFromPb(resp.Status),
		Error:     resp.Error,
	}
}

// UpdatePowershelfFirmwareResponse contains the result of updating firmware for a powershelf.
type UpdatePowershelfFirmwareResponse struct {
	PMCMACAddress string
	Components    []UpdateComponentFirmwareResponse
}

func updatePowershelfFirmwareResponseFromPb(resp *pb.UpdatePowershelfFirmwareResponse) UpdatePowershelfFirmwareResponse {
	result := UpdatePowershelfFirmwareResponse{
		PMCMACAddress: resp.PmcMacAddress,
	}
	for _, comp := range resp.Components {
		result.Components = append(result.Components, updateComponentFirmwareResponseFromPb(comp))
	}
	return result
}

// FirmwareUpdateQuery specifies a single PMC MAC and component to query for firmware update status.
type FirmwareUpdateQuery struct {
	PMCMACAddress string
	Component     PowershelfComponent
}

func firmwareUpdateQueryToPb(q FirmwareUpdateQuery) *pb.FirmwareUpdateQuery {
	return &pb.FirmwareUpdateQuery{
		PmcMacAddress: q.PMCMACAddress,
		Component:     componentToPb(q.Component),
	}
}

// FirmwareUpdateState represents the state of a firmware update operation.
type FirmwareUpdateState int

const (
	FirmwareUpdateStateUnknown   FirmwareUpdateState = 0
	FirmwareUpdateStateQueued    FirmwareUpdateState = 1
	FirmwareUpdateStateVerifying FirmwareUpdateState = 2
	FirmwareUpdateStateCompleted FirmwareUpdateState = 3
	FirmwareUpdateStateFailed    FirmwareUpdateState = 4
)

func firmwareUpdateStateFromPb(s pb.FirmwareUpdateState) FirmwareUpdateState {
	switch s {
	case pb.FirmwareUpdateState_FIRMWARE_UPDATE_STATE_QUEUED:
		return FirmwareUpdateStateQueued
	case pb.FirmwareUpdateState_FIRMWARE_UPDATE_STATE_VERIFYING:
		return FirmwareUpdateStateVerifying
	case pb.FirmwareUpdateState_FIRMWARE_UPDATE_STATE_COMPLETED:
		return FirmwareUpdateStateCompleted
	case pb.FirmwareUpdateState_FIRMWARE_UPDATE_STATE_FAILED:
		return FirmwareUpdateStateFailed
	default:
		return FirmwareUpdateStateUnknown
	}
}

// FirmwareUpdateStatus contains the status of a firmware update operation.
type FirmwareUpdateStatus struct {
	PMCMACAddress string
	Component     PowershelfComponent
	State         FirmwareUpdateState
	Status        StatusCode
	Error         string
}

func firmwareUpdateStatusFromPb(s *pb.FirmwareUpdateStatus) FirmwareUpdateStatus {
	return FirmwareUpdateStatus{
		PMCMACAddress: s.PmcMacAddress,
		Component:     componentFromPb(s.Component),
		State:         firmwareUpdateStateFromPb(s.State),
		Status:        statusCodeFromPb(s.Status),
		Error:         s.Error,
	}
}

// ComponentFirmwareUpgrades contains available firmware upgrades for a component.
type ComponentFirmwareUpgrades struct {
	Component PowershelfComponent
	Upgrades  []FirmwareVersion
}

func componentFirmwareUpgradesFromPb(u *pb.ComponentFirmwareUpgrades) ComponentFirmwareUpgrades {
	result := ComponentFirmwareUpgrades{
		Component: componentFromPb(u.Component),
	}
	for _, v := range u.Upgrades {
		result.Upgrades = append(result.Upgrades, FirmwareVersion{Version: v.Version})
	}
	return result
}

// AvailableFirmware contains available firmware upgrades for a powershelf.
type AvailableFirmware struct {
	PMCMACAddress string
	Upgrades      []ComponentFirmwareUpgrades
}

func availableFirmwareFromPb(a *pb.AvailableFirmware) AvailableFirmware {
	result := AvailableFirmware{
		PMCMACAddress: a.PmcMacAddress,
	}
	for _, u := range a.Upgrades {
		result.Upgrades = append(result.Upgrades, componentFirmwareUpgradesFromPb(u))
	}
	return result
}
