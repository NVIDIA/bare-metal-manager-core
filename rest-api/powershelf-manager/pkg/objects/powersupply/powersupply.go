// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package powersupply

import (
	"fmt"
	"strings"

	"github.com/stmcginnis/gofish/common"
	"github.com/stmcginnis/gofish/redfish"
)

// PowerSupply is a snapshot of a Power Supply Unit.
type PowerSupply struct {
	common.Entity
	CapacityWatts string
	// FirmwareVersion shall contain the firmware version as
	// defined by the manufacturer for the associated power supply.
	FirmwareVersion string
	HardwareVersion string
	// Location shall contain location information of the
	// associated power supply.
	Location redfish.PartLocation
	// HotPluggable shall indicate whether the device can be inserted or removed while the underlying equipment
	// otherwise remains in its current operational state. Devices indicated as hot-pluggable shall allow the device to
	// become operable without altering the operational state of the underlying equipment. Devices that cannot be
	// inserted or removed from equipment in operation, or devices that cannot become operable without affecting the
	// operational state of that equipment, shall be indicated as not hot-pluggable.
	HotPluggable   bool
	InputSourceNum int
	// Manufacturer shall be the name of the
	// organization responsible for producing the power supply. This
	// organization might be the entity from whom the power supply is
	// purchased, but this is not necessarily true.
	Manufacturer string
	// Model shall contain the model information as defined
	// by the manufacturer for the associated power supply.
	Model      string
	PowerState bool
	// SerialNumber shall contain the serial number as
	// defined by the manufacturer for the associated power supply.
	SerialNumber string
	Sensors      []*redfish.Sensor
	// Status shall contain any status or health properties
	// of the resource.
	Status common.Status
}

// Summary returns a summary of the PowerSupply as a string.
func (psu *PowerSupply) Summary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s Summary:\n", psu.Name))
	sb.WriteString(fmt.Sprintf("  ID: %s\n", psu.ID))
	sb.WriteString(fmt.Sprintf("  Name: %s\n", psu.Name))
	sb.WriteString(fmt.Sprintf("  CapacityWatts: %s\n", psu.CapacityWatts))
	sb.WriteString(fmt.Sprintf("  FirmwareVersion: %s\n", psu.FirmwareVersion))
	sb.WriteString(fmt.Sprintf("  HardwareVersion: %s\n", psu.HardwareVersion))
	sb.WriteString(fmt.Sprintf("  HotPluggable: %t\n", psu.HotPluggable))
	sb.WriteString(fmt.Sprintf("  InputSourceNum: %d\n", psu.InputSourceNum))
	sb.WriteString(fmt.Sprintf("  Manufacturer: %s\n", psu.Manufacturer))
	sb.WriteString(fmt.Sprintf("  Model: %s\n", psu.Model))
	sb.WriteString(fmt.Sprintf("  PowerState: %t\n", psu.PowerState))
	sb.WriteString(fmt.Sprintf("  SerialNumber: %s\n", psu.SerialNumber))
	sb.WriteString(fmt.Sprintf("  Status: %s\n", psu.Status.State))
	sb.WriteString(fmt.Sprintf("  Health: %s\n", psu.Status.Health))
	sb.WriteString("  Location:\n")
	sb.WriteString(fmt.Sprintf("    LocationOrdinalValue: %d\n", psu.Location.LocationOrdinalValue))
	sb.WriteString(fmt.Sprintf("    LocationType: %s\n", psu.Location.LocationType))
	sb.WriteString(fmt.Sprintf("    ServiceLabel: %s\n", psu.Location.ServiceLabel))
	sb.WriteString("  Sensors:\n")
	for _, sensor := range psu.Sensors {
		sb.WriteString(fmt.Sprintf("    @odataid: %s\n", sensor.ODataID))
		sb.WriteString(fmt.Sprintf("    Id: %s\n", sensor.ID))
		sb.WriteString(fmt.Sprintf("    Name: %s\n", sensor.Name))
		sb.WriteString(fmt.Sprintf("    Reading: %f\n", sensor.Reading))
		sb.WriteString(fmt.Sprintf("    ReadingRangeMax: %f\n", sensor.ReadingRangeMax))
		sb.WriteString(fmt.Sprintf("    ReadingRangeMin: %f\n", sensor.ReadingRangeMin))
		sb.WriteString(fmt.Sprintf("    ReadingType: %s\n", sensor.ReadingType))
		sb.WriteString(fmt.Sprintf("    ReadingUnits: %s\n", sensor.ReadingUnits))
		sb.WriteString("    Thresholds:\n")
		sb.WriteString(fmt.Sprintf("        LowerCaution: %f\n", sensor.Thresholds.LowerCaution.Reading))
		sb.WriteString(fmt.Sprintf("        LowerCritical: %f\n", sensor.Thresholds.LowerCritical.Reading))
		sb.WriteString(fmt.Sprintf("        UpperCaution: %f\n", sensor.Thresholds.UpperCaution.Reading))
		sb.WriteString(fmt.Sprintf("        UpperCritical: %f\n", sensor.Thresholds.UpperCritical.Reading))
	}

	return sb.String()
}
