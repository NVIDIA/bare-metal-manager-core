// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
)

// ptr is a generic helper that returns a pointer to the given value.
// Useful for constructing test structs with pointer fields (e.g. *int32, *string).
func ptr[T any](v T) *T { return &v }

func TestCompareMachineFieldsForDrift_NoMismatch(t *testing.T) {
	expected := &model.Component{
		SerialNumber:    "SN001",
		FirmwareVersion: "1.0.0",
		SlotID:          2,
		TrayIndex:       1,
		HostID:          5,
	}
	actual := nicoapi.MachineDetail{
		ChassisSerial:   ptr("SN001"),
		FirmwareVersion: "1.0.0",
	}
	position := nicoapi.MachinePosition{
		PhysicalSlotNum:  ptr(int32(2)),
		ComputeTrayIndex: ptr(int32(1)),
		TopologyID:       ptr(int32(5)),
	}

	diffs := compareMachineFieldsForDrift(expected, actual, &position)
	assert.Empty(t, diffs)
}

func TestCompareMachineFieldsForDrift_AllFieldsMismatch(t *testing.T) {
	expected := &model.Component{
		SerialNumber:    "SN001",
		FirmwareVersion: "1.0.0",
		SlotID:          2,
		TrayIndex:       1,
		HostID:          5,
	}
	actual := nicoapi.MachineDetail{
		ChassisSerial:   ptr("SN999"),
		FirmwareVersion: "2.0.0",
	}
	position := nicoapi.MachinePosition{
		PhysicalSlotNum:  ptr(int32(10)),
		ComputeTrayIndex: ptr(int32(3)),
		TopologyID:       ptr(int32(7)),
	}

	diffs := compareMachineFieldsForDrift(expected, actual, &position)
	assert.Len(t, diffs, 4)

	diffByField := make(map[string]model.FieldDiff)
	for _, d := range diffs {
		diffByField[d.FieldName] = d
	}

	assert.Equal(t, "2", diffByField["slot_id"].ExpectedValue)
	assert.Equal(t, "10", diffByField["slot_id"].ActualValue)

	assert.Equal(t, "1", diffByField["tray_index"].ExpectedValue)
	assert.Equal(t, "3", diffByField["tray_index"].ActualValue)

	assert.Equal(t, "5", diffByField["host_id"].ExpectedValue)
	assert.Equal(t, "7", diffByField["host_id"].ActualValue)

	assert.Equal(t, "SN001", diffByField["serial_number"].ExpectedValue)
	assert.Equal(t, "SN999", diffByField["serial_number"].ActualValue)

	assert.NotContains(t, diffByField, "firmware_version")
}

func TestCompareMachineFieldsForDrift_NilPositionFieldsSkipped(t *testing.T) {
	expected := &model.Component{
		SerialNumber:    "SN001",
		FirmwareVersion: "1.0.0",
		SlotID:          2,
		TrayIndex:       1,
		HostID:          5,
	}
	actual := nicoapi.MachineDetail{
		ChassisSerial:   ptr("SN001"),
		FirmwareVersion: "1.0.0",
	}
	// Position found but all fields nil — should not produce diffs
	position := nicoapi.MachinePosition{}

	diffs := compareMachineFieldsForDrift(expected, actual, &position)
	assert.Empty(t, diffs)
}

func TestCompareMachineFieldsForDrift_NilChassisSerialSkipped(t *testing.T) {
	expected := &model.Component{
		SerialNumber: "SN001",
	}
	// Nil ChassisSerial from NICo — should not flag as mismatch
	actual := nicoapi.MachineDetail{
		ChassisSerial: nil,
	}
	position := nicoapi.MachinePosition{}

	diffs := compareMachineFieldsForDrift(expected, actual, &position)
	assert.Empty(t, diffs)
}

func TestCompareMachineFieldsForDrift_PartialMismatch(t *testing.T) {
	expected := &model.Component{
		SerialNumber:    "SN001",
		FirmwareVersion: "1.0.0",
		SlotID:          2,
		TrayIndex:       1,
		HostID:          5,
	}
	actual := nicoapi.MachineDetail{
		ChassisSerial:   ptr("SN001"), // match
		FirmwareVersion: "2.0.0",      // mismatch
	}
	position := nicoapi.MachinePosition{
		PhysicalSlotNum:  ptr(int32(2)), // match
		ComputeTrayIndex: ptr(int32(1)), // match
		TopologyID:       ptr(int32(9)), // mismatch
	}

	diffs := compareMachineFieldsForDrift(expected, actual, &position)
	assert.Len(t, diffs, 1)

	diffByField := make(map[string]model.FieldDiff)
	for _, d := range diffs {
		diffByField[d.FieldName] = d
	}

	assert.NotContains(t, diffByField, "firmware_version")
	assert.Contains(t, diffByField, "host_id")
	assert.NotContains(t, diffByField, "slot_id")
	assert.NotContains(t, diffByField, "tray_index")
	assert.NotContains(t, diffByField, "serial_number")
}

func TestCompareMachineFieldsForDrift_FirmwareVersionNotCompared(t *testing.T) {
	expected := &model.Component{
		FirmwareVersion: "", // empty in DB
	}
	actual := nicoapi.MachineDetail{
		FirmwareVersion: "2.0.0", // NICo has value — should NOT produce drift (firmware_version is direct-write)
	}
	position := nicoapi.MachinePosition{}

	diffs := compareMachineFieldsForDrift(expected, actual, &position)
	assert.Empty(t, diffs)
}

func TestCompareMachineFieldsForDrift_MissingPositionReportsDrift(t *testing.T) {
	expected := &model.Component{
		SerialNumber:    "SN001",
		FirmwareVersion: "1.0.0",
		SlotID:          2,
		TrayIndex:       1,
		HostID:          5,
	}
	actual := nicoapi.MachineDetail{
		ChassisSerial:   ptr("SN001"),
		FirmwareVersion: "1.0.0",
	}

	// nil position means no entry in positionByID — should flag non-zero expected fields
	diffs := compareMachineFieldsForDrift(expected, actual, nil)
	assert.Len(t, diffs, 3)

	diffByField := make(map[string]model.FieldDiff)
	for _, d := range diffs {
		diffByField[d.FieldName] = d
	}

	assert.Equal(t, "2", diffByField["slot_id"].ExpectedValue)
	assert.Equal(t, "<missing>", diffByField["slot_id"].ActualValue)

	assert.Equal(t, "1", diffByField["tray_index"].ExpectedValue)
	assert.Equal(t, "<missing>", diffByField["tray_index"].ActualValue)

	assert.Equal(t, "5", diffByField["host_id"].ExpectedValue)
	assert.Equal(t, "<missing>", diffByField["host_id"].ActualValue)
}

func TestCompareMachineFieldsForDrift_MissingPositionZeroExpectedNoDrift(t *testing.T) {
	expected := &model.Component{
		SerialNumber: "SN001",
		SlotID:       0,
		TrayIndex:    0,
		HostID:       0,
	}
	actual := nicoapi.MachineDetail{
		ChassisSerial: ptr("SN001"),
	}

	// nil position with zero-value expected fields — no position drift
	diffs := compareMachineFieldsForDrift(expected, actual, nil)
	assert.Empty(t, diffs)
}
