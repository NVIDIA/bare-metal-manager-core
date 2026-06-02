// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/common/utils"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/nsmapi"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/psmapi"
	cmconfig "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/config"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providerapi"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

// TestInventory is the main test for the inventory package
func TestInventory(t *testing.T) {
	ctx := context.Background()

	if os.Getenv("DB_PORT") == "" {
		log.Warn().Msgf("Not running unit test due to no DB environment specified")
		t.SkipNow()
	}

	dbConf, err := cdb.ConfigFromEnv()
	assert.Nil(t, err)
	pool, err := utils.UnitTestDB(ctx, t, dbConf)
	assert.Nil(t, err)

	grpcMock := nicoapi.NewMockClient()

	// Create a basic faked GRPC environment
	serial1 := "serial1"
	serial2 := "serial2"
	serial3 := "serial3"
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "id1", ChassisSerial: &serial1})
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "id2", ChassisSerial: &serial2})
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "id3", ChassisSerial: &serial3})
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "id4", ChassisSerial: nil})
	grpcMock.AddPowerState("id2", nicoapi.PowerStateOn)

	// Create a rack (required for components due to NOT NULL constraint)
	rack := model.Rack{
		Name:         "test-rack",
		Manufacturer: "TestMfg",
		SerialNumber: "rack-serial-001",
	}
	err = rack.Create(ctx, pool.DB)
	assert.Nil(t, err)

	// Create components with required fields (manufacturer and rack_id are NOT NULL)
	c := model.Component{SerialNumber: "serial2", Manufacturer: "TestMfg", RackID: rack.ID}
	err = c.Create(ctx, pool.DB)
	assert.Nil(t, err)
	c = model.Component{SerialNumber: "serial4", Manufacturer: "TestMfg2", RackID: rack.ID}
	err = c.Create(ctx, pool.DB)
	assert.Nil(t, err)

	psmMock := psmapi.NewMockClient()
	nsmMock := nsmapi.NewMockClient()
	runInventoryOne(ctx, pool, grpcMock, psmMock, nsmMock, defaultComponentManagerTestConfig())

	rows, err := pool.DB.Query("SELECT serial_number, power_state FROM component;")
	assert.NotNil(t, rows)
	assert.Nil(t, err)
	defer rows.Close()

	var found int
	for rows.Next() {
		var serial string
		var state *nicoapi.PowerState
		rows.Scan(&serial, &state)

		switch serial {
		case "serial2":
			assert.Equal(t, *state, nicoapi.PowerStateOn)
			found++
		case "serial4":
			assert.Nil(t, state)
			found++
		default:
			panic(fmt.Sprintf("Invalid row found: %v %v", serial, state))
		}
	}
	assert.Equal(t, 2, found)
}

// TestSyncFirmwareVersion verifies that syncMachines direct-writes firmware_version
// from NICo machine details to the component table.
func TestSyncFirmwareVersion(t *testing.T) {
	ctx := context.Background()

	if os.Getenv("DB_PORT") == "" {
		log.Warn().Msgf("Not running unit test due to no DB environment specified")
		t.SkipNow()
	}

	dbConf, err := cdb.ConfigFromEnv()
	assert.Nil(t, err)
	pool, err := utils.UnitTestDB(ctx, t, dbConf)
	assert.Nil(t, err)

	grpcMock := nicoapi.NewMockClient()

	serial1 := "fw-serial-1"
	serial2 := "fw-serial-2"
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "fw-id1", ChassisSerial: &serial1, FirmwareVersion: "2.0.0"})
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "fw-id2", ChassisSerial: &serial2, FirmwareVersion: "3.1.0"})
	grpcMock.AddPowerState("fw-id1", nicoapi.PowerStateOn)

	rack := model.Rack{
		Name:         "test-rack-fw",
		Manufacturer: "TestMfg",
		SerialNumber: "rack-serial-fw",
	}
	err = rack.Create(ctx, pool.DB)
	assert.Nil(t, err)

	c1 := model.Component{SerialNumber: "fw-serial-1", Manufacturer: "TestMfg", RackID: rack.ID, FirmwareVersion: "1.0.0"}
	err = c1.Create(ctx, pool.DB)
	assert.Nil(t, err)

	c2 := model.Component{SerialNumber: "fw-serial-2", Manufacturer: "TestMfg", RackID: rack.ID, FirmwareVersion: "1.0.0"}
	err = c2.Create(ctx, pool.DB)
	assert.Nil(t, err)

	psmMock := psmapi.NewMockClient()
	nsmMock := nsmapi.NewMockClient()
	runInventoryOne(ctx, pool, grpcMock, psmMock, nsmMock, defaultComponentManagerTestConfig())

	var updated1 model.Component
	err = pool.DB.NewSelect().Model(&updated1).Where("id = ?", c1.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "2.0.0", updated1.FirmwareVersion)

	var updated2 model.Component
	err = pool.DB.NewSelect().Model(&updated2).Where("id = ?", c2.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "3.1.0", updated2.FirmwareVersion)
}

// TestHandleExpectedPowershelves tests that expected powershelves are registered with PSM
func TestHandleExpectedPowershelves(t *testing.T) {
	ctx := context.Background()

	if os.Getenv("DB_PORT") == "" {
		log.Warn().Msgf("Not running unit test due to no DB environment specified")
		t.SkipNow()
	}

	dbConf, err := cdb.ConfigFromEnv()
	assert.Nil(t, err)
	pool, err := utils.UnitTestDB(ctx, t, dbConf)
	assert.Nil(t, err)

	// Create mock clients
	nicoMock := nicoapi.NewMockClient()
	psmMock := psmapi.NewMockClient()

	// Create a rack (required for components)
	rack := model.Rack{
		Name:         "test-rack",
		Manufacturer: "TestMfg",
		SerialNumber: "rack-serial-001",
	}
	err = rack.Create(ctx, pool.DB)
	assert.Nil(t, err)

	// Create PowerShelf components with PMCs (BMCs)
	// PMC 1: Expected powershelf with DHCPed interface
	ps1 := model.Component{
		Name:         "powershelf-1",
		Type:         devicetypes.ComponentTypePowerShelf.String(),
		Manufacturer: "LiteonMfg",
		SerialNumber: "ps-serial-001",
		RackID:       rack.ID,
	}
	err = ps1.Create(ctx, pool.DB)
	assert.Nil(t, err)

	// Add PMC (BMC) for powershelf 1
	pmc1 := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:01",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: ps1.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return pmc1.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// PMC 2: Expected powershelf with DHCPed interface
	ps2 := model.Component{
		Name:         "powershelf-2",
		Type:         devicetypes.ComponentTypePowerShelf.String(),
		Manufacturer: "LiteonMfg",
		SerialNumber: "ps-serial-002",
		RackID:       rack.ID,
	}
	err = ps2.Create(ctx, pool.DB)
	assert.Nil(t, err)

	pmc2 := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:02",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: ps2.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return pmc2.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// PMC 3: Expected powershelf but NOT DHCPed (no interface in nico)
	ps3 := model.Component{
		Name:         "powershelf-3",
		Type:         devicetypes.ComponentTypePowerShelf.String(),
		Manufacturer: "LiteonMfg",
		SerialNumber: "ps-serial-003",
		RackID:       rack.ID,
	}
	err = ps3.Create(ctx, pool.DB)
	assert.Nil(t, err)

	pmc3 := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:03",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: ps3.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return pmc3.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// PMC 4: Already registered powershelf - should update firmware version and power state
	ps4 := model.Component{
		Name:            "powershelf-4",
		Type:            devicetypes.ComponentTypePowerShelf.String(),
		Manufacturer:    "LiteonMfg",
		SerialNumber:    "ps-serial-004",
		RackID:          rack.ID,
		FirmwareVersion: "1.0.0", // Old firmware version
	}
	err = ps4.Create(ctx, pool.DB)
	assert.Nil(t, err)

	pmc4 := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:04",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: ps4.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return pmc4.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// Pre-register PMC 4 in PSM with updated firmware version and PSUs
	psmMock.AddPowershelf(psmapi.PowerShelf{
		PMC: psmapi.PowerManagementController{
			MACAddress:      "aa:bb:cc:dd:ee:04",
			IPAddress:       "10.0.0.104",
			FirmwareVersion: "2.0.0", // New firmware version
		},
		PSUs: []psmapi.PowerSupplyUnit{
			{PowerState: true}, // On
			{PowerState: true}, // On
		},
	})

	// PMC 5: Already registered powershelf with mixed PSU power states (should be Unknown)
	ps5 := model.Component{
		Name:            "powershelf-5",
		Type:            devicetypes.ComponentTypePowerShelf.String(),
		Manufacturer:    "LiteonMfg",
		SerialNumber:    "ps-serial-005",
		RackID:          rack.ID,
		FirmwareVersion: "1.0.0",
	}
	err = ps5.Create(ctx, pool.DB)
	assert.Nil(t, err)

	pmc5 := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:05",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: ps5.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return pmc5.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// Pre-register PMC 5 in PSM with mixed PSU power states
	psmMock.AddPowershelf(psmapi.PowerShelf{
		PMC: psmapi.PowerManagementController{
			MACAddress:      "aa:bb:cc:dd:ee:05",
			IPAddress:       "10.0.0.105",
			FirmwareVersion: "2.1.0",
		},
		PSUs: []psmapi.PowerSupplyUnit{
			{PowerState: true},  // On
			{PowerState: false}, // Off - mixed state
		},
	})

	// PMC 6: Already registered powershelf with all PSUs off (should be PowerStateOff)
	ps6 := model.Component{
		Name:            "powershelf-6",
		Type:            devicetypes.ComponentTypePowerShelf.String(),
		Manufacturer:    "LiteonMfg",
		SerialNumber:    "ps-serial-006",
		RackID:          rack.ID,
		FirmwareVersion: "1.0.0",
	}
	err = ps6.Create(ctx, pool.DB)
	assert.Nil(t, err)

	pmc6 := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:06",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: ps6.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return pmc6.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// Pre-register PMC 6 in PSM with all PSUs off
	psmMock.AddPowershelf(psmapi.PowerShelf{
		PMC: psmapi.PowerManagementController{
			MACAddress:      "aa:bb:cc:dd:ee:06",
			IPAddress:       "10.0.0.106",
			FirmwareVersion: "2.2.0",
		},
		PSUs: []psmapi.PowerSupplyUnit{
			{PowerState: false}, // Off
			{PowerState: false}, // Off
		},
	})

	// PMC 7: DHCPed but with multiple IP addresses (should skip registration)
	ps7 := model.Component{
		Name:         "powershelf-7",
		Type:         devicetypes.ComponentTypePowerShelf.String(),
		Manufacturer: "LiteonMfg",
		SerialNumber: "ps-serial-007",
		RackID:       rack.ID,
	}
	err = ps7.Create(ctx, pool.DB)
	assert.Nil(t, err)

	pmc7 := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:07",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: ps7.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return pmc7.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// Add machine interfaces to nico mock
	// PMC 1 has DHCPed
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "aa:bb:cc:dd:ee:01",
		Addresses:  []string{"10.0.0.101"},
	})

	// PMC 2 has DHCPed
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "aa:bb:cc:dd:ee:02",
		Addresses:  []string{"10.0.0.102"},
	})

	// Random BMC interfaces (not expected powershelves)
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "ff:ff:ff:ff:ff:01",
		Addresses:  []string{"10.0.0.201"},
	})
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "ff:ff:ff:ff:ff:02",
		Addresses:  []string{"10.0.0.202"},
	})

	// PMC 7 has multiple IP addresses (unexpected, should skip registration)
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "aa:bb:cc:dd:ee:07",
		Addresses:  []string{"10.0.0.107", "10.0.0.108"}, // Multiple IPs
	})

	// PMC 3 is NOT in nico (hasn't DHCPed)

	// Verify we have 3 pre-registered powershelves before running inventory
	preRegistered, err := psmMock.GetPowershelves(ctx, []string{})
	assert.Nil(t, err)
	assert.Equal(t, 3, len(preRegistered), "Should have 3 pre-registered powershelves (PMC 4, 5, 6)")

	// Run the inventory loop
	nsmMock := nsmapi.NewMockClient()
	runInventoryOne(ctx, pool, nicoMock, psmMock, nsmMock, defaultComponentManagerTestConfig())

	// Verify that only expected PMCs that have DHCPed were registered with PSM
	registeredPowershelves, err := psmMock.GetPowershelves(ctx, []string{})
	assert.Nil(t, err)

	// Should have 5 total powershelves: PMC 4, 5, 6 (pre-registered) + PMC 1, 2 (newly registered)
	// PMC 3 (not DHCPed), PMC 7 (multiple IPs), and the random ones should NOT be registered
	assert.Equal(t, 5, len(registeredPowershelves))

	// Build a map for easier verification
	registeredByMac := make(map[string]psmapi.PowerShelf)
	for _, ps := range registeredPowershelves {
		registeredByMac[ps.PMC.MACAddress] = ps
	}

	// Verify PMC 1 was registered with correct IP
	ps1Registered, ok := registeredByMac["aa:bb:cc:dd:ee:01"]
	assert.True(t, ok, "PMC 1 should be registered")
	assert.Equal(t, "10.0.0.101", ps1Registered.PMC.IPAddress)

	// Verify PMC 2 was registered with correct IP
	ps2Registered, ok := registeredByMac["aa:bb:cc:dd:ee:02"]
	assert.True(t, ok, "PMC 2 should be registered")
	assert.Equal(t, "10.0.0.102", ps2Registered.PMC.IPAddress)

	// Verify PMC 3 was NOT registered (not DHCPed)
	_, ok = registeredByMac["aa:bb:cc:dd:ee:03"]
	assert.False(t, ok, "PMC 3 should NOT be registered (not DHCPed)")

	// Verify random BMCs were NOT registered
	_, ok = registeredByMac["ff:ff:ff:ff:ff:01"]
	assert.False(t, ok, "Random BMC 1 should NOT be registered")
	_, ok = registeredByMac["ff:ff:ff:ff:ff:02"]
	assert.False(t, ok, "Random BMC 2 should NOT be registered")

	// Verify power state and firmware version updates in the component table
	// PMC 4: Should have updated firmware version and PowerStateOn (all PSUs on)
	var updatedPs4 model.Component
	err = pool.DB.NewSelect().Model(&updatedPs4).Where("id = ?", ps4.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "2.0.0", updatedPs4.FirmwareVersion, "PMC 4 firmware version should be updated")
	assert.NotNil(t, updatedPs4.PowerState, "PMC 4 power state should be set")
	assert.Equal(t, nicoapi.PowerStateOn, *updatedPs4.PowerState, "PMC 4 should be PowerStateOn (all PSUs on)")

	// PMC 5: Should have updated firmware version and PowerStateUnknown (mixed PSU states)
	var updatedPs5 model.Component
	err = pool.DB.NewSelect().Model(&updatedPs5).Where("id = ?", ps5.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "2.1.0", updatedPs5.FirmwareVersion, "PMC 5 firmware version should be updated")
	assert.NotNil(t, updatedPs5.PowerState, "PMC 5 power state should be set")
	assert.Equal(t, nicoapi.PowerStateUnknown, *updatedPs5.PowerState, "PMC 5 should be PowerStateUnknown (mixed PSU states)")

	// PMC 6: Should have updated firmware version and PowerStateOff (all PSUs off)
	var updatedPs6 model.Component
	err = pool.DB.NewSelect().Model(&updatedPs6).Where("id = ?", ps6.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "2.2.0", updatedPs6.FirmwareVersion, "PMC 6 firmware version should be updated")
	assert.NotNil(t, updatedPs6.PowerState, "PMC 6 power state should be set")
	assert.Equal(t, nicoapi.PowerStateOff, *updatedPs6.PowerState, "PMC 6 should be PowerStateOff (all PSUs off)")

	// PMC 7: Should NOT be registered (multiple IP addresses)
	_, ok = registeredByMac["aa:bb:cc:dd:ee:07"]
	assert.False(t, ok, "PMC 7 should NOT be registered (multiple IP addresses)")
}

// TestHandleExpectedNVSwitches tests that expected NVSwitches are registered with NSM
func TestHandleExpectedNVSwitches(t *testing.T) {
	ctx := context.Background()

	if os.Getenv("DB_PORT") == "" {
		log.Warn().Msgf("Not running unit test due to no DB environment specified")
		t.SkipNow()
	}

	dbConf, err := cdb.ConfigFromEnv()
	assert.Nil(t, err)
	pool, err := utils.UnitTestDB(ctx, t, dbConf)
	assert.Nil(t, err)

	nicoMock := nicoapi.NewMockClient()
	nsmMock := nsmapi.NewMockClient()
	psmMock := psmapi.NewMockClient()

	rack := model.Rack{
		Name:         "test-rack",
		Manufacturer: "TestMfg",
		SerialNumber: "rack-serial-001",
	}
	err = rack.Create(ctx, pool.DB)
	assert.Nil(t, err)

	// --- SW1: Happy path, BMC + NVOS DHCPed, should be newly registered ---
	sw1 := model.Component{
		Name:         "nvswitch-1",
		Type:         devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
		Manufacturer: "NVMfg",
		SerialNumber: "sw-serial-001",
		RackID:       rack.ID,
	}
	err = sw1.Create(ctx, pool.DB)
	assert.Nil(t, err)

	bmc1 := model.BMC{
		MacAddress:  "aa:bb:cc:11:11:01",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: sw1.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return bmc1.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// --- SW2: Happy path, second new registration ---
	sw2 := model.Component{
		Name:         "nvswitch-2",
		Type:         devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
		Manufacturer: "NVMfg",
		SerialNumber: "sw-serial-002",
		RackID:       rack.ID,
	}
	err = sw2.Create(ctx, pool.DB)
	assert.Nil(t, err)

	bmc2 := model.BMC{
		MacAddress:  "aa:bb:cc:11:11:02",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: sw2.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return bmc2.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// --- SW3: BMC has NOT DHCPed — should NOT register, produces missing_in_actual drift ---
	sw3 := model.Component{
		Name:         "nvswitch-3",
		Type:         devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
		Manufacturer: "NVMfg",
		SerialNumber: "sw-serial-003",
		RackID:       rack.ID,
	}
	err = sw3.Create(ctx, pool.DB)
	assert.Nil(t, err)

	bmc3 := model.BMC{
		MacAddress:  "aa:bb:cc:11:11:03",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: sw3.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return bmc3.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// --- SW4: BMC DHCPed but NVOS NOT DHCPed — should NOT register, produces missing_in_actual drift ---
	sw4 := model.Component{
		Name:         "nvswitch-4",
		Type:         devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
		Manufacturer: "NVMfg",
		SerialNumber: "sw-serial-004",
		RackID:       rack.ID,
	}
	err = sw4.Create(ctx, pool.DB)
	assert.Nil(t, err)

	bmc4 := model.BMC{
		MacAddress:  "aa:bb:cc:11:11:04",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: sw4.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return bmc4.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// --- SW5: Not in NICo expected switches — should NOT register ---
	sw5 := model.Component{
		Name:         "nvswitch-5",
		Type:         devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
		Manufacturer: "NVMfg",
		SerialNumber: "sw-serial-005",
		RackID:       rack.ID,
	}
	err = sw5.Create(ctx, pool.DB)
	assert.Nil(t, err)

	bmc5 := model.BMC{
		MacAddress:  "aa:bb:cc:11:11:05",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: sw5.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return bmc5.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// --- SW6: BMC has multiple IPs — should NOT register ---
	sw6 := model.Component{
		Name:         "nvswitch-6",
		Type:         devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
		Manufacturer: "NVMfg",
		SerialNumber: "sw-serial-006",
		RackID:       rack.ID,
	}
	err = sw6.Create(ctx, pool.DB)
	assert.Nil(t, err)

	bmc6 := model.BMC{
		MacAddress:  "aa:bb:cc:11:11:06",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: sw6.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return bmc6.Create(ctx, tx)
	})
	assert.Nil(t, err)

	// --- SW7: Already registered with NSM — should direct-write firmware_version + external_id, serial mismatch drift ---
	sw7 := model.Component{
		Name:            "nvswitch-7",
		Type:            devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
		Manufacturer:    "NVMfg",
		SerialNumber:    "sw-serial-007",
		RackID:          rack.ID,
		FirmwareVersion: "1.0.0",
	}
	err = sw7.Create(ctx, pool.DB)
	assert.Nil(t, err)

	bmc7 := model.BMC{
		MacAddress:  "aa:bb:cc:11:11:07",
		Type:        devicetypes.BMCTypeHost.String(),
		ComponentID: sw7.ID,
	}
	err = pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return bmc7.Create(ctx, tx)
	})
	assert.Nil(t, err)

	nsmMock.AddNVSwitch(nsmapi.NVSwitchTray{
		UUID:          "nsm-uuid-sw7",
		BMCMACAddress: "aa:bb:cc:11:11:07",
		BMCIPAddress:  "10.0.0.207",
		BMCFirmware:   "2.0.0",
		ChassisSerial: "actual-serial-007", // Different from DB serial to trigger drift
	})

	// --- NICo expected switches (metadata with host_mac_address for NVOS) ---
	// SW1-SW4 and SW6 have expected switch entries; SW5 intentionally omitted
	nicoMock.AddExpectedSwitchInfo(nicoapi.ExpectedSwitchInfo{
		BMCMACAddress: "aa:bb:cc:11:11:01",
		Metadata:      map[string]string{"host_mac_address": "dd:ee:ff:11:11:01"},
	})
	nicoMock.AddExpectedSwitchInfo(nicoapi.ExpectedSwitchInfo{
		BMCMACAddress: "aa:bb:cc:11:11:02",
		Metadata:      map[string]string{"host_mac_address": "dd:ee:ff:11:11:02"},
	})
	nicoMock.AddExpectedSwitchInfo(nicoapi.ExpectedSwitchInfo{
		BMCMACAddress: "aa:bb:cc:11:11:03",
		Metadata:      map[string]string{"host_mac_address": "dd:ee:ff:11:11:03"},
	})
	nicoMock.AddExpectedSwitchInfo(nicoapi.ExpectedSwitchInfo{
		BMCMACAddress: "aa:bb:cc:11:11:04",
		Metadata:      map[string]string{"host_mac_address": "dd:ee:ff:11:11:04"},
	})
	nicoMock.AddExpectedSwitchInfo(nicoapi.ExpectedSwitchInfo{
		BMCMACAddress: "aa:bb:cc:11:11:06",
		Metadata:      map[string]string{"host_mac_address": "dd:ee:ff:11:11:06"},
	})
	nicoMock.AddExpectedSwitchInfo(nicoapi.ExpectedSwitchInfo{
		BMCMACAddress: "aa:bb:cc:11:11:07",
		Metadata:      map[string]string{"host_mac_address": "dd:ee:ff:11:11:07"},
	})

	// --- NICo machine interfaces (DHCP status) ---
	// SW1: BMC DHCPed, NVOS DHCPed
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "aa:bb:cc:11:11:01",
		Addresses:  []string{"10.0.0.101"},
	})
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "dd:ee:ff:11:11:01",
		Addresses:  []string{"10.0.1.101"},
	})

	// SW2: BMC DHCPed, NVOS DHCPed
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "aa:bb:cc:11:11:02",
		Addresses:  []string{"10.0.0.102"},
	})
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "dd:ee:ff:11:11:02",
		Addresses:  []string{"10.0.1.102"},
	})

	// SW3: BMC NOT DHCPed (no interface entry)

	// SW4: BMC DHCPed, NVOS NOT DHCPed
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "aa:bb:cc:11:11:04",
		Addresses:  []string{"10.0.0.104"},
	})
	// NVOS for SW4 intentionally absent

	// SW5: BMC DHCPed (but not in expected switches, so won't look up NVOS)
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "aa:bb:cc:11:11:05",
		Addresses:  []string{"10.0.0.105"},
	})

	// SW6: BMC has multiple IPs
	nicoMock.AddMachineInterface(nicoapi.MachineInterface{
		MacAddress: "aa:bb:cc:11:11:06",
		Addresses:  []string{"10.0.0.106", "10.0.0.116"},
	})

	// Verify pre-registered state
	preRegistered, err := nsmMock.GetNVSwitches(ctx, nil)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(preRegistered), "Should have 1 pre-registered switch (SW7)")

	// Run the inventory loop
	runInventoryOne(ctx, pool, nicoMock, psmMock, nsmMock, defaultComponentManagerTestConfig())

	// --- Verify NSM registrations ---
	registeredSwitches, err := nsmMock.GetNVSwitches(ctx, nil)
	assert.Nil(t, err)

	// Should have 3 total: SW7 (pre-registered) + SW1, SW2 (newly registered)
	assert.Equal(t, 3, len(registeredSwitches))

	registeredByMac := make(map[string]nsmapi.NVSwitchTray)
	for _, sw := range registeredSwitches {
		registeredByMac[sw.BMCMACAddress] = sw
	}

	// SW1 registered with correct BMC IP
	sw1Registered, ok := registeredByMac["aa:bb:cc:11:11:01"]
	assert.True(t, ok, "SW1 should be registered")
	assert.Equal(t, "10.0.0.101", sw1Registered.BMCIPAddress)

	// SW2 registered with correct BMC IP
	sw2Registered, ok := registeredByMac["aa:bb:cc:11:11:02"]
	assert.True(t, ok, "SW2 should be registered")
	assert.Equal(t, "10.0.0.102", sw2Registered.BMCIPAddress)

	// SW3 NOT registered (BMC not DHCPed)
	_, ok = registeredByMac["aa:bb:cc:11:11:03"]
	assert.False(t, ok, "SW3 should NOT be registered (BMC not DHCPed)")

	// SW4 NOT registered (NVOS not DHCPed)
	_, ok = registeredByMac["aa:bb:cc:11:11:04"]
	assert.False(t, ok, "SW4 should NOT be registered (NVOS not DHCPed)")

	// SW5 NOT registered (not in NICo expected switches)
	_, ok = registeredByMac["aa:bb:cc:11:11:05"]
	assert.False(t, ok, "SW5 should NOT be registered (not in NICo expected switches)")

	// SW6 NOT registered (multiple BMC IPs)
	_, ok = registeredByMac["aa:bb:cc:11:11:06"]
	assert.False(t, ok, "SW6 should NOT be registered (multiple BMC IPs)")

	// --- Verify direct-write updates for SW7 (pre-registered) ---
	var updatedSw7 model.Component
	err = pool.DB.NewSelect().Model(&updatedSw7).Where("id = ?", sw7.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "2.0.0", updatedSw7.FirmwareVersion, "SW7 firmware version should be updated from NSM")
	assert.NotNil(t, updatedSw7.ComponentID, "SW7 external_id should be set")
	assert.Equal(t, "nsm-uuid-sw7", *updatedSw7.ComponentID, "SW7 external_id should match NSM UUID")

	// SW1 and SW2 should NOT have external_id or firmware_version yet (just registered, not synced)
	var preSw1 model.Component
	err = pool.DB.NewSelect().Model(&preSw1).Where("id = ?", sw1.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Nil(t, preSw1.ComponentID, "SW1 external_id should not be set before second cycle")
	assert.Empty(t, preSw1.FirmwareVersion, "SW1 firmware version should not be set before second cycle")

	var preSw2 model.Component
	err = pool.DB.NewSelect().Model(&preSw2).Where("id = ?", sw2.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Nil(t, preSw2.ComponentID, "SW2 external_id should not be set before second cycle")
	assert.Empty(t, preSw2.FirmwareVersion, "SW2 firmware version should not be set before second cycle")

	// --- Second inventory cycle: SW1 and SW2 are now registered in NSM ---
	// Simulate NSM having discovered firmware versions after registration
	nsmMock.SetNVSwitchFirmware("aa:bb:cc:11:11:01", "3.0.0")
	nsmMock.SetNVSwitchFirmware("aa:bb:cc:11:11:02", "3.1.0")

	runInventoryOne(ctx, pool, nicoMock, psmMock, nsmMock, defaultComponentManagerTestConfig())

	// SW1: external_id and firmware_version should now be set
	var updatedSw1 model.Component
	err = pool.DB.NewSelect().Model(&updatedSw1).Where("id = ?", sw1.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.NotNil(t, updatedSw1.ComponentID, "SW1 external_id should be set after second cycle")
	assert.Equal(t, sw1Registered.UUID, *updatedSw1.ComponentID, "SW1 external_id should match NSM UUID")
	assert.Equal(t, "3.0.0", updatedSw1.FirmwareVersion, "SW1 firmware version should be updated from NSM")

	// SW2: external_id and firmware_version should now be set
	var updatedSw2 model.Component
	err = pool.DB.NewSelect().Model(&updatedSw2).Where("id = ?", sw2.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.NotNil(t, updatedSw2.ComponentID, "SW2 external_id should be set after second cycle")
	assert.Equal(t, sw2Registered.UUID, *updatedSw2.ComponentID, "SW2 external_id should match NSM UUID")
	assert.Equal(t, "3.1.0", updatedSw2.FirmwareVersion, "SW2 firmware version should be updated from NSM")

	// --- Verify drift records ---
	allDrifts, err := model.GetAllDrifts(ctx, pool.DB)
	assert.Nil(t, err)

	driftByComponentID := make(map[string]model.ComponentDrift)
	for _, d := range allDrifts {
		if d.ComponentID != nil {
			driftByComponentID[d.ComponentID.String()] = d
		}
	}

	// SW3: missing_in_actual (BMC not DHCPed)
	sw3Drift, hasSw3Drift := driftByComponentID[sw3.ID.String()]
	assert.True(t, hasSw3Drift, "SW3 should have a drift record")
	if hasSw3Drift {
		assert.Equal(t, model.DriftTypeMissingInActual, sw3Drift.DriftType)
	}

	// SW4: missing_in_actual (NVOS not DHCPed)
	sw4Drift, hasSw4Drift := driftByComponentID[sw4.ID.String()]
	assert.True(t, hasSw4Drift, "SW4 should have a drift record")
	if hasSw4Drift {
		assert.Equal(t, model.DriftTypeMissingInActual, sw4Drift.DriftType)
	}

	// SW7: mismatch drift (serial_number differs between DB and NSM)
	sw7Drift, hasSw7Drift := driftByComponentID[sw7.ID.String()]
	assert.True(t, hasSw7Drift, "SW7 should have a drift record (serial mismatch)")
	if hasSw7Drift {
		assert.Equal(t, model.DriftTypeMismatch, sw7Drift.DriftType)
		assert.Equal(t, 1, len(sw7Drift.Diffs))
		if len(sw7Drift.Diffs) > 0 {
			assert.Equal(t, "serial_number", sw7Drift.Diffs[0].FieldName)
			assert.Equal(t, "sw-serial-007", sw7Drift.Diffs[0].ExpectedValue)
			assert.Equal(t, "actual-serial-007", sw7Drift.Diffs[0].ActualValue)
		}
	}
}

func defaultComponentManagerTestConfig() cmconfig.Config {
	return cmconfig.Config{
		ComponentManagers: map[devicetypes.ComponentType]string{
			devicetypes.ComponentTypeCompute:    "mock",
			devicetypes.ComponentTypeNVSwitch:   "mock",
			devicetypes.ComponentTypePowerShelf: "mock",
		},
		ProviderConfigs: map[string]providerapi.ProviderConfig{},
	}
}
