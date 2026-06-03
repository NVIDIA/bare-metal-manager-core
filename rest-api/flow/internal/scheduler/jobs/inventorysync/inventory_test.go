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

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/common/utils"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
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

	runInventoryOne(ctx, pool, grpcMock)

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

	runInventoryOne(ctx, pool, grpcMock)

	var updated1 model.Component
	err = pool.DB.NewSelect().Model(&updated1).Where("id = ?", c1.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "2.0.0", updated1.FirmwareVersion)

	var updated2 model.Component
	err = pool.DB.NewSelect().Model(&updated2).Where("id = ?", c2.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "3.1.0", updated2.FirmwareVersion)
}
