// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/common/utils"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

// createTestBMC inserts a single BMC row for the given component so BMC-MAC
// linking has a MAC to correlate on.
func createTestBMC(ctx context.Context, t *testing.T, pool *cdb.Session, componentID uuid.UUID, mac string) {
	t.Helper()
	bmc := model.BMC{MacAddress: mac, ComponentID: componentID, Type: "Host"}
	_, err := pool.DB.NewInsert().Model(&bmc).Exec(ctx)
	assert.Nil(t, err)
}

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

	// Create a basic faked GRPC environment. Linking is keyed on BMC MAC now
	// (matched against the machine's BmcMac), so machines no longer carry a
	// chassis serial for correlation.
	mac2 := "aa:bb:cc:dd:ee:02"
	mac4 := "aa:bb:cc:dd:ee:04"
	hostType := corev1.MachineType_HOST.String()
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "id1", MachineType: hostType})
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "id2", BmcMac: mac2, MachineType: hostType})
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "id3", MachineType: hostType})
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "id4", MachineType: hostType})
	grpcMock.AddPowerState("id2", nicoapi.PowerStateOn)

	// serial2's BMC MAC (mac2) matches machine id2; serial4's BMC MAC (mac4)
	// matches no machine, so it stays unmatched (missing_in_actual).

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
	createTestBMC(ctx, t, pool, c.ID, mac2)
	c = model.Component{SerialNumber: "serial4", Manufacturer: "TestMfg2", RackID: rack.ID}
	err = c.Create(ctx, pool.DB)
	assert.Nil(t, err)
	createTestBMC(ctx, t, pool, c.ID, mac4)

	// expectedSyncEnabled=false: this test exercises actual-sync only. The
	// mock carries no expected machines, so running the mirror would treat
	// that as Core authoritatively reporting zero compute components and
	// soft-delete serial2/serial4 before actual-sync runs. The mirror has
	// its own coverage in expected_mirror_db_test.go.
	runInventoryOne(ctx, pool, grpcMock, false)

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

	// Link both components to their Core machines by BMC MAC (matched against
	// the machine's BmcMac).
	mac1 := "aa:bb:cc:dd:ff:01"
	mac2 := "aa:bb:cc:dd:ff:02"
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "fw-id1", BmcMac: mac1, FirmwareVersion: "2.0.0", MachineType: corev1.MachineType_HOST.String()})
	grpcMock.AddMachine(nicoapi.MachineDetail{MachineID: "fw-id2", BmcMac: mac2, FirmwareVersion: "3.1.0", MachineType: corev1.MachineType_HOST.String()})
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
	createTestBMC(ctx, t, pool, c1.ID, mac1)

	c2 := model.Component{SerialNumber: "fw-serial-2", Manufacturer: "TestMfg", RackID: rack.ID, FirmwareVersion: "1.0.0"}
	err = c2.Create(ctx, pool.DB)
	assert.Nil(t, err)
	createTestBMC(ctx, t, pool, c2.ID, mac2)

	// expectedSyncEnabled=false: actual-sync only. See TestInventory for why
	// the mirror must stay off here (empty expected-mock would soft-delete
	// the components this test relies on).
	runInventoryOne(ctx, pool, grpcMock, false)

	var updated1 model.Component
	err = pool.DB.NewSelect().Model(&updated1).Where("id = ?", c1.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "2.0.0", updated1.FirmwareVersion)

	var updated2 model.Component
	err = pool.DB.NewSelect().Model(&updated2).Where("id = ?", c2.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "3.1.0", updated2.FirmwareVersion)
}

// TestSyncMachineIDs_DpuBmcNotLinked verifies that a compute component owning
// both a host BMC and a DPU BMC links to the HOST machine id, never the DPU's.
// Core exposes the DPU as its own MachineDetail whose BmcMac is the DPU BMC, so
// without the host-only filter the component could resolve to the DPU machine.
func TestSyncMachineIDs_DpuBmcNotLinked(t *testing.T) {
	ctx := context.Background()

	if os.Getenv("DB_PORT") == "" {
		log.Warn().Msgf("Not running unit test due to no DB environment specified")
		t.SkipNow()
	}

	dbConf, err := cdb.ConfigFromEnv()
	assert.Nil(t, err)
	pool, err := utils.UnitTestDB(ctx, t, dbConf)
	assert.Nil(t, err)

	hostMac := "aa:bb:cc:dd:0a:01"
	dpuMac := "aa:bb:cc:dd:0a:02"

	// The DPU machine is listed first so that, without the host-only filter,
	// map-build order alone would not save us; the guard is the type filter.
	allDetails := []nicoapi.MachineDetail{
		{MachineID: "dpu-machine", BmcMac: dpuMac, MachineType: corev1.MachineType_DPU.String()},
		{MachineID: "host-machine", BmcMac: hostMac, MachineType: corev1.MachineType_HOST.String()},
	}

	rack := model.Rack{
		Name:         "test-rack-dpu",
		Manufacturer: "TestMfg",
		SerialNumber: "rack-serial-dpu",
	}
	err = rack.Create(ctx, pool.DB)
	assert.Nil(t, err)

	comp := model.Component{SerialNumber: "dpu-host-serial", Manufacturer: "TestMfg", RackID: rack.ID}
	err = comp.Create(ctx, pool.DB)
	assert.Nil(t, err)
	// Two BMCs on the same compute component: host and DPU.
	createTestBMC(ctx, t, pool, comp.ID, hostMac)
	dpuBMC := model.BMC{MacAddress: dpuMac, ComponentID: comp.ID, Type: "DPU"}
	_, err = pool.DB.NewInsert().Model(&dpuBMC).Exec(ctx)
	assert.Nil(t, err)

	components, err := model.GetComponentsByType(ctx, pool.DB, devicetypes.ComponentTypeCompute)
	assert.Nil(t, err)

	syncMachineIDs(ctx, pool, allDetails, components)

	var updated model.Component
	err = pool.DB.NewSelect().Model(&updated).Where("id = ?", comp.ID).Scan(ctx)
	assert.Nil(t, err)
	assert.NotNil(t, updated.ComponentID)
	assert.Equal(t, "host-machine", *updated.ComponentID)
}
