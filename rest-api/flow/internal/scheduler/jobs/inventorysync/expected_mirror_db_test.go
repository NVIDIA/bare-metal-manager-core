// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/common/utils"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

// failGetMachinesClient wraps the production mock and forces the machine
// actual-sync RPC to fail, so runActualSync reports allRPCOK=false.
type failGetMachinesClient struct {
	nicoapi.Client
}

func (c *failGetMachinesClient) GetMachines(_ context.Context) ([]nicoapi.MachineDetail, error) {
	return nil, errors.New("boom")
}

// These tests exercise the mirror's write paths against a real database —
// the half that pure-function tests can't reach and where the
// resurrection / rename / runtime-preservation / eviction bugs lived. They
// skip without a DB (CI provides one via DB_PORT).

func mirrorTestPool(t *testing.T) (context.Context, *cdb.Session) {
	t.Helper()
	ctx := context.Background()
	if os.Getenv("DB_PORT") == "" {
		log.Warn().Msg("Not running DB-backed mirror test: no DB environment specified")
		t.SkipNow()
	}
	dbConf, err := cdb.ConfigFromEnv()
	require.NoError(t, err)
	pool, err := utils.UnitTestDB(ctx, t, dbConf)
	require.NoError(t, err)
	return ctx, pool
}

func strPtr(s string) *string { return &s }

func coreRack(rackID, mfr, serial string) nicoapi.ExpectedRackDetail {
	return nicoapi.ExpectedRackDetail{
		RackID: rackID,
		Name:   "rack-" + serial,
		Labels: map[string]string{
			labelChassisManufacturer: mfr,
			labelChassisSerialNumber: serial,
		},
	}
}

// coreRackNamed is coreRack with an explicit name, for cases that contend on
// the chassis pair and so must not also contend on rack_name_idx.
func coreRackNamed(rackID, name, mfr, serial string) nicoapi.ExpectedRackDetail {
	r := coreRack(rackID, mfr, serial)
	r.Name = name
	return r
}

func computeSpec(mfr, serial, mac string) expectedComponentSpec {
	return expectedComponentSpec{
		Type:         devicetypes.ComponentTypeToString(devicetypes.ComponentTypeCompute),
		Manufacturer: mfr,
		SerialNumber: serial,
		Name:         "node-" + serial,
		BMC:          expectedBMCSpec{MACAddress: mac, IPAddress: "10.0.0.1"},
	}
}

// --- rack mirror ----------------------------------------------------------

// #11: a successful but empty Core response soft-deletes mirror-adopted racks,
// while legacy NULL-external_id racks are exempted.
func TestMirrorRacks_EmptyCoreSoftDeletesAdoptedNotLegacy(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	adopted := model.Rack{Name: "adopted", Manufacturer: "Mfg", SerialNumber: "AD-1", ExternalID: strPtr("a12")}
	require.NoError(t, adopted.Create(ctx, pool.DB))
	legacy := model.Rack{Name: "legacy", Manufacturer: "Mfg", SerialNumber: "LG-1"}
	require.NoError(t, legacy.Create(ctx, pool.DB))

	mirrorExpectedRacks(ctx, pool, nil)

	gotAdopted, err := (&model.Rack{ID: adopted.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.NotNil(t, gotAdopted.DeletedAt, "adopted rack absent from Core must be soft-deleted")

	gotLegacy, err := (&model.Rack{ID: legacy.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, gotLegacy.DeletedAt, "legacy NULL-external_id rack must be exempt from mirror deletes")
}

// #1: a soft-deleted rack is resurrected (deleted_at cleared) when Core
// re-reports it, keeping the UUID stable.
func TestMirrorRacks_ResurrectOnReReport(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	r := model.Rack{Name: "res", Manufacturer: "Mfg", SerialNumber: "RS-1", ExternalID: strPtr("a12")}
	require.NoError(t, r.Create(ctx, pool.DB))
	require.NoError(t, r.Delete(ctx, pool.DB))

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{coreRack("a12", "Mfg", "RS-1")})

	got, err := (&model.Rack{ID: r.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt, "re-reported rack must be resurrected (deleted_at cleared)")
	assert.Equal(t, r.ID, got.ID, "resurrection must keep the original UUID")
}

// #2: renaming a rack's Core rack_id updates external_id in place; the stale
// id must not cause a soft-delete in the same cycle.
func TestMirrorRacks_RenameKeepsRow(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	r := model.Rack{Name: "rename", Manufacturer: "Mfg", SerialNumber: "RN-1", ExternalID: strPtr("old")}
	require.NoError(t, r.Create(ctx, pool.DB))

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{coreRack("new", "Mfg", "RN-1")})

	got, err := (&model.Rack{ID: r.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt, "renamed rack must not be soft-deleted")
	require.NotNil(t, got.ExternalID)
	assert.Equal(t, "new", *got.ExternalID, "external_id must be updated to Core's new rack_id")
}

// #3: a Core row missing a chassis label is mirrored, not skipped, and the
// existing Flow rack survives with its own label intact.
func TestMirrorRacks_MissingChassisLabelStillMirrored(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	r := model.Rack{Name: "labelled", Manufacturer: "Mfg", SerialNumber: "MF-1", ExternalID: strPtr("a12")}
	require.NoError(t, r.Create(ctx, pool.DB))

	unlabelled := nicoapi.ExpectedRackDetail{
		RackID: "a12",
		Name:   "still-here",
		Labels: map[string]string{labelChassisSerialNumber: "MF-1"}, // manufacturer missing
	}
	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{unlabelled})

	got, err := (&model.Rack{ID: r.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt, "rack still listed by Core must survive")
	assert.Equal(t, "still-here", got.Name, "the row must be updated, proving Core's row was not skipped")
	assert.Equal(t, "Mfg", got.Manufacturer, "Core omitting a label must not erase Flow's copy")
}

// A Core rack carrying no chassis labels at all is mirrored under its rack_id.
// This is the case that used to be skipped outright.
func TestMirrorRacks_NoChassisLabelsStillMirrored(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{
		{RackID: "klamath-1", Name: "klamath-1"},
	})

	var got model.Rack
	require.NoError(t, pool.DB.NewSelect().Model(&got).Where("external_id = ?", "klamath-1").Scan(ctx))
	assert.Empty(t, got.Manufacturer)
	assert.Empty(t, got.SerialNumber)
}

// Several Core racks with no chassis labels must all be mirrored: the labels
// land as NULL, which is distinct in Postgres, so they don't collapse onto one
// slot in rack_manufacturer_serial_idx.
func TestMirrorRacks_UnlabelledRacksDoNotCollapse(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{
		{RackID: "klamath-1", Name: "klamath-1", Labels: map[string]string{labelChassisManufacturer: "NVIDIA"}},
		{RackID: "klamath-2", Name: "klamath-2", Labels: map[string]string{labelChassisManufacturer: "NVIDIA"}},
		{RackID: "klamath-3", Name: "klamath-3", Labels: map[string]string{labelChassisManufacturer: "NVIDIA"}},
		{RackID: "klamath-4", Name: "klamath-4", Labels: map[string]string{labelChassisManufacturer: "NVIDIA"}},
	})

	n, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).Where("manufacturer = ?", "NVIDIA").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 4, n, "every serial-less rack must be mirrored, not deduplicated onto one chassis key")
}

// A rack the mirror has never reached is adopted by its chassis pair: Core's
// rack_id is written onto the existing row rather than inserted as a new one.
func TestMirrorRacks_LegacyRackAdoptedByNaturalKey(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	legacy := model.Rack{Name: "legacy", Manufacturer: "Mfg", SerialNumber: "LG-1"}
	require.NoError(t, legacy.Create(ctx, pool.DB))

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{coreRack("a12", "Mfg", "LG-1")})

	total, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, total, "adoption must reuse the existing row, not insert a second rack")

	got, err := (&model.Rack{ID: legacy.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt)
	require.NotNil(t, got.ExternalID)
	assert.Equal(t, "a12", *got.ExternalID)
}

// A rack stored without chassis labels picks them up once Core starts sending
// them.
func TestMirrorRacks_ChassisLabelsBackfilled(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	r := model.Rack{Name: "backfill", ExternalID: strPtr("a12")}
	require.NoError(t, r.Create(ctx, pool.DB))

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{coreRack("a12", "Mfg", "BF-1")})

	got, err := (&model.Rack{ID: r.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Equal(t, "Mfg", got.Manufacturer)
	assert.Equal(t, "BF-1", got.SerialNumber)
}

// A Core rack whose chassis pair matches an already-identified Flow rack must
// not take that rack's row while Core still reports the rack_id on it.
func TestMirrorRacks_AdoptionDoesNotStealAnIdentifiedRack(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	owner := model.Rack{Name: "owner", Manufacturer: "Mfg", SerialNumber: "ST-1", ExternalID: strPtr("a12")}
	require.NoError(t, owner.Create(ctx, pool.DB))

	// Both racks claim the same chassis; a12 already holds the Flow row.
	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{
		coreRackNamed("b34", "rack-b34", "Mfg", "ST-1"),
		coreRackNamed("a12", "rack-a12", "Mfg", "ST-1"),
	})

	got, err := (&model.Rack{ID: owner.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt)
	require.NotNil(t, got.ExternalID)
	assert.Equal(t, "a12", *got.ExternalID, "the row must stay with the rack_id already on it")
	assert.Equal(t, "ST-1", got.SerialNumber, "the owner keeps the contested chassis pair")

	var intruder model.Rack
	require.NoError(t, pool.DB.NewSelect().Model(&intruder).Where("external_id = ?", "b34").Scan(ctx))
	assert.Empty(t, intruder.SerialNumber, "the second rack is mirrored without the contested pair")
}

// #4: two Core racks reporting the same chassis must not abort the cycle on
// rack_manufacturer_serial_idx. Both racks are mirrored; only the first keeps
// the contested labels.
func TestMirrorRacks_DuplicateChassisNoAbort(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{
		coreRackNamed("a12", "rack-a12", "Mfg", "DUP-1"),
		coreRackNamed("b34", "rack-b34", "Mfg", "DUP-1"),
	})

	total, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, total, "both racks must be mirrored under their own rack_id")

	withSerial, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).Where("serial_number = ?", "DUP-1").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, withSerial, "only one rack may hold the contested chassis pair")
}

// Two Core racks resolving to the same name must not abort the cycle on
// rack_name_idx: the second write is skipped and the first still lands.
func TestMirrorRacks_DuplicateNameNoAbort(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{
		coreRackNamed("a12", "same-name", "Mfg", "NM-1"),
		coreRackNamed("b34", "same-name", "Mfg", "NM-2"),
	})

	total, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, total, "the first rack must land; the second is skipped, not left to abort the cycle")

	var got model.Rack
	require.NoError(t, pool.DB.NewSelect().Model(&got).Where("name = ?", "same-name").Scan(ctx))
	assert.Equal(t, "NM-1", got.SerialNumber)
}

// #8: an empty Core description must not wipe operator-set rack metadata.
func TestMirrorRacks_EmptyDescriptionPreserved(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	r := model.Rack{
		Name:         "desc",
		Manufacturer: "Mfg",
		SerialNumber: "DS-1",
		ExternalID:   strPtr("a12"),
		Description:  map[string]any{"text": "operator note"},
	}
	require.NoError(t, r.Create(ctx, pool.DB))

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{coreRack("a12", "Mfg", "DS-1")})

	got, err := (&model.Rack{ID: r.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	require.NotNil(t, got.Description)
	assert.Equal(t, "operator note", got.Description["text"], "empty Core description must not wipe operator metadata")
}

// #6: a Core rack whose name collides with a different live Flow rack must be
// skipped, not abort the cycle on the unique name index.
func TestMirrorRacks_NameCollisionWithLiveRackSkips(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	live := model.Rack{Name: "collide", Manufacturer: "Mfg", SerialNumber: "LIVE-1", ExternalID: strPtr("x")}
	require.NoError(t, live.Create(ctx, pool.DB))

	collidingCore := nicoapi.ExpectedRackDetail{
		RackID: "y",
		Name:   "collide", // same name, different chassis
		Labels: map[string]string{
			labelChassisManufacturer: "Mfg",
			labelChassisSerialNumber: "NEW-1",
		},
	}
	// Include the live rack's own Core row so it isn't soft-deleted for absence.
	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{
		coreRack("x", "Mfg", "LIVE-1"),
		collidingCore,
	})

	gotLive, err := (&model.Rack{ID: live.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, gotLive.DeletedAt, "the live rack holding the name must survive")

	n, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).Where("serial_number = ?", "NEW-1").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "the colliding-name insert must be skipped, not committed or aborting the cycle")
}

// --- component mirror -----------------------------------------------------

func compType() string {
	return devicetypes.ComponentTypeToString(devicetypes.ComponentTypeCompute)
}

// #11: a successful but empty Core response soft-deletes all Flow components
// of the type.
func TestMirrorComponents_EmptyCoreSoftDeletesAll(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	c := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-DEL-1"}
	require.NoError(t, c.Create(ctx, pool.DB))

	mirrorExpectedComponents(ctx, pool, compType(), nil, map[string]uuid.UUID{})

	got, err := (&model.Component{ID: c.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.NotNil(t, got.DeletedAt, "component absent from a successful empty Core response must be soft-deleted")
}

// #1: a soft-deleted component is resurrected when Core re-reports it.
func TestMirrorComponents_ResurrectOnReReport(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	c := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-RES-1"}
	require.NoError(t, c.Create(ctx, pool.DB))
	require.NoError(t, c.Delete(ctx, pool.DB))

	mirrorExpectedComponents(ctx, pool, compType(),
		[]expectedComponentSpec{computeSpec("Mfg", "C-RES-1", "aa:bb:cc:dd:ee:01")},
		map[string]uuid.UUID{})

	got, err := (&model.Component{ID: c.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt, "re-reported component must be resurrected")
	assert.Equal(t, c.ID, got.ID, "resurrection must keep the original UUID")
}

// #5: an UPDATE must touch only mirror-managed columns and leave runtime-owned
// columns (external_id, power_state, firmware_version) intact.
func TestMirrorComponents_UpdatePreservesRuntimeColumns(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	on := nicoapi.PowerStateOn
	c := model.Component{
		Type:            compType(),
		Manufacturer:    "Mfg",
		SerialNumber:    "C-UPD-1",
		Model:           "old-model",
		ComponentID:     strPtr("runtime-ext-id"),
		PowerState:      &on,
		FirmwareVersion: "9.9.9",
	}
	require.NoError(t, c.Create(ctx, pool.DB))
	hostBMC := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:10",
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
		ComponentID: c.ID,
		IPAddress:   strPtr("10.0.0.1"),
	}
	_, err := pool.DB.NewInsert().Model(&hostBMC).Exec(ctx)
	require.NoError(t, err)

	spec := computeSpec("Mfg", "C-UPD-1", "aa:bb:cc:dd:ee:10")
	spec.Model = "new-model"
	mirrorExpectedComponents(ctx, pool, compType(), []expectedComponentSpec{spec}, map[string]uuid.UUID{})

	got, err := (&model.Component{ID: c.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Equal(t, "new-model", got.Model, "mirror-managed model must be updated")
	require.NotNil(t, got.ComponentID)
	assert.Equal(t, "runtime-ext-id", *got.ComponentID, "external_id is runtime-owned, must survive")
	require.NotNil(t, got.PowerState)
	assert.Equal(t, nicoapi.PowerStateOn, *got.PowerState, "power_state is runtime-owned, must survive")
	assert.Equal(t, "9.9.9", got.FirmwareVersion, "firmware_version is runtime-owned, must survive")
}

// #6: a host BMC insert whose MAC collides with an existing non-host (DPU) BMC
// must be refused — the DPU row must not be evicted.
func TestMirrorComponents_EvictRefusesNonHostBMC(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	const sharedMAC = "aa:bb:cc:dd:ee:50"

	// Component A keeps a host BMC (so it isn't re-inserted) plus a DPU BMC
	// on the contested MAC.
	a := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-A"}
	require.NoError(t, a.Create(ctx, pool.DB))
	for _, b := range []model.BMC{
		{MacAddress: "aa:bb:cc:dd:ee:0a", Type: devicetypes.BMCTypeToString(devicetypes.BMCTypeHost), ComponentID: a.ID, IPAddress: strPtr("10.0.0.10")},
		{MacAddress: sharedMAC, Type: devicetypes.BMCTypeToString(devicetypes.BMCTypeDPU), ComponentID: a.ID, IPAddress: strPtr("10.0.0.50")},
	} {
		b := b
		_, err := pool.DB.NewInsert().Model(&b).Exec(ctx)
		require.NoError(t, err)
	}

	specs := []expectedComponentSpec{
		computeSpec("Mfg", "C-A", "aa:bb:cc:dd:ee:0a"), // matches A's existing host BMC
		computeSpec("Mfg", "C-B", sharedMAC),           // new component, host BMC collides with A's DPU
	}
	mirrorExpectedComponents(ctx, pool, compType(), specs, map[string]uuid.UUID{})

	// A's DPU BMC must still be present and still a DPU.
	var dpu model.BMC
	err := pool.DB.NewSelect().Model(&dpu).Where("mac_address = ?", sharedMAC).Scan(ctx)
	require.NoError(t, err, "the DPU BMC must not have been evicted")
	assert.Equal(t, devicetypes.BMCTypeToString(devicetypes.BMCTypeDPU), dpu.Type)
	assert.Equal(t, a.ID, dpu.ComponentID, "DPU BMC must still belong to component A")

	// B must be inserted but carry no BMC (the colliding host insert was skipped).
	b, err := (&model.Component{Manufacturer: "Mfg", SerialNumber: "C-B"}).Get(ctx, pool.DB)
	require.NoError(t, err)
	assert.Empty(t, b.BMCs, "B's host BMC insert must be skipped, not steal the DPU MAC")
}

// #10: when an actual-sync RPC fails, the component_drift table must be left
// intact rather than wiped with a partial view.
func TestRunInventoryOne_DriftTablePreservedOnRPCFailure(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	// A compute component so syncMachines reaches GetMachines (which fails).
	c := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-DRIFT-1"}
	require.NoError(t, c.Create(ctx, pool.DB))

	// A pre-existing drift row that must survive the failed cycle.
	existing := model.ComponentDrift{
		ComponentID: &c.ID,
		DriftType:   model.DriftTypeMissingInActual,
		Diffs:       []model.FieldDiff{},
		CheckedAt:   time.Now(),
	}
	_, err := pool.DB.NewInsert().Model(&existing).Exec(ctx)
	require.NoError(t, err)

	client := &failGetMachinesClient{Client: nicoapi.NewMockClient()}
	runInventoryOne(ctx, pool, client, false)

	n, err := pool.DB.NewSelect().Model((*model.ComponentDrift)(nil)).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "drift table must not be wiped when an actual-sync RPC failed")
}

// #4: two specs reporting the same manufacturer and serial must not abort the
// transaction on component_manufacturer_serial_idx. Both are mirrored under
// their own BMC MAC; only the first keeps the contested labels.
func TestMirrorComponents_DuplicateSerialNoAbort(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	specs := []expectedComponentSpec{
		computeSpec("Mfg", "C-DUP", "aa:bb:cc:dd:ee:21"),
		computeSpec("Mfg", "C-DUP", "aa:bb:cc:dd:ee:22"),
	}
	mirrorExpectedComponents(ctx, pool, compType(), specs, map[string]uuid.UUID{})

	total, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, total, "both components must be mirrored under their own BMC MAC")

	withSerial, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Where("serial_number = ?", "C-DUP").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, withSerial, "only one component may hold the contested manufacturer and serial")
}

// Core reporting the same BMC MAC on two specs is a Core-side fault:
// bmc.mac_address is a primary key, so the later spec is dropped.
func TestMirrorComponents_DuplicateMACSkipsLaterSpec(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	specs := []expectedComponentSpec{
		computeSpec("Mfg", "C-MAC-1", "aa:bb:cc:dd:ee:31"),
		computeSpec("Mfg", "C-MAC-2", "aa:bb:cc:dd:ee:31"),
	}
	mirrorExpectedComponents(ctx, pool, compType(), specs, map[string]uuid.UUID{})

	total, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, total, "only the first spec on a MAC may be mirrored")
}

// A spec carrying only a BMC MAC is mirrored; manufacturer and serial land as
// NULL rather than blocking the row.
func TestMirrorComponents_NoLabelsStillMirrored(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	mirrorExpectedComponents(ctx, pool, compType(),
		[]expectedComponentSpec{computeSpec("", "", "aa:bb:cc:dd:ee:41")},
		map[string]uuid.UUID{})

	var bmc model.BMC
	require.NoError(t, pool.DB.NewSelect().Model(&bmc).Where("mac_address = ?", "aa:bb:cc:dd:ee:41").Scan(ctx))

	got, err := (&model.Component{ID: bmc.ComponentID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Empty(t, got.Manufacturer)
	assert.Empty(t, got.SerialNumber)
}

// Relabelling a chassis in Core must not fork the component: the host BMC MAC
// is its identity, so the existing row is updated in place.
func TestMirrorComponents_MatchByMACSurvivesRelabel(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	const mac = "aa:bb:cc:dd:ee:51"
	c := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-OLD"}
	require.NoError(t, c.Create(ctx, pool.DB))
	hostBMC := model.BMC{
		MacAddress:  mac,
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
		ComponentID: c.ID,
	}
	_, err := pool.DB.NewInsert().Model(&hostBMC).Exec(ctx)
	require.NoError(t, err)

	mirrorExpectedComponents(ctx, pool, compType(),
		[]expectedComponentSpec{computeSpec("Mfg", "C-NEW", mac)},
		map[string]uuid.UUID{})

	total, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, total, "the MAC match must update in place, not insert a second component")

	got, err := (&model.Component{ID: c.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt)
	assert.Equal(t, "C-OLD", got.SerialNumber, "a populated serial is not overwritten by Core's new one")
}

// Swapping a BMC board changes the MAC Core reports. The natural key adopts the
// existing row and the BMC is repointed, so the component keeps its UUID.
func TestMirrorComponents_BMCBoardSwapAdoptsByNaturalKey(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	c := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-SWAP"}
	require.NoError(t, c.Create(ctx, pool.DB))
	oldBMC := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:61",
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
		ComponentID: c.ID,
	}
	_, err := pool.DB.NewInsert().Model(&oldBMC).Exec(ctx)
	require.NoError(t, err)

	mirrorExpectedComponents(ctx, pool, compType(),
		[]expectedComponentSpec{computeSpec("Mfg", "C-SWAP", "aa:bb:cc:dd:ee:62")},
		map[string]uuid.UUID{})

	total, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, total, "the natural key must adopt the existing row, not insert a second component")

	got, err := (&model.Component{ID: c.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	require.Len(t, got.BMCs, 1)
	assert.Equal(t, "aa:bb:cc:dd:ee:62", got.BMCs[0].MacAddress, "the host BMC must be repointed to Core's new MAC")
}

// A Flow component with neither a host BMC nor a complete chassis pair can't be
// compared with what Core reported, so the delete phase leaves it alone.
func TestMirrorComponents_UnmatchableRowExemptFromDelete(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	c := model.Component{Type: compType(), Name: "orphan"}
	require.NoError(t, c.Create(ctx, pool.DB))

	mirrorExpectedComponents(ctx, pool, compType(), nil, map[string]uuid.UUID{})

	got, err := (&model.Component{ID: c.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt, "a component the mirror cannot match must not be soft-deleted")
}
