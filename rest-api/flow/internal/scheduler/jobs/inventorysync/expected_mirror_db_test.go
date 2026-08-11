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

// #3: a Core row that's present but malformed (missing chassis labels) must
// not cause the matching Flow rack to be soft-deleted.
func TestMirrorRacks_MalformedPresentNotDeleted(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	r := model.Rack{Name: "malformed", Manufacturer: "Mfg", SerialNumber: "MF-1", ExternalID: strPtr("a12")}
	require.NoError(t, r.Create(ctx, pool.DB))

	malformed := nicoapi.ExpectedRackDetail{
		RackID: "a12",
		Name:   "still-here",
		Labels: map[string]string{labelChassisSerialNumber: "MF-1"}, // manufacturer missing
	}
	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{malformed})

	got, err := (&model.Rack{ID: r.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt, "rack still listed by Core (even malformed) must survive")
}

// #4: duplicate Core racks for the same chassis must not abort the whole
// transaction on the (manufacturer, serial) unique index.
func TestMirrorRacks_DuplicateChassisNoAbort(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{
		coreRack("a12", "Mfg", "DUP-1"),
		coreRack("b34", "Mfg", "DUP-1"),
	})

	n, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).Where("serial_number = ?", "DUP-1").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "exactly one rack inserted; the duplicate is dropped, not a constraint abort")
}

// Racks with manufacturer but no serial, each with a distinct rack_id, must
// all insert. Postgres treats NULL serials as distinct under
// UNIQUE (manufacturer, serial_number), and matching is by external_id.
func TestMirrorRacks_NullSerialDistinctByExternalID(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	core := make([]nicoapi.ExpectedRackDetail, 0, 4)
	for _, id := range []string{"a12", "b07", "c03", "d09"} {
		core = append(core, nicoapi.ExpectedRackDetail{
			RackID: id,
			Name:   "rack-" + id,
			Labels: map[string]string{labelChassisManufacturer: "NVIDIA"},
		})
	}
	mirrorExpectedRacks(ctx, pool, core)

	n, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).
		Where("manufacturer = ?", "NVIDIA").
		Where("serial_number IS NULL").
		Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 4, n, "four NULL-serial racks with distinct external_ids must all insert")
}

// A NULL-serial rack matched by external_id whose newly-reported serial is
// already held by another rack (here a tombstone, which still occupies the
// unique slot) must be skipped, not written: the write would abort the whole
// rack transaction and take every other rack down with it, every cycle.
func TestMirrorRacks_SerialTakenByTombstoneSkipsUpdate(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	holder := model.Rack{Name: "holder", Manufacturer: "NVIDIA", SerialNumber: "SN-CLASH"}
	require.NoError(t, holder.Create(ctx, pool.DB))
	require.NoError(t, holder.Delete(ctx, pool.DB))

	target := model.Rack{Name: "rack-a12", Manufacturer: "NVIDIA", ExternalID: strPtr("a12")}
	require.NoError(t, target.Create(ctx, pool.DB))
	other := model.Rack{Name: "rack-b07", Manufacturer: "NVIDIA", ExternalID: strPtr("b07")}
	require.NoError(t, other.Create(ctx, pool.DB))

	mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{
		coreRack("a12", "NVIDIA", "SN-CLASH"),
		{RackID: "b07", Name: "rack-b07-renamed", Labels: map[string]string{labelChassisManufacturer: "NVIDIA"}},
	})

	gotTarget, err := (&model.Rack{ID: target.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Empty(t, gotTarget.SerialNumber, "must not write a serial another rack already holds")
	assert.Nil(t, gotTarget.DeletedAt, "a skipped update must not cascade into a soft-delete")

	gotOther, err := (&model.Rack{ID: other.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Equal(t, "rack-b07-renamed", gotOther.Name, "the colliding rack must not block unrelated racks in the same cycle")
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

// A row the mirror has never written an identity_key for must be adopted via
// the derivation rather than duplicated, and the adoption must persist so the
// next cycle matches on the stored value.
func TestMirrorComponents_AdoptsRowWithoutIdentityKey(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	legacy := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-LEGACY"}
	require.NoError(t, legacy.Create(ctx, pool.DB))
	require.Empty(t, legacy.IdentityKey, "fixture must start unadopted")
	hostBMC := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:60",
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
		ComponentID: legacy.ID,
	}
	_, err := pool.DB.NewInsert().Model(&hostBMC).Exec(ctx)
	require.NoError(t, err)

	spec := computeSpec("Mfg", "C-LEGACY", "aa:bb:cc:dd:ee:60")
	mirrorExpectedComponents(ctx, pool, compType(), []expectedComponentSpec{spec}, map[string]uuid.UUID{})

	got, err := (&model.Component{ID: legacy.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt, "adoption must not soft-delete the row it adopted")
	assert.Equal(t, "aa:bb:cc:dd:ee:60", got.IdentityKey, "adoption must persist the derived identity")

	n, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Where("type = ?", compType()).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the unadopted row must be reused, not duplicated")
}

// A replaced BMC board changes the component's identity. Re-inserting would
// be refused forever by the (manufacturer, serial) slot the old row still
// occupies, so the fallback must adopt it and re-key it in place.
func TestMirrorComponents_ReplacedBMCReKeysInPlace(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	c := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-REKEY"}
	require.NoError(t, c.Create(ctx, pool.DB))
	oldBMC := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:80",
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
		ComponentID: c.ID,
	}
	_, err := pool.DB.NewInsert().Model(&oldBMC).Exec(ctx)
	require.NoError(t, err)
	mirrorExpectedComponents(ctx, pool, compType(),
		[]expectedComponentSpec{computeSpec("Mfg", "C-REKEY", "aa:bb:cc:dd:ee:80")},
		map[string]uuid.UUID{})

	// Same chassis, new BMC board.
	mirrorExpectedComponents(ctx, pool, compType(),
		[]expectedComponentSpec{computeSpec("Mfg", "C-REKEY", "aa:bb:cc:dd:ee:81")},
		map[string]uuid.UUID{})

	got, err := (&model.Component{ID: c.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt, "re-keying must not soft-delete the component")
	assert.Equal(t, "aa:bb:cc:dd:ee:81", got.IdentityKey, "identity must follow the new BMC")

	n, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Where("type = ?", compType()).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "a BMC swap must not leave a second component behind")
}

// The natural-key fallback must never take a row another spec claims by
// identity, whatever order the specs arrive in.
func TestMirrorComponents_FallbackYieldsToIdentityClaim(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	// Held by identity aa:bb:cc:dd:ee:90, and also the only holder of
	// (Mfg, C-CONTESTED).
	held := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-CONTESTED"}
	require.NoError(t, held.Create(ctx, pool.DB))
	hostBMC := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:90",
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
		ComponentID: held.ID,
	}
	_, err := pool.DB.NewInsert().Model(&hostBMC).Exec(ctx)
	require.NoError(t, err)

	// The contender is listed first, so a single-pass fallback would let it
	// steal the row before the identity match is ever considered.
	mirrorExpectedComponents(ctx, pool, compType(), []expectedComponentSpec{
		computeSpec("Mfg", "C-CONTESTED", "aa:bb:cc:dd:ee:91"),
		computeSpec("Mfg", "C-CONTESTED", "aa:bb:cc:dd:ee:90"),
	}, map[string]uuid.UUID{})

	got, err := (&model.Component{ID: held.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt)
	assert.Equal(t, "aa:bb:cc:dd:ee:90", got.IdentityKey, "the identity claim must win over the label fallback")
}

// Identity is the host BMC MAC, so the same serial under two manufacturers is
// two components. The previous serial-keyed dedup silently dropped the second.
func TestMirrorComponents_SameSerialDifferentManufacturerBothInsert(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	mirrorExpectedComponents(ctx, pool, compType(), []expectedComponentSpec{
		computeSpec("MfgA", "C-SHARED", "aa:bb:cc:dd:ee:61"),
		computeSpec("MfgB", "C-SHARED", "aa:bb:cc:dd:ee:62"),
	}, map[string]uuid.UUID{})

	n, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Where("serial_number = ?", "C-SHARED").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "a shared serial under distinct manufacturers is two legitimate components")
}

// Same, for the klamath-style rows Core reports without a manufacturer label:
// the pair stores a NULL, so it occupies no unique-index slot at all.
func TestMirrorComponents_SameSerialNoManufacturerBothInsert(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	mirrorExpectedComponents(ctx, pool, compType(), []expectedComponentSpec{
		computeSpec("", "C-UNLABELLED", "aa:bb:cc:dd:ee:63"),
		computeSpec("", "C-UNLABELLED", "aa:bb:cc:dd:ee:64"),
	}, map[string]uuid.UUID{})

	n, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Where("serial_number = ?", "C-UNLABELLED").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "unlabelled rows sharing a serial must not collapse onto one key")
}

// The delete phase keys off identity, so a Flow row Core no longer reports is
// soft-deleted even while some other component Core still reports happens to
// carry the same serial. Keying deletes off serial kept such rows alive
// forever.
func TestMirrorComponents_SharedSerialDoesNotShieldAbsentComponent(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	gone := model.Component{Type: compType(), Manufacturer: "MfgA", SerialNumber: "C-TWIN"}
	require.NoError(t, gone.Create(ctx, pool.DB))
	hostBMC := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:65",
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
		ComponentID: gone.ID,
	}
	_, err := pool.DB.NewInsert().Model(&hostBMC).Exec(ctx)
	require.NoError(t, err)

	// Core reports a different component that shares the serial but not the
	// identity of the row above.
	mirrorExpectedComponents(ctx, pool, compType(), []expectedComponentSpec{
		computeSpec("MfgB", "C-TWIN", "aa:bb:cc:dd:ee:66"),
	}, map[string]uuid.UUID{})

	got, err := (&model.Component{ID: gone.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.NotNil(t, got.DeletedAt, "a component Core stopped reporting must be soft-deleted regardless of who else holds its serial")
}

// identity_key is a denormalised copy of a value that is unique at its source,
// so the index has to be global. Scoped by type it would admit one MAC under
// two component types, which no valid inventory produces.
func TestComponent_IdentityKeyUniqueAcrossTypes(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	first := model.Component{Type: compType(), Name: "c1", IdentityKey: "aa:bb:cc:dd:ee:a0"}
	require.NoError(t, first.Create(ctx, pool.DB))

	second := model.Component{
		Type:        devicetypes.ComponentTypeToString(devicetypes.ComponentTypeNVSwitch),
		Name:        "c2",
		IdentityKey: "aa:bb:cc:dd:ee:a0",
	}
	require.Error(t, second.Create(ctx, pool.DB), "one identity must not appear under two component types")

	// NULL is exempt, so the ingestion gRPC paths stay unconstrained.
	for _, name := range []string{"no-identity-1", "no-identity-2"} {
		c := model.Component{Type: compType(), Name: name}
		require.NoError(t, c.Create(ctx, pool.DB), "rows without an identity must not collide")
	}
}

// bmc_one_host_per_component_idx makes the 1:1 the identity derivation assumes
// enforceable rather than conventional, so hostBMCMac can never have to pick
// between candidates.
func TestBMC_SecondHostBMCPerComponentRejected(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	c := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-1TO1"}
	require.NoError(t, c.Create(ctx, pool.DB))

	hostType := devicetypes.BMCTypeToString(devicetypes.BMCTypeHost)
	first := model.BMC{MacAddress: "aa:bb:cc:dd:ee:70", Type: hostType, ComponentID: c.ID}
	_, err := pool.DB.NewInsert().Model(&first).Exec(ctx)
	require.NoError(t, err)

	second := model.BMC{MacAddress: "aa:bb:cc:dd:ee:71", Type: hostType, ComponentID: c.ID}
	_, err = pool.DB.NewInsert().Model(&second).Exec(ctx)
	require.Error(t, err, "a component must not be able to hold two host BMCs")

	// A DPU BMC is outside the partial index and stays allowed.
	dpu := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:72",
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeDPU),
		ComponentID: c.ID,
	}
	_, err = pool.DB.NewInsert().Model(&dpu).Exec(ctx)
	require.NoError(t, err, "the index must only constrain host BMCs")
}

// #4: duplicate component specs must not abort the transaction. The two specs
// carry distinct identities, so it is the (manufacturer, serial) pair they
// share that has to be kept off one unique-index slot.
func TestMirrorComponents_DuplicateSpecNoAbort(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	specs := []expectedComponentSpec{
		computeSpec("Mfg", "C-DUP", "aa:bb:cc:dd:ee:21"),
		computeSpec("Mfg", "C-DUP", "aa:bb:cc:dd:ee:22"),
	}
	mirrorExpectedComponents(ctx, pool, compType(), specs, map[string]uuid.UUID{})

	n, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Where("serial_number = ?", "C-DUP").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "exactly one component inserted; the duplicate serial is dropped")
}

// Missing manufacturer is allowed: identity_key carries the identity, so the
// chassis labels are free to be incomplete.
func TestMirrorComponents_MissingManufacturerInserts(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	spec := computeSpec("", "C-NO-MFR", "aa:bb:cc:dd:ee:30")
	mirrorExpectedComponents(ctx, pool, compType(), []expectedComponentSpec{spec}, map[string]uuid.UUID{})

	got, err := model.GetComponentByBMCMAC(ctx, pool.DB, "aa:bb:cc:dd:ee:30")
	require.NoError(t, err)
	assert.Empty(t, got.Manufacturer)
	assert.Equal(t, "C-NO-MFR", got.SerialNumber)
	require.Len(t, got.BMCs, 1)
	assert.Equal(t, "aa:bb:cc:dd:ee:30", got.BMCs[0].MacAddress)
}

// Missing serial is allowed once identity comes from elsewhere. Several such
// rows must not collapse: Postgres treats the NULL serials as distinct under
// component_manufacturer_serial_idx.
func TestMirrorComponents_NullSerialDistinctByHostBMCMac(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	specs := []expectedComponentSpec{
		{Type: compType(), BMC: expectedBMCSpec{MACAddress: "aa:bb:cc:dd:ee:31"}},
		{Type: compType(), BMC: expectedBMCSpec{MACAddress: "aa:bb:cc:dd:ee:32"}},
		{Type: compType(), BMC: expectedBMCSpec{MACAddress: "aa:bb:cc:dd:ee:33"}},
	}
	mirrorExpectedComponents(ctx, pool, compType(), specs, map[string]uuid.UUID{})

	n, err := pool.DB.NewSelect().Model((*model.Component)(nil)).
		Where("type = ?", compType()).
		Where("serial_number IS NULL").
		Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, n, "three NULL-serial components with distinct Host BMC MACs must all insert")
}

// Identity is independent of the chassis labels, so Core renaming a serial
// updates the existing row in place instead of inserting a duplicate.
func TestMirrorComponents_MatchByHostBMCMac(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	c := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-OLD"}
	require.NoError(t, c.Create(ctx, pool.DB))
	hostBMC := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:40",
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
		ComponentID: c.ID,
	}
	_, err := pool.DB.NewInsert().Model(&hostBMC).Exec(ctx)
	require.NoError(t, err)

	spec := computeSpec("Mfg", "C-NEW", "aa:bb:cc:dd:ee:40")
	mirrorExpectedComponents(ctx, pool, compType(), []expectedComponentSpec{spec}, map[string]uuid.UUID{})

	got, err := (&model.Component{ID: c.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, got.DeletedAt)
	assert.Equal(t, "C-NEW", got.SerialNumber, "Host BMC match must update serial metadata in place")

	n, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Where("type = ?", compType()).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "must not insert a second component for the same Host BMC MAC")
}

// Identity and (manufacturer, serial) can disagree: identity matches one row
// while Core's serial belongs to another. The write must be skipped so a
// single conflicting component doesn't roll back the type's whole cycle.
func TestMirrorComponents_SerialTakenByOtherComponentSkipsUpdate(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	holder := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-CLASH"}
	require.NoError(t, holder.Create(ctx, pool.DB))

	target := model.Component{Type: compType(), Manufacturer: "Mfg", SerialNumber: "C-TARGET"}
	require.NoError(t, target.Create(ctx, pool.DB))
	hostBMC := model.BMC{
		MacAddress:  "aa:bb:cc:dd:ee:50",
		Type:        devicetypes.BMCTypeToString(devicetypes.BMCTypeHost),
		ComponentID: target.ID,
	}
	_, err := pool.DB.NewInsert().Model(&hostBMC).Exec(ctx)
	require.NoError(t, err)

	mirrorExpectedComponents(ctx, pool, compType(), []expectedComponentSpec{
		computeSpec("Mfg", "C-CLASH", "aa:bb:cc:dd:ee:50"),
		computeSpec("Mfg", "C-FRESH", "aa:bb:cc:dd:ee:51"),
	}, map[string]uuid.UUID{})

	gotTarget, err := (&model.Component{ID: target.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Equal(t, "C-TARGET", gotTarget.SerialNumber, "must not write a serial another component already holds")
	assert.Nil(t, gotTarget.DeletedAt, "a skipped update must not cascade into a soft-delete")

	n, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Where("serial_number = ?", "C-FRESH").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the colliding component must not block unrelated components in the same cycle")
}
