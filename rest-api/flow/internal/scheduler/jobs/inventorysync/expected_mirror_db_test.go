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

func namedCoreRack(rackID, name, mfr, serial string) nicoapi.ExpectedRackDetail {
	rack := coreRack(rackID, mfr, serial)
	rack.Name = name
	return rack
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
	returning := model.Rack{Name: "deleted-name", Manufacturer: "Mfg", SerialNumber: "RETURNING", ExternalID: strPtr("z")}
	require.NoError(t, returning.Create(ctx, pool.DB))
	require.NoError(t, returning.Delete(ctx, pool.DB))

	collidingCore := nicoapi.ExpectedRackDetail{
		RackID: "y",
		Name:   "collide", // same name, different chassis
		Labels: map[string]string{
			labelChassisManufacturer: "Mfg",
			labelChassisSerialNumber: "NEW-1",
		},
	}
	// Include the live rack's own Core row so it isn't soft-deleted for absence.
	result := mirrorExpectedRacks(ctx, pool, []nicoapi.ExpectedRackDetail{
		coreRack("x", "Mfg", "LIVE-1"),
		collidingCore,
		namedCoreRack("z", "collide", "Mfg", "RETURNING"),
	})

	gotLive, err := (&model.Rack{ID: live.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Nil(t, gotLive.DeletedAt, "the live rack holding the name must survive")

	n, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).Where("serial_number = ?", "NEW-1").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "the colliding-name insert must be skipped, not committed or aborting the cycle")
	gotReturning, err := (&model.Rack{ID: returning.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.NotNil(t, gotReturning.DeletedAt, "a blocked resurrection must remain deleted")
	assert.Zero(t, result.resurrected, "a blocked resurrection must not be reported as committed")
}

// One Core row can match a Flow rack by external ID while another matches the
// same row by its original chassis key. The exact owner must win regardless of
// planning order, and even malformed owner data must preserve the existing row.
func TestMirrorRacks_DuplicateFlowMatch(t *testing.T) {
	tests := []struct {
		name               string
		flowExternalID     string
		coreRacks          []nicoapi.ExpectedRackDetail
		wantName           string
		wantUpdated        int
		wantSkippedInvalid int
	}{
		{
			name:           "exact-first",
			flowExternalID: "a",
			coreRacks: []nicoapi.ExpectedRackDetail{
				namedCoreRack("a", "exact-name", "Mfg", "CORRECTED"),
				namedCoreRack("z", "natural-name", "Mfg", "ORIGINAL"),
			},
			wantName:    "exact-name",
			wantUpdated: 1,
		},
		{
			name:           "natural-first",
			flowExternalID: "z",
			coreRacks: []nicoapi.ExpectedRackDetail{
				namedCoreRack("z", "exact-name", "Mfg", "ORIGINAL"),
				namedCoreRack("a", "natural-name", "Mfg", "ORIGINAL"),
			},
			wantName:    "exact-name",
			wantUpdated: 1,
		},
		{
			name:           "bad-owner",
			flowExternalID: "z",
			coreRacks: []nicoapi.ExpectedRackDetail{
				{
					RackID: "z",
					Name:   "malformed-name",
					Labels: map[string]string{
						labelChassisManufacturer: "Mfg",
					},
				},
				namedCoreRack("a", "natural-name", "Mfg", "ORIGINAL"),
			},
			wantName:           "old-name",
			wantSkippedInvalid: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pool := mirrorTestPool(t)
			existing := model.Rack{
				Name:         "old-name",
				Manufacturer: "Mfg",
				SerialNumber: "ORIGINAL",
				ExternalID:   strPtr(tc.flowExternalID),
			}
			require.NoError(t, existing.Create(ctx, pool.DB))

			result := mirrorExpectedRacks(ctx, pool, tc.coreRacks)

			assert.Equal(t, tc.wantUpdated, result.updated)
			assert.Equal(t, tc.wantSkippedInvalid, result.skippedNoIDOrKey)
			assert.Zero(t, result.inserted)
			assert.Zero(t, result.adopted)
			assert.Zero(t, result.skippedNameTaken)
			got, err := (&model.Rack{ID: existing.ID}).GetIncludingDeleted(ctx, pool.DB)
			require.NoError(t, err)
			assert.Equal(t, existing.ID, got.ID)
			assert.Equal(t, "Mfg", got.Manufacturer)
			assert.Equal(t, "ORIGINAL", got.SerialNumber)
			require.NotNil(t, got.ExternalID)
			assert.Equal(t, tc.flowExternalID, *got.ExternalID)
			assert.Equal(t, tc.wantName, got.Name)
			count, err := pool.DB.NewSelect().Model((*model.Rack)(nil)).Count(ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, count)
		})
	}
}

// Name conflicts and duplicate rack IDs skip only the losing Core row while
// unrelated creates and updates still commit.
func TestMirrorRacks_NamePlan(t *testing.T) {
	tests := []struct {
		name              string
		existing          []model.Rack
		coreRacks         []nicoapi.ExpectedRackDetail
		wantNameBySerial  map[string]string
		wantAbsentSerials []string
		wantInserted      int
		wantUpdated       int
		wantSkippedName   int
	}{
		{
			name: "creates",
			coreRacks: []nicoapi.ExpectedRackDetail{
				namedCoreRack("z", "shared", "Mfg", "CREATE-Z"),
				namedCoreRack("u", "unrelated", "Mfg", "CREATE-U"),
				namedCoreRack("a", "shared", "Mfg", "CREATE-A"),
			},
			wantNameBySerial: map[string]string{
				"CREATE-A": "shared",
				"CREATE-U": "unrelated",
			},
			wantAbsentSerials: []string{"CREATE-Z"},
			wantInserted:      2,
			wantSkippedName:   1,
		},
		{
			name: "updates",
			existing: []model.Rack{
				{Name: "old-a", Manufacturer: "Mfg", SerialNumber: "UPDATE-A", ExternalID: strPtr("a")},
				{Name: "old-z", Manufacturer: "Mfg", SerialNumber: "UPDATE-Z", ExternalID: strPtr("z")},
			},
			coreRacks: []nicoapi.ExpectedRackDetail{
				namedCoreRack("z", "shared", "Mfg", "UPDATE-Z"),
				namedCoreRack("u", "unrelated", "Mfg", "UPDATE-U"),
				namedCoreRack("a", "shared", "Mfg", "UPDATE-A"),
			},
			wantNameBySerial: map[string]string{
				"UPDATE-A": "shared",
				"UPDATE-U": "unrelated",
				"UPDATE-Z": "old-z",
			},
			wantInserted:    1,
			wantUpdated:     1,
			wantSkippedName: 1,
		},
		{
			name: "mixed",
			existing: []model.Rack{
				{Name: "old-z", Manufacturer: "Mfg", SerialNumber: "MIXED-Z", ExternalID: strPtr("z")},
			},
			coreRacks: []nicoapi.ExpectedRackDetail{
				namedCoreRack("z", "shared", "Mfg", "MIXED-Z"),
				namedCoreRack("u", "unrelated", "Mfg", "MIXED-U"),
				namedCoreRack("a", "shared", "Mfg", "MIXED-A"),
			},
			wantNameBySerial: map[string]string{
				"MIXED-A": "shared",
				"MIXED-U": "unrelated",
				"MIXED-Z": "old-z",
			},
			wantInserted:    2,
			wantSkippedName: 1,
		},
		{
			name: "duplicate-rack-id",
			coreRacks: []nicoapi.ExpectedRackDetail{
				namedCoreRack("duplicate", "winner", "Mfg", "DUPLICATE-A"),
				namedCoreRack("duplicate", "loser", "Mfg", "DUPLICATE-B"),
				namedCoreRack("unrelated", "unrelated", "Mfg", "DUPLICATE-U"),
			},
			wantNameBySerial: map[string]string{
				"DUPLICATE-A": "winner",
				"DUPLICATE-U": "unrelated",
			},
			wantAbsentSerials: []string{"DUPLICATE-B"},
			wantInserted:      2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pool := mirrorTestPool(t)
			for i := range tc.existing {
				require.NoError(t, tc.existing[i].Create(ctx, pool.DB))
			}

			result := mirrorExpectedRacks(ctx, pool, tc.coreRacks)

			assert.Equal(t, tc.wantSkippedName, result.skippedNameTaken)
			assert.Equal(t, tc.wantInserted, result.inserted)
			assert.Equal(t, tc.wantUpdated, result.updated)
			for serial, wantName := range tc.wantNameBySerial {
				got, err := (&model.Rack{Manufacturer: "Mfg", SerialNumber: serial}).Get(ctx, pool.DB, false)
				require.NoError(t, err)
				assert.Equal(t, wantName, got.Name)
			}
			for _, serial := range tc.wantAbsentSerials {
				count, err := pool.DB.NewSelect().
					Model((*model.Rack)(nil)).
					Where("manufacturer = ? AND serial_number = ?", "Mfg", serial).
					Count(ctx)
				require.NoError(t, err)
				assert.Zero(t, count)
			}
		})
	}
}

// A tombstone being resurrected keeps its source name reserved for that pass;
// another rack can reuse the name after the resurrection has renamed it.
func TestMirrorRacks_NameReuseAcrossCycles(t *testing.T) {
	ctx, pool := mirrorTestPool(t)
	returning := model.Rack{
		Name:         "old-name",
		Manufacturer: "Mfg",
		SerialNumber: "RETURNING",
		ExternalID:   strPtr("z"),
	}
	require.NoError(t, returning.Create(ctx, pool.DB))
	require.NoError(t, returning.Delete(ctx, pool.DB))
	coreRacks := []nicoapi.ExpectedRackDetail{
		namedCoreRack("a", "old-name", "Mfg", "NEW"),
		namedCoreRack("z", "new-name", "Mfg", "RETURNING"),
	}

	first := mirrorExpectedRacks(ctx, pool, coreRacks)

	assert.Equal(t, 1, first.skippedNameTaken)
	assert.Equal(t, 0, first.inserted)
	assert.Equal(t, 1, first.updated)
	assert.Equal(t, 1, first.resurrected)
	gotReturning, err := (&model.Rack{ID: returning.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Equal(t, returning.ID, gotReturning.ID, "resurrection must preserve the Flow rack UUID")
	assert.Equal(t, "new-name", gotReturning.Name)
	assert.Nil(t, gotReturning.DeletedAt)
	newCount, err := pool.DB.NewSelect().
		Model((*model.Rack)(nil)).
		Where("manufacturer = ? AND serial_number = ?", "Mfg", "NEW").
		Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, newCount, "old-name reuse waits until the resurrection has renamed its source row")

	second := mirrorExpectedRacks(ctx, pool, coreRacks)

	assert.Equal(t, 0, second.skippedNameTaken)
	assert.Equal(t, 1, second.inserted)
	assert.Equal(t, 0, second.updated)
	gotNew, err := (&model.Rack{Manufacturer: "Mfg", SerialNumber: "NEW"}).Get(ctx, pool.DB, false)
	require.NoError(t, err)
	assert.Equal(t, "old-name", gotNew.Name)
	gotReturning, err = (&model.Rack{ID: returning.ID}).GetIncludingDeleted(ctx, pool.DB)
	require.NoError(t, err)
	assert.Equal(t, returning.ID, gotReturning.ID)
	assert.Equal(t, "new-name", gotReturning.Name)
	assert.Nil(t, gotReturning.DeletedAt)
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

// #4: duplicate component specs must not abort the transaction on the
// (manufacturer, serial) unique index.
func TestMirrorComponents_DuplicateSpecNoAbort(t *testing.T) {
	ctx, pool := mirrorTestPool(t)

	specs := []expectedComponentSpec{
		computeSpec("Mfg", "C-DUP", "aa:bb:cc:dd:ee:21"),
		computeSpec("Mfg", "C-DUP", "aa:bb:cc:dd:ee:22"),
	}
	mirrorExpectedComponents(ctx, pool, compType(), specs, map[string]uuid.UUID{})

	n, err := pool.DB.NewSelect().Model((*model.Component)(nil)).Where("serial_number = ?", "C-DUP").Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "exactly one component inserted; the duplicate spec is dropped")
}
