// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
)

func TestNaturalKeyIsCollisionFree(t *testing.T) {
	// The classic concatenation bug: "ab"+"cd" and "abc"+"d" collide if you
	// don't separate with a forbidden byte.
	a := naturalKey("ab", "cd")
	b := naturalKey("abc", "d")
	assert.NotEqual(t, a, b, "manufacturer/serial collisions must be impossible")
}

func TestNaturalKeyOrEmpty(t *testing.T) {
	tests := []struct {
		name         string
		manufacturer string
		serialNumber string
		wantEmpty    bool
	}{
		{name: "both halves populated", manufacturer: "Foxconn", serialNumber: "SN-1"},
		{name: "no manufacturer", serialNumber: "SN-1", wantEmpty: true},
		{name: "no serial", manufacturer: "Foxconn", wantEmpty: true},
		{name: "neither", wantEmpty: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := naturalKeyOrEmpty(tc.manufacturer, tc.serialNumber)
			if tc.wantEmpty {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, naturalKey(tc.manufacturer, tc.serialNumber), got)
		})
	}
}

func TestBuildRackFromCore(t *testing.T) {
	tests := []struct {
		name      string
		in        nicoapi.ExpectedRackDetail
		wantOK    bool
		assertRow func(t *testing.T, r model.Rack)
	}{
		{
			name: "happy path with all labels",
			in: nicoapi.ExpectedRackDetail{
				RackID: "a12",
				Name:   "Rack A12",
				Labels: map[string]string{
					labelChassisManufacturer: "Foxconn",
					labelChassisSerialNumber: "SN-A12",
					labelChassisModel:        "MGX-Rack-Gen2",
					labelLocationRegion:      "us-east",
					labelLocationDatacenter:  "DC1",
				},
				Description: "Building 1, Row 3",
			},
			wantOK: true,
			assertRow: func(t *testing.T, r model.Rack) {
				assert.Equal(t, "Rack A12", r.Name)
				assert.Equal(t, "Foxconn", r.Manufacturer)
				assert.Equal(t, "SN-A12", r.SerialNumber)
				require.NotNil(t, r.ExternalID)
				assert.Equal(t, "a12", *r.ExternalID)
				assert.Equal(t, "MGX-Rack-Gen2", r.Description["model"])
				assert.Equal(t, "Building 1, Row 3", r.Description["text"])
				assert.Equal(t, "us-east", r.Location["region"])
				assert.Equal(t, "DC1", r.Location["datacenter"])
				assert.NotContains(t, r.Location, "room")
				assert.NotContains(t, r.Location, "position")
			},
		},
		{
			name: "empty name falls back to rack_id so the NOT NULL/unique name constraint holds",
			in: nicoapi.ExpectedRackDetail{
				RackID: "b07",
				Labels: map[string]string{
					labelChassisManufacturer: "Foxconn",
					labelChassisSerialNumber: "SN-B07",
				},
			},
			wantOK: true,
			assertRow: func(t *testing.T, r model.Rack) {
				assert.Equal(t, "b07", r.Name)
			},
		},
		{
			name: "missing manufacturer is mirrored without it",
			in: nicoapi.ExpectedRackDetail{
				RackID: "c01",
				Labels: map[string]string{
					labelChassisSerialNumber: "SN-C01",
				},
			},
			wantOK: true,
			assertRow: func(t *testing.T, r model.Rack) {
				assert.Empty(t, r.Manufacturer)
				assert.Equal(t, "SN-C01", r.SerialNumber)
				require.NotNil(t, r.ExternalID)
				assert.Equal(t, "c01", *r.ExternalID)
			},
		},
		{
			name: "missing serial is mirrored without it",
			in: nicoapi.ExpectedRackDetail{
				RackID: "c02",
				Labels: map[string]string{
					labelChassisManufacturer: "Foxconn",
				},
			},
			wantOK: true,
			assertRow: func(t *testing.T, r model.Rack) {
				assert.Equal(t, "Foxconn", r.Manufacturer)
				assert.Empty(t, r.SerialNumber)
			},
		},
		{
			name: "no chassis labels at all is still mirrored under rack_id",
			in: nicoapi.ExpectedRackDetail{
				RackID: "c03",
				Name:   "klamath-1",
			},
			wantOK: true,
			assertRow: func(t *testing.T, r model.Rack) {
				assert.Empty(t, r.Manufacturer)
				assert.Empty(t, r.SerialNumber)
				assert.Equal(t, "klamath-1", r.Name)
			},
		},
		{
			name: "no description/location labels leaves jsonb columns nil",
			in: nicoapi.ExpectedRackDetail{
				RackID: "d05",
				Name:   "bare",
				Labels: map[string]string{
					labelChassisManufacturer: "Foxconn",
					labelChassisSerialNumber: "SN-D05",
				},
			},
			wantOK: true,
			assertRow: func(t *testing.T, r model.Rack) {
				assert.Nil(t, r.Description)
				assert.Nil(t, r.Location)
			},
		},
		{
			name: "missing rack_id is unusable: nothing to identify the rack by",
			in: nicoapi.ExpectedRackDetail{
				Name: "noext",
				Labels: map[string]string{
					labelChassisManufacturer: "Foxconn",
					labelChassisSerialNumber: "SN-E01",
				},
			},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := buildRackFromCore(tc.in)
			assert.Equal(t, tc.wantOK, ok)
			if ok && tc.assertRow != nil {
				tc.assertRow(t, got)
			}
		})
	}
}

func TestRackUpdatedFromCore(t *testing.T) {
	id := uuid.New()
	base := func() *model.Rack {
		return &model.Rack{
			ID:           id,
			Name:         "old-name",
			Manufacturer: "Foxconn",
			SerialNumber: "SN-1",
			Description:  map[string]any{"model": "old-model"},
			Location:     map[string]any{"region": "us-west"},
		}
	}

	t.Run("name change produces an update", func(t *testing.T) {
		existing := base()
		fromCore := *base()
		fromCore.Name = "new-name"
		got := rackUpdatedFromCore(existing, &fromCore)
		require.NotNil(t, got)
		assert.Equal(t, "new-name", got.Name)
	})

	t.Run("identical inputs produce no update", func(t *testing.T) {
		existing := base()
		fromCore := *base()
		assert.Nil(t, rackUpdatedFromCore(existing, &fromCore))
	})

	t.Run("description swap is detected", func(t *testing.T) {
		existing := base()
		fromCore := *base()
		fromCore.Description = map[string]any{"model": "new-model"}
		got := rackUpdatedFromCore(existing, &fromCore)
		require.NotNil(t, got)
		assert.Equal(t, "new-model", got.Description["model"])
	})

	t.Run("location swap is detected", func(t *testing.T) {
		existing := base()
		fromCore := *base()
		fromCore.Location = map[string]any{"region": "us-east"}
		got := rackUpdatedFromCore(existing, &fromCore)
		require.NotNil(t, got)
		assert.Equal(t, "us-east", got.Location["region"])
	})

	t.Run("adoption: existing has nil external_id, core provides one", func(t *testing.T) {
		existing := base()
		existing.ExternalID = nil
		fromCore := *base()
		ext := "a12"
		fromCore.ExternalID = &ext
		got := rackUpdatedFromCore(existing, &fromCore)
		require.NotNil(t, got)
		require.NotNil(t, got.ExternalID)
		assert.Equal(t, "a12", *got.ExternalID)
	})

	t.Run("empty name in fromCore does not clobber existing name", func(t *testing.T) {
		existing := base()
		fromCore := *base()
		fromCore.Name = ""
		assert.Nil(t, rackUpdatedFromCore(existing, &fromCore))
	})

	t.Run("chassis labels are backfilled once Core starts sending them", func(t *testing.T) {
		existing := base()
		existing.Manufacturer = ""
		existing.SerialNumber = ""
		fromCore := *base()
		got := rackUpdatedFromCore(existing, &fromCore)
		require.NotNil(t, got)
		assert.Equal(t, "Foxconn", got.Manufacturer)
		assert.Equal(t, "SN-1", got.SerialNumber)
	})

	t.Run("Core dropping a chassis label does not erase Flow's copy", func(t *testing.T) {
		existing := base()
		fromCore := *base()
		fromCore.Manufacturer = ""
		fromCore.SerialNumber = ""
		assert.Nil(t, rackUpdatedFromCore(existing, &fromCore))
	})

	t.Run("a populated chassis label is not overwritten with a different one", func(t *testing.T) {
		existing := base()
		fromCore := *base()
		fromCore.Manufacturer = "Wistron"
		fromCore.SerialNumber = "SN-2"
		assert.Nil(t, rackUpdatedFromCore(existing, &fromCore))
	})
}

func TestNameUnavailable(t *testing.T) {
	holder := uuid.New()
	liveByName := map[string]uuid.UUID{"held": holder}

	tests := []struct {
		name         string
		plannedNames map[string]struct{}
		rackName     string
		selfID       uuid.UUID
		want         bool
	}{
		{name: "free name", rackName: "free", selfID: uuid.Nil},
		{name: "name held by another live rack", rackName: "held", selfID: uuid.New(), want: true},
		{name: "name held by the rack being updated", rackName: "held", selfID: holder},
		{
			name:         "name claimed by a write queued earlier this cycle",
			plannedNames: map[string]struct{}{"free": {}},
			rackName:     "free",
			selfID:       uuid.Nil,
			want:         true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			planned := tc.plannedNames
			if planned == nil {
				planned = map[string]struct{}{}
			}
			assert.Equal(t, tc.want, nameUnavailable(liveByName, planned, tc.rackName, tc.selfID))
		})
	}
}

func TestClearChassisLabelsIfSlotTaken(t *testing.T) {
	owner := &model.Rack{ID: uuid.New(), Name: "owner", Manufacturer: "Foxconn", SerialNumber: "SN-1"}
	flowByNaturalKey := map[string]*model.Rack{
		naturalKey("Foxconn", "SN-1"): owner,
	}

	t.Run("labels held by another rack are dropped", func(t *testing.T) {
		built := model.Rack{Manufacturer: "Foxconn", SerialNumber: "SN-1"}
		clearChassisLabelsIfSlotTaken(&built, flowByNaturalKey, uuid.New(), "b34")
		assert.Empty(t, built.Manufacturer)
		assert.Empty(t, built.SerialNumber)
	})

	t.Run("the rack already holding the pair keeps it", func(t *testing.T) {
		built := model.Rack{Manufacturer: "Foxconn", SerialNumber: "SN-1"}
		clearChassisLabelsIfSlotTaken(&built, flowByNaturalKey, owner.ID, "a12")
		assert.Equal(t, "Foxconn", built.Manufacturer)
		assert.Equal(t, "SN-1", built.SerialNumber)
	})

	t.Run("an unclaimed pair is kept", func(t *testing.T) {
		built := model.Rack{Manufacturer: "Wistron", SerialNumber: "SN-9"}
		clearChassisLabelsIfSlotTaken(&built, flowByNaturalKey, uuid.Nil, "c01")
		assert.Equal(t, "Wistron", built.Manufacturer)
		assert.Equal(t, "SN-9", built.SerialNumber)
	})

	t.Run("a half-populated pair occupies no slot and is left alone", func(t *testing.T) {
		built := model.Rack{SerialNumber: "SN-1"}
		clearChassisLabelsIfSlotTaken(&built, flowByNaturalKey, uuid.Nil, "c02")
		assert.Equal(t, "SN-1", built.SerialNumber)
	})
}

func TestAdoptableByNaturalKey(t *testing.T) {
	coreExtIDs := map[string]struct{}{"live": {}}

	tests := []struct {
		name       string
		externalID *string
		want       bool
	}{
		{name: "no external_id has never been claimed", want: true},
		{name: "empty external_id has never been claimed", externalID: strPtr(""), want: true},
		{name: "external_id Core no longer reports may be re-pointed", externalID: strPtr("retired"), want: true},
		{name: "external_id Core still reports owns the row", externalID: strPtr("live")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &model.Rack{ExternalID: tc.externalID}
			assert.Equal(t, tc.want, adoptableByNaturalKey(r, coreExtIDs))
		})
	}
}

// errExpectedRacksClient is a tiny test wrapper around the production mock
// that overrides GetAllExpectedRackDetails to inject either an RPC error or a
// custom row set. It satisfies the same nicoapi.Client interface so it slots
// straight into pullExpectedRacks without touching the production mock.
type errExpectedRacksClient struct {
	nicoapi.Client
	err  error
	rows []nicoapi.ExpectedRackDetail
}

func (c *errExpectedRacksClient) GetAllExpectedRackDetails(_ context.Context) ([]nicoapi.ExpectedRackDetail, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.rows, nil
}

func TestPullExpectedRacks(t *testing.T) {
	ctx := context.Background()

	t.Run("rpc error returns rpcOK=false so caller leaves Flow untouched", func(t *testing.T) {
		c := &errExpectedRacksClient{Client: nicoapi.NewMockClient(), err: errors.New("boom")}
		rows, rpcOK := pullExpectedRacks(ctx, c)
		assert.Nil(t, rows)
		assert.False(t, rpcOK)
	})

	t.Run("empty response is an authoritative rpcOK=true so caller soft-deletes all", func(t *testing.T) {
		c := &errExpectedRacksClient{Client: nicoapi.NewMockClient()}
		rows, rpcOK := pullExpectedRacks(ctx, c)
		assert.Empty(t, rows)
		assert.True(t, rpcOK)
	})

	t.Run("populated response returns rpcOK=true", func(t *testing.T) {
		c := &errExpectedRacksClient{
			Client: nicoapi.NewMockClient(),
			rows: []nicoapi.ExpectedRackDetail{
				{RackID: "a12"},
			},
		}
		rows, rpcOK := pullExpectedRacks(ctx, c)
		assert.Len(t, rows, 1)
		assert.True(t, rpcOK)
	})
}
