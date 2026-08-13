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

func TestRackNaturalKeyIsCollisionFree(t *testing.T) {
	// The classic concatenation bug: "ab"+"cd" and "abc"+"d" collide if you
	// don't separate with a forbidden byte.
	a := rackNaturalKey("ab", "cd")
	b := rackNaturalKey("abc", "d")
	assert.NotEqual(t, a, b, "manufacturer/serial collisions must be impossible")
}

func TestOrderCoreRacksForPlanning(t *testing.T) {
	tests := []struct {
		name            string
		coreRacks       []nicoapi.ExpectedRackDetail
		wantNames       []string
		wantTieBreakers []string
	}{
		{
			name: "rack IDs sort before missing IDs",
			coreRacks: []nicoapi.ExpectedRackDetail{
				{RackID: "z", Name: "rack-z"},
				{
					Name: "missing-z",
					Labels: map[string]string{
						labelChassisManufacturer: "Mfg",
						labelChassisSerialNumber: "Z",
					},
				},
				{RackID: "a", Name: "rack-a"},
				{
					Name: "missing-a",
					Labels: map[string]string{
						labelChassisManufacturer: "Mfg",
						labelChassisSerialNumber: "A",
					},
				},
			},
			wantNames: []string{"rack-a", "rack-z", "missing-a", "missing-z"},
		},
		{
			name: "all labels break identity ties",
			coreRacks: []nicoapi.ExpectedRackDetail{
				{
					RackID:        "same",
					RackProfileID: "profile",
					Name:          "same",
					Description:   "same",
					Labels: map[string]string{
						labelChassisManufacturer: "Mfg",
						labelChassisSerialNumber: "Serial",
						"tie-breaker":            "z",
					},
				},
				{
					RackID:        "same",
					RackProfileID: "profile",
					Name:          "same",
					Description:   "same",
					Labels: map[string]string{
						labelChassisManufacturer: "Mfg",
						labelChassisSerialNumber: "Serial",
						"tie-breaker":            "a",
					},
				},
			},
			wantNames:       []string{"same", "same"},
			wantTieBreakers: []string{"a", "z"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := append([]nicoapi.ExpectedRackDetail(nil), tc.coreRacks...)

			ordered := orderCoreRacksForPlanning(tc.coreRacks)

			require.Len(t, ordered, len(tc.wantNames))
			gotNames := make([]string, 0, len(ordered))
			var gotTieBreakers []string
			for _, rack := range ordered {
				gotNames = append(gotNames, rack.Name)
				if tc.wantTieBreakers != nil {
					gotTieBreakers = append(gotTieBreakers, rack.Labels["tie-breaker"])
				}
			}
			assert.Equal(t, tc.wantNames, gotNames)
			assert.Equal(t, tc.wantTieBreakers, gotTieBreakers)
			assert.Equal(t, original, tc.coreRacks, "planning must not reorder the RPC result in place")
		})
	}
}

func TestMatchFlowRackForCore(t *testing.T) {
	extID := "ext"
	extMatch := &model.Rack{
		ID:           uuid.MustParse("00000000-0000-0000-0000-00000000000a"),
		ExternalID:   &extID,
		Manufacturer: "Mfg",
		SerialNumber: "Ext",
	}
	naturalMatch := &model.Rack{
		ID:           uuid.MustParse("00000000-0000-0000-0000-00000000000b"),
		Manufacturer: "Mfg",
		SerialNumber: "Natural",
	}
	flowByExtID := map[string]*model.Rack{"ext": extMatch}
	flowBySerial := map[string]*model.Rack{
		rackNaturalKey("Mfg", "Natural"): naturalMatch,
	}
	tests := []struct {
		name           string
		rack           nicoapi.ExpectedRackDetail
		want           *model.Rack
		wantExternalID bool
	}{
		{
			name: "external ID wins over a different natural-key match",
			rack: nicoapi.ExpectedRackDetail{
				RackID: "ext",
				Labels: map[string]string{
					labelChassisManufacturer: "Mfg",
					labelChassisSerialNumber: "Natural",
				},
			},
			want:           extMatch,
			wantExternalID: true,
		},
		{
			name:           "malformed labels still keep an external ID match",
			rack:           nicoapi.ExpectedRackDetail{RackID: "ext"},
			want:           extMatch,
			wantExternalID: true,
		},
		{
			name: "valid natural key is the fallback",
			rack: nicoapi.ExpectedRackDetail{
				RackID: "unknown",
				Labels: map[string]string{
					labelChassisManufacturer: "Mfg",
					labelChassisSerialNumber: "Natural",
				},
			},
			want: naturalMatch,
		},
		{
			name: "malformed unmatched rack has no fallback",
			rack: nicoapi.ExpectedRackDetail{RackID: "unknown"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, matchedByExternalID := matchFlowRackForCore(tc.rack, flowByExtID, flowBySerial)

			if tc.want == nil {
				assert.Nil(t, got)
			} else {
				assert.Same(t, tc.want, got)
			}
			assert.Equal(t, tc.wantExternalID, matchedByExternalID)
		})
	}
}

func TestReserveRackName(t *testing.T) {
	flowA := rackNameReservation{flowID: uuid.MustParse("00000000-0000-0000-0000-00000000000a")}
	flowB := rackNameReservation{flowID: uuid.MustParse("00000000-0000-0000-0000-00000000000b")}
	coreA := rackNameReservation{coreRackID: "a", manufacturer: "Mfg", serialNumber: "A"}
	coreB := rackNameReservation{coreRackID: "b", manufacturer: "Mfg", serialNumber: "B"}
	tests := []struct {
		name        string
		current     *rackNameReservation
		candidate   rackNameReservation
		wantAllowed bool
		wantOwner   rackNameReservation
	}{
		{
			name:        "unclaimed name is reserved",
			candidate:   coreA,
			wantAllowed: true,
			wantOwner:   coreA,
		},
		{
			name:        "same Flow rack keeps its own name",
			current:     &flowA,
			candidate:   flowA,
			wantAllowed: true,
			wantOwner:   flowA,
		},
		{
			name:        "different live Flow rack is rejected",
			current:     &flowA,
			candidate:   flowB,
			wantAllowed: false,
			wantOwner:   flowA,
		},
		{
			name:        "different planned Core rack is rejected",
			current:     &coreA,
			candidate:   coreB,
			wantAllowed: false,
			wantOwner:   coreA,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reserved := map[string]rackNameReservation{}
			if tc.current != nil {
				reserved["shared"] = *tc.current
			}

			owner, allowed := reserveRackName(reserved, "shared", tc.candidate)

			assert.Equal(t, tc.wantAllowed, allowed)
			assert.Equal(t, tc.wantOwner, owner)
			assert.Equal(t, tc.wantOwner, reserved["shared"])
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
			name: "missing manufacturer is unusable",
			in: nicoapi.ExpectedRackDetail{
				RackID: "c01",
				Labels: map[string]string{
					labelChassisSerialNumber: "SN-C01",
				},
			},
			wantOK: false,
		},
		{
			name: "missing serial is unusable",
			in: nicoapi.ExpectedRackDetail{
				RackID: "c02",
				Labels: map[string]string{
					labelChassisManufacturer: "Foxconn",
				},
			},
			wantOK: false,
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
			name: "missing rack_id yields nil ExternalID (NULL in DB) so partial unique index stays clean",
			in: nicoapi.ExpectedRackDetail{
				Name: "noext",
				Labels: map[string]string{
					labelChassisManufacturer: "Foxconn",
					labelChassisSerialNumber: "SN-E01",
				},
			},
			wantOK: true,
			assertRow: func(t *testing.T, r model.Rack) {
				assert.Nil(t, r.ExternalID)
				assert.Equal(t, "noext", r.Name)
			},
		},
		{
			name: "missing both rack_id and name falls back to manufacturer-serial",
			in: nicoapi.ExpectedRackDetail{
				Labels: map[string]string{
					labelChassisManufacturer: "Foxconn",
					labelChassisSerialNumber: "SN-F01",
				},
			},
			wantOK: true,
			assertRow: func(t *testing.T, r model.Rack) {
				assert.Equal(t, "Foxconn-SN-F01", r.Name)
				assert.Nil(t, r.ExternalID)
			},
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
}

func TestFlowBySerialInCore(t *testing.T) {
	core := []nicoapi.ExpectedRackDetail{
		{
			RackID: "a12",
			Labels: map[string]string{
				labelChassisManufacturer: "Foxconn",
				labelChassisSerialNumber: "SN-A12",
			},
		},
		{
			RackID: "b07",
			Labels: map[string]string{
				// Missing manufacturer; should not match anything.
				labelChassisSerialNumber: "SN-B07",
			},
		},
	}

	t.Run("matches by (manufacturer, serial)", func(t *testing.T) {
		flow := &model.Rack{Manufacturer: "Foxconn", SerialNumber: "SN-A12"}
		ext, ok := flowBySerialInCore(flow, core)
		assert.True(t, ok)
		assert.Equal(t, "a12", ext)
	})

	t.Run("no match returns false", func(t *testing.T) {
		flow := &model.Rack{Manufacturer: "Foxconn", SerialNumber: "SN-ZZ"}
		_, ok := flowBySerialInCore(flow, core)
		assert.False(t, ok)
	})

	t.Run("core row without manufacturer is ignored", func(t *testing.T) {
		flow := &model.Rack{Manufacturer: "Foxconn", SerialNumber: "SN-B07"}
		_, ok := flowBySerialInCore(flow, core)
		assert.False(t, ok)
	})
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
