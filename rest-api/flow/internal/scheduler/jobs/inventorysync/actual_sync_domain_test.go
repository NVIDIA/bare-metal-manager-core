// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
)

type failDomainMembershipClient struct {
	nicoapi.Client
}

func (c *failDomainMembershipClient) GetObservedNVLinkDomainMemberships(_ context.Context) ([]nicoapi.NVLinkDomainMembership, error) {
	return nil, errors.New("domain snapshot unavailable")
}

func TestBuildDomainTopologySnapshot(t *testing.T) {
	rackA := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	rackB := uuid.MustParse("10000000-0000-0000-0000-000000000002")
	domainA := "20000000-0000-0000-0000-000000000001"
	domainB := "20000000-0000-0000-0000-000000000002"
	rackIDs := map[string]uuid.UUID{"rack-a": rackA, "rack-b": rackB}

	tests := []struct {
		name            string
		memberships     []nicoapi.NVLinkDomainMembership
		wantRackCount   int
		wantDomainCount int
		wantErr         string
	}{
		{
			name: "deduplicates switch observations",
			memberships: []nicoapi.NVLinkDomainMembership{
				{DomainID: domainA, RackID: "rack-a"},
				{DomainID: domainA, RackID: "rack-a"},
				{DomainID: domainA, RackID: "rack-b"},
			},
			wantRackCount:   2,
			wantDomainCount: 1,
		},
		{
			name: "accepts no valid observations",
		},
		{
			name: "rejects invalid domain UUID",
			memberships: []nicoapi.NVLinkDomainMembership{
				{DomainID: "not-a-uuid", RackID: "rack-a"},
			},
			wantErr: "invalid observed NVLink domain ID",
		},
		{
			name: "skips unknown rack",
			memberships: []nicoapi.NVLinkDomainMembership{
				{DomainID: domainA, RackID: "unknown"},
			},
		},
		{
			name: "keeps known membership when another rack is unknown",
			memberships: []nicoapi.NVLinkDomainMembership{
				{DomainID: domainA, RackID: "rack-a"},
				{DomainID: domainB, RackID: "unknown"},
			},
			wantRackCount:   1,
			wantDomainCount: 1,
		},
		{
			name: "rejects conflicting rack memberships",
			memberships: []nicoapi.NVLinkDomainMembership{
				{DomainID: domainA, RackID: "rack-a"},
				{DomainID: domainB, RackID: "rack-a"},
			},
			wantErr: "conflicting observed NVLink domains",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := buildDomainTopologySnapshot(test.memberships, rackIDs)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, snapshot.domainByRack, test.wantRackCount)
			assert.Len(t, snapshot.domainIDs, test.wantDomainCount)
		})
	}
}

func TestPullObservedNVLinkDomainMembershipsPreservesTopologyOnFailure(t *testing.T) {
	client := &failDomainMembershipClient{Client: nicoapi.NewMockClient()}
	memberships, ok := pullObservedNVLinkDomainMemberships(context.Background(), client)
	assert.False(t, ok)
	assert.Nil(t, memberships)
}

func TestMirrorObservedNVLinkDomainMembershipsLifecycle(t *testing.T) {
	ctx, pool := mirrorTestPool(t)
	rackA := model.Rack{Name: "domain-rack-a", ExternalID: strPtr("rack-a")}
	rackB := model.Rack{Name: "domain-rack-b", ExternalID: strPtr("rack-b")}
	require.NoError(t, rackA.Create(ctx, pool.DB))
	require.NoError(t, rackB.Create(ctx, pool.DB))
	rackIDs := map[string]uuid.UUID{"rack-a": rackA.ID, "rack-b": rackB.ID}
	domainA := uuid.MustParse("20000000-0000-0000-0000-000000000001")
	domainB := uuid.MustParse("20000000-0000-0000-0000-000000000002")

	initial := []nicoapi.NVLinkDomainMembership{
		{DomainID: domainA.String(), RackID: "rack-a"},
		{DomainID: domainA.String(), RackID: "rack-a"},
		{DomainID: domainA.String(), RackID: "rack-b"},
	}
	result, err := mirrorObservedNVLinkDomainMemberships(ctx, pool, initial, rackIDs)
	require.NoError(t, err)
	assert.Equal(t, 1, result.domainsInserted)
	assert.Equal(t, 2, result.membershipsAssigned)

	result, err = mirrorObservedNVLinkDomainMemberships(ctx, pool, initial, rackIDs)
	require.NoError(t, err)
	assert.Equal(t, domainMirrorResult{pulled: len(initial)}, result)

	moved := []nicoapi.NVLinkDomainMembership{
		{DomainID: domainA.String(), RackID: "rack-a"},
		{DomainID: domainB.String(), RackID: "rack-b"},
	}
	result, err = mirrorObservedNVLinkDomainMemberships(ctx, pool, moved, rackIDs)
	require.NoError(t, err)
	assert.Equal(t, 1, result.domainsInserted)
	assert.Equal(t, 1, result.membershipsAssigned)
	orphanDomain := model.NVLDomain{
		ID:   uuid.MustParse("20000000-0000-0000-0000-000000000003"),
		Name: "manually-created-domain",
	}
	require.NoError(t, orphanDomain.Create(ctx, pool.DB))

	var logOutput bytes.Buffer
	originalLogger := log.Logger
	log.Logger = zerolog.New(&logOutput)
	result, err = mirrorObservedNVLinkDomainMemberships(ctx, pool, nil, rackIDs)
	log.Logger = originalLogger
	require.NoError(t, err)
	assert.Equal(t, 2, result.membershipsCleared)
	assert.Equal(t, 2, result.domainsSoftDeleted)
	assert.Contains(t, logOutput.String(), "cleared rack NVLink domain membership because the observed snapshot contained no valid membership")
	assert.Contains(t, logOutput.String(), `"rack_external_id":"rack-a"`)
	assert.Contains(t, logOutput.String(), `"previous_domain_id":"`+domainA.String()+`"`)
	var rackAAfterEmpty model.Rack
	err = pool.DB.NewSelect().Model(&rackAAfterEmpty).Where("id = ?", rackA.ID).Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, rackAAfterEmpty.NVLDomainID)
	var rackBAfterEmpty model.Rack
	err = pool.DB.NewSelect().Model(&rackBAfterEmpty).Where("id = ?", rackB.ID).Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, rackBAfterEmpty.NVLDomainID)
	_, err = pool.DB.NewUpdate().
		Model((*model.NVLDomain)(nil)).
		Set("name = ?", "friendly-domain-b").
		WhereAllWithDeleted().
		Where("id = ?", domainB).
		Exec(ctx)
	require.NoError(t, err)
	_, err = pool.DB.NewDelete().
		Model(&model.NVLDomain{ID: domainB}).
		Where("id = ?", domainB).
		Exec(ctx)
	require.NoError(t, err)

	resurrected := []nicoapi.NVLinkDomainMembership{
		{DomainID: domainB.String(), RackID: "rack-b"},
	}
	result, err = mirrorObservedNVLinkDomainMemberships(ctx, pool, resurrected, rackIDs)
	require.NoError(t, err)
	assert.Equal(t, 1, result.domainsResurrected)
	assert.Equal(t, 1, result.membershipsAssigned)

	converged := []nicoapi.NVLinkDomainMembership{
		{DomainID: domainB.String(), RackID: "rack-a"},
		{DomainID: domainB.String(), RackID: "rack-b"},
	}
	result, err = mirrorObservedNVLinkDomainMemberships(ctx, pool, converged, rackIDs)
	require.NoError(t, err)
	assert.Equal(t, 1, result.membershipsAssigned)
	assert.Equal(t, 0, result.domainsSoftDeleted)

	var gotRackA model.Rack
	err = pool.DB.NewSelect().Model(&gotRackA).Where("id = ?", rackA.ID).Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, domainB, gotRackA.NVLDomainID)
	var gotRackB model.Rack
	err = pool.DB.NewSelect().Model(&gotRackB).Where("id = ?", rackB.ID).Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, domainB, gotRackB.NVLDomainID)
	var gotDomainB model.NVLDomain
	err = pool.DB.NewSelect().Model(&gotDomainB).Where("id = ?", domainB).Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, "friendly-domain-b", gotDomainB.Name)
	var gotOrphanDomain model.NVLDomain
	err = pool.DB.NewSelect().Model(&gotOrphanDomain).Where("id = ?", orphanDomain.ID).Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, orphanDomain.Name, gotOrphanDomain.Name)
	var gotDomainA model.NVLDomain
	err = pool.DB.NewSelect().
		Model(&gotDomainA).
		WhereAllWithDeleted().
		Where("id = ?", domainA).
		Scan(ctx)
	require.NoError(t, err)
	assert.NotNil(t, gotDomainA.DeletedAt)
}

func TestMirrorObservedNVLinkDomainMembershipsRollsBackAllWrites(t *testing.T) {
	ctx, pool := mirrorTestPool(t)
	oldDomain := model.NVLDomain{
		ID:   uuid.MustParse("30000000-0000-0000-0000-000000000001"),
		Name: "old-domain",
	}
	require.NoError(t, oldDomain.Create(ctx, pool.DB))
	targetDomainID := uuid.MustParse("30000000-0000-0000-0000-000000000002")
	nameConflict := model.NVLDomain{
		ID:   uuid.MustParse("30000000-0000-0000-0000-000000000003"),
		Name: targetDomainID.String(),
	}
	require.NoError(t, nameConflict.Create(ctx, pool.DB))
	rack := model.Rack{
		Name:        "rollback-rack",
		ExternalID:  strPtr("rack-a"),
		NVLDomainID: oldDomain.ID,
	}
	require.NoError(t, rack.Create(ctx, pool.DB))

	memberships := []nicoapi.NVLinkDomainMembership{
		{DomainID: targetDomainID.String(), RackID: "rack-a"},
	}
	result, err := mirrorObservedNVLinkDomainMemberships(
		ctx,
		pool,
		memberships,
		map[string]uuid.UUID{"rack-a": rack.ID},
	)
	require.Error(t, err)
	assert.Equal(t, domainMirrorResult{pulled: 1}, result)

	var gotRack model.Rack
	err = pool.DB.NewSelect().Model(&gotRack).Where("id = ?", rack.ID).Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, oldDomain.ID, gotRack.NVLDomainID)
	var activeDomains []model.NVLDomain
	err = pool.DB.NewSelect().Model(&activeDomains).Order("id").Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, activeDomains, 2)
}
