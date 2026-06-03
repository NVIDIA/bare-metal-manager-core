// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	otrace "go.opentelemetry.io/otel/trace"
)

// reset the tables needed for SSHKeyGroupSiteAssociation tests
func testSSHKeyGroupSiteAssociationSetupSchema(t *testing.T, dbSession *db.Session) {
	testSSHKeyGroupSetupSchema(t, dbSession)
	// create the SSHKeyGroupSiteAssociation table
	err := dbSession.DB.ResetModel(context.Background(), (*SSHKeyGroupSiteAssociation)(nil))
	assert.Nil(t, err)
}

func TestSSHKeyGroupSiteAssociationSQLDAO_CreateFromParams(t *testing.T) {
	ctx := context.Background()
	dbSession := testInstanceInitDB(t)
	defer dbSession.Close()
	testSSHKeyGroupSiteAssociationSetupSchema(t, dbSession)

	user := testOperatingSystemBuildUser(t, dbSession, "testUser")
	ip := testBuildInfrastructureProvider(t, dbSession, db.GetUUIDPtr(uuid.New()), "test", "testorg", user.ID)
	site := TestBuildSite(t, dbSession, ip, "test", user)
	tenant := testOperatingSystemBuildTenant(t, dbSession, "testTenant")

	sshKeyGroup1 := testBuildSSHKeyGroup(t, dbSession, "test1", db.GetStrPtr("test1"), "tesorg", tenant.ID, nil, SSHKeyGroupStatusSyncing, user.ID)
	sshKeyGroup2 := testBuildSSHKeyGroup(t, dbSession, "test2", db.GetStrPtr("test2"), "tesorg", tenant.ID, nil, SSHKeyGroupStatusSyncing, user.ID)

	skgsd := NewSSHKeyGroupSiteAssociationDAO(dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		skgas              []SSHKeyGroupSiteAssociation
		expectError        bool
		verifyChildSpanner bool
	}{
		{
			desc: "create one",
			skgas: []SSHKeyGroupSiteAssociation{
				{
					SSHKeyGroupID: sshKeyGroup1.ID, SiteID: site.ID, Version: db.GetStrPtr("1224"), Status: SSHKeyGroupSiteAssociationStatusSyncing, CreatedBy: user.ID,
				},
			},
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc: "create multiple",
			skgas: []SSHKeyGroupSiteAssociation{
				{
					SSHKeyGroupID: sshKeyGroup1.ID, SiteID: site.ID, Status: SSHKeyGroupSiteAssociationStatusSyncing, CreatedBy: user.ID,
				},
				{
					SSHKeyGroupID: sshKeyGroup2.ID, SiteID: site.ID, Status: SSHKeyGroupSiteAssociationStatusSyncing, CreatedBy: user.ID,
				},
			},
			expectError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			for _, skg := range tc.skgas {
				skga, err := skgsd.CreateFromParams(ctx, nil, skg.SSHKeyGroupID, skg.SiteID, skg.Version, skg.Status, skg.CreatedBy)
				assert.Equal(t, tc.expectError, err != nil)
				if !tc.expectError {
					assert.NotNil(t, skga)
				}
				if tc.verifyChildSpanner {
					span := otrace.SpanFromContext(ctx)
					assert.True(t, span.SpanContext().IsValid())
					_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
					assert.True(t, ok)
				}
			}
		})
	}
}

func TestSSHKeyGroupSiteAssociationSQLDAO_GetByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testInstanceInitDB(t)
	defer dbSession.Close()
	testSSHKeyGroupSiteAssociationSetupSchema(t, dbSession)
	user := testOperatingSystemBuildUser(t, dbSession, "testUser")
	ip := testBuildInfrastructureProvider(t, dbSession, db.GetUUIDPtr(uuid.New()), "test", "testorg", user.ID)
	site := TestBuildSite(t, dbSession, ip, "test", user)
	tenant := testOperatingSystemBuildTenant(t, dbSession, "testTenant")

	skasd := NewSSHKeyGroupSiteAssociationDAO(dbSession)
	sshKeyGroup1 := testBuildSSHKeyGroup(t, dbSession, "test1", db.GetStrPtr("test1"), "tesorg", tenant.ID, nil, SSHKeyGroupStatusSyncing, user.ID)

	skga1, err := skasd.CreateFromParams(ctx, nil, sshKeyGroup1.ID, site.ID, nil, SSHKeyGroupSiteAssociationStatusSyncing, user.ID)
	assert.Nil(t, err)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc                    string
		skgaID                  uuid.UUID
		includeRelations        []string
		expectNotNilSSHKeyGroup bool
		expectNotNilSite        bool
		expectError             bool
		verifyChildSpanner      bool
	}{
		{
			desc:               "success without relations",
			skgaID:             skga1.ID,
			includeRelations:   []string{},
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc:                    "success with relations",
			skgaID:                  skga1.ID,
			includeRelations:        []string{SSHKeyGroupRelationName, SiteRelationName},
			expectError:             false,
			expectNotNilSSHKeyGroup: true,
		},
		{
			desc:             "error when not found",
			skgaID:           uuid.New(),
			includeRelations: []string{},
			expectError:      true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := skasd.GetByID(ctx, nil, tc.skgaID, tc.includeRelations)
			assert.Equal(t, tc.expectError, err != nil)
			if !tc.expectError {
				assert.NotNil(t, got)
				if tc.expectNotNilSSHKeyGroup {
					assert.NotNil(t, got.SSHKeyGroup)
				}
				if tc.expectNotNilSite {
					assert.NotNil(t, got.Site)
				}
			}
			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestSSHKeyGroupSiteAssociationSQLDAO_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := testInstanceInitDB(t)
	defer dbSession.Close()
	testSSHKeyGroupSiteAssociationSetupSchema(t, dbSession)
	user := testOperatingSystemBuildUser(t, dbSession, "testUser")
	ip := testBuildInfrastructureProvider(t, dbSession, db.GetUUIDPtr(uuid.New()), "test", "testorg", user.ID)
	site := TestBuildSite(t, dbSession, ip, "test", user)
	tenant := testOperatingSystemBuildTenant(t, dbSession, "testTenant")

	skgs := []*SSHKeyGroup{}
	skgsd := NewSSHKeyGroupDAO(dbSession)
	skgasd := NewSSHKeyGroupSiteAssociationDAO(dbSession)
	for i := 1; i <= 25; i++ {
		skg1, err := skgsd.Create(
			ctx,
			nil,
			SSHKeyGroupCreateInput{
				Name:        fmt.Sprintf("test-%d", i),
				Description: db.GetStrPtr(fmt.Sprintf("test-%d", i)),
				TenantOrg:   "testorg",
				TenantID:    tenant.ID,
				Status:      SSHKeyGroupStatusSyncing,
				CreatedBy:   user.ID,
			},
		)
		skgs = append(skgs, skg1)
		assert.Nil(t, err)
		assert.NotNil(t, skg1)
		skga1, err := skgasd.CreateFromParams(ctx, nil, skg1.ID, site.ID, nil, SSHKeyGroupSiteAssociationStatusSyncing, user.ID)
		assert.Nil(t, err)
		assert.NotNil(t, skga1)
	}

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc             string
		includeRelations []string

		paramSSHKeyGroupIDs []uuid.UUID
		paramSiteID         *uuid.UUID
		paramVersion        *string
		paramStatus         *string

		paramOffset  *int
		paramLimit   *int
		paramOrderBy *paginator.OrderBy

		expectCnt                      int
		expectTotal                    int
		expectFirstObjectSSHKeyGroupID string

		expectNotNilSSHKeyGroup bool
		expectError             bool
		verifyChildSpanner      bool
	}{
		{
			desc:                           "getall with SSHKeyGroup filters but no relations returns objects",
			paramSSHKeyGroupIDs:            []uuid.UUID{skgs[0].ID, skgs[1].ID},
			includeRelations:               []string{},
			expectFirstObjectSSHKeyGroupID: skgs[0].ID.String(),
			expectError:                    false,
			expectTotal:                    2,
			expectCnt:                      2,
			verifyChildSpanner:             true,
		},
		{
			desc:             "getall with filters and relations returns objects",
			includeRelations: []string{SSHKeyGroupRelationName},
			paramOrderBy: &paginator.OrderBy{
				Field: "updated",
				Order: paginator.OrderAscending,
			},
			expectFirstObjectSSHKeyGroupID: skgs[0].ID.String(),
			expectError:                    false,
			expectTotal:                    25,
			expectCnt:                      20,
			expectNotNilSSHKeyGroup:        true,
		},
		{
			desc:             "getall with status filters and relations returns objects",
			includeRelations: []string{SSHKeyGroupRelationName},
			paramStatus:      db.GetStrPtr(SSHKeyGroupSiteAssociationStatusSyncing),
			paramOrderBy: &paginator.OrderBy{
				Field: "updated",
				Order: paginator.OrderAscending,
			},
			expectFirstObjectSSHKeyGroupID: skgs[0].ID.String(),
			expectError:                    false,
			expectTotal:                    25,
			expectCnt:                      20,
			expectNotNilSSHKeyGroup:        true,
		},
		{
			desc:             "getall with site filters and relations returns objects",
			includeRelations: []string{SSHKeyGroupRelationName},
			paramSiteID:      db.GetUUIDPtr(site.ID),
			paramOrderBy: &paginator.OrderBy{
				Field: "updated",
				Order: paginator.OrderAscending,
			},
			expectFirstObjectSSHKeyGroupID: skgs[0].ID.String(),
			expectError:                    false,
			expectTotal:                    25,
			expectCnt:                      20,
			expectNotNilSSHKeyGroup:        true,
		},
		{
			desc:             "getall with offset, limit returns objects",
			includeRelations: []string{},
			paramOffset:      db.GetIntPtr(10),
			paramLimit:       db.GetIntPtr(10),
			paramOrderBy: &paginator.OrderBy{
				Field: "updated",
				Order: paginator.OrderAscending,
			},
			expectFirstObjectSSHKeyGroupID: skgs[10].ID.String(),
			expectError:                    false,
			expectTotal:                    25,
			expectCnt:                      10,
		},
		{
			desc:                "case when no objects are returned",
			includeRelations:    []string{},
			expectError:         false,
			paramSSHKeyGroupIDs: []uuid.UUID{uuid.New()},
			expectTotal:         0,
			expectCnt:           0,
		},
		{
			desc:             "case when filter by controller keyset version no objects are returned",
			includeRelations: []string{},
			expectError:      false,
			paramVersion:     db.GetStrPtr("1234"),
			expectTotal:      0,
			expectCnt:        0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			objs, tot, err := skgasd.GetAll(ctx, nil, tc.paramSSHKeyGroupIDs, tc.paramSiteID, tc.paramVersion, tc.paramStatus, tc.includeRelations, tc.paramOffset, tc.paramLimit, tc.paramOrderBy)
			assert.Equal(t, tc.expectError, err != nil)
			assert.Equal(t, tc.expectCnt, len(objs))
			assert.Equal(t, tc.expectTotal, tot)
			if len(objs) > 0 {
				if tc.expectFirstObjectSSHKeyGroupID != "" {
					assert.Equal(t, tc.expectFirstObjectSSHKeyGroupID, objs[0].SSHKeyGroupID.String())
				}

				if tc.expectNotNilSSHKeyGroup {
					assert.NotNil(t, objs[0].SSHKeyGroup)
				}
			}
			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestSSHKeyGroupSiteAssociationSQLDAO_GenerateAndUpdateVersion(t *testing.T) {
	ctx := context.Background()
	dbSession := testInitDB(t)
	defer dbSession.Close()

	TestSetupSchema(t, dbSession)

	ipOrg1 := "test-ip-org-1"
	tnOrg := "test-tenant-org-1"

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", ipOrg1, ipu.ID)
	assert.NotNil(t, ip)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe1@test.com"), db.GetStrPtr("John1"), db.GetStrPtr("Doe2"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)
	assert.NotNil(t, tn)

	site1 := testBuildSite(t, dbSession, nil, ip.ID, "test-site-1", "Test Site-1", ip.Org, ipu.ID)
	site2 := testBuildSite(t, dbSession, nil, ip.ID, "test-site-2", "Test Site-2", ip.Org, ipu.ID)

	// Build SSHKeyGroup
	skg := testBuildSSHKeyGroup(t, dbSession, "test1", db.GetStrPtr("testdesc"), tnOrg, tn.ID, nil, SSHKeyGroupStatusSyncing, tnu.ID)

	// Build SSHKeyGroupSiteAssociation
	skga1 := testBuildSSHKeyGroupSiteAssociation(t, dbSession, skg.ID, site1.ID, db.GetStrPtr("test-version"), SSHKeyGroupSiteAssociationStatusSynced, tnu.ID)
	assert.NotNil(t, skga1)

	skga2 := testBuildSSHKeyGroupSiteAssociation(t, dbSession, skg.ID, site2.ID, db.GetStrPtr("test-version"), SSHKeyGroupSiteAssociationStatusDeleting, tnu.ID)
	assert.NotNil(t, skga2)

	// Build SSHKey
	sk1 := testBuildSSHKey(t, dbSession, "test-ssh-key-1", tnOrg, tn.ID, "testpublickey", db.GetStrPtr("test"), nil, tn.ID)
	assert.NotNil(t, sk1)

	sk2 := testBuildSSHKey(t, dbSession, "test-ssh-key-2", tnOrg, tn.ID, "testpublickey", db.GetStrPtr("test"), nil, tn.ID)
	assert.NotNil(t, sk2)

	// Build SSHKeyAssociation
	ska1 := testBuildSSHKeyAssociation(t, dbSession, sk1.ID, skg.ID, tn.ID)
	assert.NotNil(t, ska1)

	ska2 := testBuildSSHKeyAssociation(t, dbSession, sk2.ID, skg.ID, tn.ID)
	assert.NotNil(t, ska2)

	skgad := NewSSHKeyGroupSiteAssociationDAO(dbSession)

	tests := []struct {
		name          string
		skga          *SSHKeyGroupSiteAssociation
		expectVersion bool
		expectErr     bool
	}{
		{
			name:          "success case with keys",
			skga:          skga1,
			expectErr:     false,
			expectVersion: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uskga, err := skgad.GenerateAndUpdateVersion(ctx, nil, tc.skga.ID)

			if tc.expectErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}

			if tc.expectVersion {
				assert.NotNil(t, uskga)
				assert.NotEqual(t, *tc.skga.Version, *uskga.Version)
			}
		})
	}
}

func TestSSHKeyGroupSiteAssociationSQLDAO_UpdateFromParams(t *testing.T) {
	ctx := context.Background()
	dbSession := testInstanceInitDB(t)
	defer dbSession.Close()
	testSSHKeyGroupSiteAssociationSetupSchema(t, dbSession)
	user := testOperatingSystemBuildUser(t, dbSession, "testUser")
	ip := testBuildInfrastructureProvider(t, dbSession, db.GetUUIDPtr(uuid.New()), "test", "testorg", user.ID)
	site := TestBuildSite(t, dbSession, ip, "test", user)
	site2 := TestBuildSite(t, dbSession, ip, "test2", user)
	tenant := testOperatingSystemBuildTenant(t, dbSession, "testTenant")

	skgasd := NewSSHKeyGroupSiteAssociationDAO(dbSession)
	sshKeyGroup1 := testBuildSSHKeyGroup(t, dbSession, "test1", db.GetStrPtr("test1"), "tesorg", tenant.ID, nil, SSHKeyGroupStatusSyncing, user.ID)
	sshKeyGroup2 := testBuildSSHKeyGroup(t, dbSession, "test2", db.GetStrPtr("test2"), "tesorg", tenant.ID, nil, SSHKeyGroupStatusSyncing, user.ID)

	skga1, err := skgasd.CreateFromParams(ctx, nil, sshKeyGroup1.ID, site.ID, nil, SSHKeyGroupSiteAssociationStatusSyncing, user.ID)
	assert.Nil(t, err)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc string
		id   uuid.UUID

		paramSSHKeyGroupID *uuid.UUID
		paramSiteID        *uuid.UUID
		paramVersion       *string
		paramStatus        *string

		expectedSSHKeyGroupID *uuid.UUID
		expectedSiteID        *uuid.UUID
		expectedVersion       *string
		expectedStatus        *string
		IsMissingOnSite       *bool

		expectError        bool
		verifyChildSpanner bool
	}{
		{
			desc:               "can update all fields",
			id:                 skga1.ID,
			paramSSHKeyGroupID: db.GetUUIDPtr(sshKeyGroup2.ID),
			paramVersion:       db.GetStrPtr("1234"),
			paramSiteID:        db.GetUUIDPtr(site2.ID),
			paramStatus:        db.GetStrPtr(SSHKeyGroupSiteAssociationStatusError),

			expectedSSHKeyGroupID: db.GetUUIDPtr(sshKeyGroup2.ID),
			expectedVersion:       db.GetStrPtr("1234"),
			expectedSiteID:        db.GetUUIDPtr(site2.ID),
			expectedStatus:        db.GetStrPtr(SSHKeyGroupSiteAssociationStatusError),
			IsMissingOnSite:       db.GetBoolPtr(true),

			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc:        "error when ID not found",
			id:          uuid.New(),
			expectError: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := skgasd.UpdateFromParams(ctx, nil, tc.id, tc.paramSSHKeyGroupID, tc.paramSiteID, tc.paramVersion, tc.paramStatus, tc.IsMissingOnSite)
			assert.Equal(t, tc.expectError, err != nil)
			if err == nil {
				assert.Equal(t, tc.expectedSSHKeyGroupID.String(), got.SSHKeyGroupID.String())
				assert.Equal(t, tc.expectedVersion, got.Version)
				assert.Equal(t, tc.expectedSiteID.String(), got.SiteID.String())
				assert.Equal(t, *tc.expectedStatus, got.Status)
				assert.Equal(t, *tc.IsMissingOnSite, got.IsMissingOnSite)
			}
			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestSSHKeyGroupSiteAssociationSQLDAO_DeleteByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testInstanceInitDB(t)
	defer dbSession.Close()
	testSSHKeyGroupSiteAssociationSetupSchema(t, dbSession)
	user := testOperatingSystemBuildUser(t, dbSession, "testUser")
	ip := testBuildInfrastructureProvider(t, dbSession, db.GetUUIDPtr(uuid.New()), "test", "testorg", user.ID)
	site := TestBuildSite(t, dbSession, ip, "test", user)
	tenant := testOperatingSystemBuildTenant(t, dbSession, "testTenant")

	skgasd := NewSSHKeyGroupSiteAssociationDAO(dbSession)
	sshKeyGroup1 := testBuildSSHKeyGroup(t, dbSession, "test1", db.GetStrPtr("test1"), "tesorg", tenant.ID, nil, SSHKeyGroupStatusSyncing, user.ID)

	skga1, err := skgasd.CreateFromParams(ctx, nil, sshKeyGroup1.ID, site.ID, nil, SSHKeyGroupSiteAssociationStatusSyncing, user.ID)
	assert.Nil(t, err)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		id                 uuid.UUID
		expectedError      bool
		verifyChildSpanner bool
	}{
		{
			desc:               "can delete existing object",
			id:                 skga1.ID,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:          "delete non-existing object",
			id:            uuid.New(),
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := skgasd.DeleteByID(ctx, nil, tc.id)
			assert.Equal(t, tc.expectedError, err != nil)
			if !tc.expectedError {
				tmp, err := skgasd.GetByID(ctx, nil, tc.id, nil)
				assert.NotNil(t, err)
				assert.Nil(t, tmp)
			}
			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}
