// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	otrace "go.opentelemetry.io/otel/trace"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	"github.com/google/uuid"
	"github.com/uptrace/bun/extra/bundebug"
)

func testVpcPrefixInitDB(t *testing.T) *db.Session {
	dbSession := util.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv(""),
	))
	return dbSession
}

// reset the tables needed for VpcPrefix tests
func testVpcPrefixSetupSchema(t *testing.T, dbSession *db.Session) {
	// create Vpc table
	err := dbSession.DB.ResetModel(context.Background(), (*Vpc)(nil))
	assert.Nil(t, err)
	// create VpcPrefix table
	err = dbSession.DB.ResetModel(context.Background(), (*VpcPrefix)(nil))
	assert.Nil(t, err)
	// create domain table
	err = dbSession.DB.ResetModel(context.Background(), (*Domain)(nil))
	assert.Nil(t, err)
	// create tenant table
	err = dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	assert.Nil(t, err)
	// create ipblock table
	err = dbSession.DB.ResetModel(context.Background(), (*IPBlock)(nil))
	assert.Nil(t, err)
	// create User table
	err = dbSession.DB.ResetModel(context.Background(), (*User)(nil))
	assert.Nil(t, err)
}

func testVpcPrefixBuildTenant(t *testing.T, dbSession *db.Session, name string) *Tenant {
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: name,
		Org:  "test",
	}
	_, err := dbSession.DB.NewInsert().Model(tenant).Exec(context.Background())
	assert.Nil(t, err)
	return tenant
}

func testVpcPrefixBuildInfrastructureProvider(t *testing.T, dbSession *db.Session, name string) *InfrastructureProvider {
	ip := &InfrastructureProvider{
		ID:          uuid.New(),
		Name:        name,
		DisplayName: db.GetStrPtr("TestInfraProvider"),
		Org:         "test",
	}
	_, err := dbSession.DB.NewInsert().Model(ip).Exec(context.Background())
	assert.Nil(t, err)
	return ip
}

func testVpcPrefixBuildSite(t *testing.T, dbSession *db.Session, ip *InfrastructureProvider, name string) *Site {
	st := &Site{
		ID:                          uuid.New(),
		Name:                        name,
		DisplayName:                 db.GetStrPtr("Test"),
		Org:                         "test",
		InfrastructureProviderID:    ip.ID,
		SiteControllerVersion:       db.GetStrPtr("1.0.0"),
		SiteAgentVersion:            db.GetStrPtr("1.0.0"),
		RegistrationToken:           db.GetStrPtr("1234-5678-9012-3456"),
		RegistrationTokenExpiration: db.GetTimePtr(db.GetCurTime()),
		Status:                      SiteStatusPending,
		CreatedBy:                   uuid.New(),
	}
	_, err := dbSession.DB.NewInsert().Model(st).Exec(context.Background())
	assert.Nil(t, err)
	return st
}

func testVpcPrefixBuildVpc(t *testing.T, dbSession *db.Session, infrastructureProvider *InfrastructureProvider, site *Site, tenant *Tenant, name string) *Vpc {
	vpc := &Vpc{
		ID:                       uuid.New(),
		Name:                     name,
		Org:                      "test",
		InfrastructureProviderID: infrastructureProvider.ID,
		SiteID:                   site.ID,
		TenantID:                 tenant.ID,
		Status:                   VpcStatusPending,
		CreatedBy:                uuid.New(),
	}
	_, err := dbSession.DB.NewInsert().Model(vpc).Exec(context.Background())
	assert.Nil(t, err)
	return vpc
}

func testVpcPrefixBuildDomain(t *testing.T, dbSession *db.Session, hostname string) *Domain {
	domain := &Domain{
		ID:       uuid.New(),
		Hostname: hostname,
		Org:      "test",
	}
	_, err := dbSession.DB.NewInsert().Model(domain).Exec(context.Background())
	assert.Nil(t, err)
	return domain
}

func testVpcPrefixBuildIPBlock(t *testing.T, dbSession *db.Session, siteID, infrastructureProviderID *uuid.UUID, name string, createdBy *uuid.UUID) *IPBlock {
	ipBlock := &IPBlock{
		ID:                       uuid.New(),
		Name:                     name,
		SiteID:                   *siteID,
		InfrastructureProviderID: *infrastructureProviderID,
		PrefixLength:             8,
		RoutingType:              IPBlockRoutingTypeDatacenterOnly,
		CreatedBy:                createdBy,
	}
	_, err := dbSession.DB.NewInsert().Model(ipBlock).Exec(context.Background())
	assert.Nil(t, err)
	return ipBlock
}

func testVpcPrefixBuildUser(t *testing.T, dbSession *db.Session, starfleetID string) *User {
	user := &User{
		ID:          uuid.New(),
		StarfleetID: db.GetStrPtr(starfleetID),
		Email:       db.GetStrPtr("jdoe@test.com"),
		FirstName:   db.GetStrPtr("John"),
		LastName:    db.GetStrPtr("Doe"),
	}
	_, err := dbSession.DB.NewInsert().Model(user).Exec(context.Background())
	assert.Nil(t, err)
	return user
}

func TestVpcPrefixSQLDAO_Create(t *testing.T) {
	ctx := context.Background()
	dbSession := testVpcPrefixInitDB(t)
	defer dbSession.Close()
	testVpcPrefixSetupSchema(t, dbSession)
	ip := testVpcPrefixBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testVpcPrefixBuildSite(t, dbSession, ip, "testSite")
	tenant := testVpcPrefixBuildTenant(t, dbSession, "testTenant")
	user := testVpcPrefixBuildUser(t, dbSession, "testUser")
	ipBlock := testVpcPrefixBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipBlock", &user.ID)
	vpc := testVpcPrefixBuildVpc(t, dbSession, ip, site, tenant, "testVpc")

	vpd := NewVpcPrefixDAO(dbSession)

	prefix := "192.0.2.0/24"

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		vps                []VpcPrefix
		expectError        bool
		verifyChildSpanner bool
	}{
		{
			desc: "create one",
			vps: []VpcPrefix{
				{
					Name: "test", Org: "test", SiteID: site.ID, VpcID: vpc.ID, TenantID: tenant.ID, IPBlockID: &ipBlock.ID, Prefix: prefix, PrefixLength: 24, Status: VpcPrefixStatusReady, CreatedBy: user.ID,
				},
			},
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc: "create mulitiple, some with null values in nullable fields",
			vps: []VpcPrefix{
				{
					Name: "test1", Org: "test", SiteID: site.ID, VpcID: vpc.ID, TenantID: tenant.ID, IPBlockID: &ipBlock.ID, Prefix: prefix, PrefixLength: 24, Status: VpcPrefixStatusReady, CreatedBy: user.ID,
				},
				{
					Name: "test2", Org: "test", SiteID: site.ID, VpcID: vpc.ID, TenantID: tenant.ID, IPBlockID: &ipBlock.ID, Prefix: prefix, PrefixLength: 24, Status: VpcPrefixStatusReady, CreatedBy: user.ID,
				},
			},
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc: "create fails, due to foreign key violation on vpcID",
			vps: []VpcPrefix{
				{
					Name: "test", Org: "test", SiteID: site.ID, VpcID: uuid.New(), TenantID: tenant.ID, IPBlockID: &ipBlock.ID, Prefix: prefix, PrefixLength: 24, Status: VpcPrefixStatusReady, CreatedBy: user.ID,
				},
			},
			expectError: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			for _, i := range tc.vps {
				got, err := vpd.Create(ctx, nil, VpcPrefixCreateInput{
					Name:         i.Name,
					TenantOrg:    i.Org,
					SiteID:       i.SiteID,
					VpcID:        i.VpcID,
					TenantID:     i.TenantID,
					IpBlockID:    i.IPBlockID,
					Prefix:       i.Prefix,
					PrefixLength: i.PrefixLength,
					Status:       i.Status,
					CreatedBy:    i.CreatedBy,
				})
				assert.Equal(t, tc.expectError, err != nil)
				if !tc.expectError {
					assert.NotNil(t, got)
					assert.Equal(t, i.Prefix, got.Prefix)
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

func TestVpcPrefixSQLDAO_GetByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testVpcPrefixInitDB(t)
	defer dbSession.Close()
	testVpcPrefixSetupSchema(t, dbSession)

	ip := testVpcPrefixBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testVpcPrefixBuildSite(t, dbSession, ip, "testSite")
	tenant := testVpcPrefixBuildTenant(t, dbSession, "testTenant")
	user := testVpcPrefixBuildUser(t, dbSession, "testUser")
	ipBlock := testVpcPrefixBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipBlock", &user.ID)
	vpc := testVpcPrefixBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	vps := NewVpcPrefixDAO(dbSession)

	prefix := "192.0.2.0/24"

	vpcprefix, err := vps.Create(ctx, nil, VpcPrefixCreateInput{
		Name:         "test",
		TenantOrg:    "test",
		SiteID:       site.ID,
		VpcID:        vpc.ID,
		TenantID:     tenant.ID,
		IpBlockID:    &ipBlock.ID,
		Prefix:       prefix,
		PrefixLength: 24,
		Status:       VpcPrefixStatusReady,
		CreatedBy:    user.ID,
	})

	assert.Nil(t, err)
	assert.NotNil(t, vpcprefix)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		id                 uuid.UUID
		vpcPrefix          *VpcPrefix
		paramRelations     []string
		expectedError      bool
		expectedErrVal     error
		expectedVpcID      *uuid.UUID
		verifyChildSpanner bool
	}{
		{
			desc:               "GetById success when exists",
			id:                 vpcprefix.ID,
			vpcPrefix:          vpcprefix,
			paramRelations:     []string{},
			expectedError:      false,
			expectedVpcID:      nil,
			verifyChildSpanner: true,
		},
		{
			desc:           "GetById error when not found",
			id:             uuid.New(),
			vpcPrefix:      vpcprefix,
			paramRelations: []string{},
			expectedError:  true,
			expectedErrVal: db.ErrDoesNotExist,
			expectedVpcID:  nil,
		},
		{
			desc:           "GetById with the Vpc relation",
			id:             vpcprefix.ID,
			vpcPrefix:      vpcprefix,
			paramRelations: []string{"Vpc"},
			expectedError:  false,
			expectedVpcID:  &vpc.ID,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := vps.GetByID(ctx, nil, tc.id, tc.paramRelations)
			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				assert.Equal(t, tc.expectedErrVal, err)
			}
			if err == nil {
				assert.EqualValues(t, tc.vpcPrefix.ID, got.ID)
				assert.Equal(t, tc.expectedVpcID != nil, got.Vpc != nil)
				if tc.expectedVpcID != nil {
					assert.Equal(t, *tc.expectedVpcID, got.Vpc.ID)
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

func TestVpcPrefixSQLDAO_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := testVpcPrefixInitDB(t)
	defer dbSession.Close()
	testVpcPrefixSetupSchema(t, dbSession)
	ip := testVpcPrefixBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testVpcPrefixBuildSite(t, dbSession, ip, "testSite")
	tenant1 := testVpcPrefixBuildTenant(t, dbSession, "testTenant1")
	tenant2 := testVpcPrefixBuildTenant(t, dbSession, "testTenant2")
	user := testVpcPrefixBuildUser(t, dbSession, "testUser")
	ipBlock1 := testVpcPrefixBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipBlock1", &user.ID)
	ipBlock2 := testVpcPrefixBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipBlock2", &user.ID)
	vpc1 := testVpcPrefixBuildVpc(t, dbSession, ip, site, tenant1, "testVpc1")
	vpc2 := testVpcPrefixBuildVpc(t, dbSession, ip, site, tenant2, "testVpc2")

	vpsd := NewVpcPrefixDAO(dbSession)

	prefix := "192.0.2.0/24"

	totalCount := 30

	vps := []VpcPrefix{}

	for i := 0; i < totalCount; i++ {
		if i%2 == 0 {
			vpcPrefix, err := vpsd.Create(ctx, nil, VpcPrefixCreateInput{
				Name:         fmt.Sprintf("VpcPrefix-%v", i),
				TenantOrg:    "test",
				SiteID:       site.ID,
				VpcID:        vpc1.ID,
				TenantID:     tenant1.ID,
				IpBlockID:    &ipBlock1.ID,
				Prefix:       prefix,
				PrefixLength: 24,
				Status:       VpcPrefixStatusReady,
				CreatedBy:    user.ID,
			})

			assert.Nil(t, err)
			vps = append(vps, *vpcPrefix)
		} else {
			_, err := vpsd.Create(ctx, nil, VpcPrefixCreateInput{
				Name:         fmt.Sprintf("VpcPrefix-%v", i),
				TenantOrg:    "test",
				SiteID:       site.ID,
				VpcID:        vpc2.ID,
				TenantID:     tenant2.ID,
				IpBlockID:    &ipBlock2.ID,
				Prefix:       prefix,
				PrefixLength: 24,
				Status:       VpcPrefixStatusReady,
				CreatedBy:    user.ID,
			})
			assert.Nil(t, err)
		}
	}

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		names              []string
		siteIDs            []uuid.UUID
		vpcIDs             []uuid.UUID
		tenantIDs          []uuid.UUID
		ip4BlockIDs        []uuid.UUID
		prefixes           []string
		prefixLengths      []int
		searchQuery        *string
		statuses           []string
		offset             *int
		limit              *int
		orderBy            *paginator.OrderBy
		firstEntry         *VpcPrefix
		expectedCount      int
		expectedTotal      *int
		expectedError      bool
		paramRelations     []string
		verifyChildSpanner bool
	}{
		{
			desc:               "GetAll with no filters returns objects",
			vpcIDs:             nil,
			expectedCount:      paginator.DefaultLimit,
			expectedTotal:      &totalCount,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:           "GetAll with relation filters returns objects",
			vpcIDs:         nil,
			expectedCount:  paginator.DefaultLimit,
			expectedTotal:  &totalCount,
			expectedError:  false,
			paramRelations: []string{VpcRelationName, SiteRelationName, TenantRelationName, IPBlockRelationName},
		},
		{
			desc:          "GetAll with Site filter returns objects",
			siteIDs:       []uuid.UUID{site.ID},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with Vpc filter returns objects",
			vpcIDs:        []uuid.UUID{vpc1.ID},
			expectedCount: totalCount / 2,
			expectedError: false,
		},
		{
			desc:          "GetAll with tenant filter returns objects",
			siteIDs:       nil,
			vpcIDs:        nil,
			tenantIDs:     []uuid.UUID{tenant2.ID},
			expectedCount: totalCount / 2,
			expectedError: false,
		},
		{
			desc:          "GetAll with Ipblock filter returns objects",
			ip4BlockIDs:   []uuid.UUID{ipBlock1.ID},
			expectedCount: totalCount / 2,
			expectedError: false,
		},
		{
			desc:          "GetAll with limit returns objects",
			vpcIDs:        []uuid.UUID{vpc1.ID},
			offset:        db.GetIntPtr(0),
			limit:         db.GetIntPtr(5),
			expectedCount: 5,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
		{
			desc:          "GetAll with offset returns objects",
			vpcIDs:        []uuid.UUID{vpc1.ID},
			offset:        db.GetIntPtr(5),
			expectedCount: 10,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
		{
			desc:   "GetAll with order by returns objects",
			vpcIDs: []uuid.UUID{vpc1.ID},
			orderBy: &paginator.OrderBy{
				Field: "name",
				Order: paginator.OrderDescending,
			},
			firstEntry:    &vps[4], // 5th entry is "VpcPrefix-8" and would appear first on descending order
			expectedCount: totalCount / 2,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
		{
			desc:          "GetAll with name search query returns objects",
			searchQuery:   db.GetStrPtr("VpcPrefix-"),
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with prefix filter returns objects",
			prefixes:      []string{prefix},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with prefix length filter returns objects",
			prefixLengths: []int{24},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with status search query returns objects",
			searchQuery:   db.GetStrPtr(VpcPrefixStatusReady),
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with empty search query returns objects",
			vpcIDs:        nil,
			searchQuery:   db.GetStrPtr(""),
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with status returns objects",
			vpcIDs:        nil,
			statuses:      []string{VpcPrefixStatusReady},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, total, err := vpsd.GetAll(ctx, nil,
				VpcPrefixFilterInput{
					Names:         tc.names,
					SiteIDs:       tc.siteIDs,
					VpcIDs:        tc.vpcIDs,
					TenantIDs:     tc.tenantIDs,
					IpBlockIDs:    tc.ip4BlockIDs,
					Prefixes:      tc.prefixes,
					PrefixLengths: tc.prefixLengths,
					Statuses:      tc.statuses,
					SearchQuery:   tc.searchQuery,
				},
				paginator.PageInput{
					Offset:  tc.offset,
					Limit:   tc.limit,
					OrderBy: tc.orderBy,
				},
				tc.paramRelations,
			)
			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				assert.Equal(t, nil, got)
			} else {
				assert.Equal(t, tc.expectedCount, len(got))
				if len(tc.paramRelations) > 0 {
					assert.NotNil(t, got[0].Vpc)
					assert.NotNil(t, got[0].Tenant)
					assert.NotNil(t, got[0].IPBlock)
				}
			}

			if tc.expectedTotal != nil {
				assert.Equal(t, *tc.expectedTotal, total)
			}

			if tc.firstEntry != nil {
				assert.Equal(t, tc.firstEntry.Name, got[0].Name)
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

func TestVpcPrefixSQLDAO_Update(t *testing.T) {
	ctx := context.Background()
	dbSession := testVpcPrefixInitDB(t)
	defer dbSession.Close()
	testVpcPrefixSetupSchema(t, dbSession)
	ip := testVpcPrefixBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testVpcPrefixBuildSite(t, dbSession, ip, "testSite")
	tenant := testVpcPrefixBuildTenant(t, dbSession, "testTenant")
	tenant2 := testVpcPrefixBuildTenant(t, dbSession, "testTenant2")
	user := testVpcPrefixBuildUser(t, dbSession, "testUser")
	ipBlock := testVpcPrefixBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipBlock", &user.ID)
	ipBlock2 := testVpcPrefixBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipBlock2", &user.ID)
	vpc := testVpcPrefixBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	vpc2 := testVpcPrefixBuildVpc(t, dbSession, ip, site, tenant2, "testVpc2")

	vpsd := NewVpcPrefixDAO(dbSession)
	prefix := "192.0.2.0/24"

	VpcPrefix1, err := vpsd.Create(ctx, nil, VpcPrefixCreateInput{
		Name:         "test1",
		TenantOrg:    "test",
		SiteID:       site.ID,
		VpcID:        vpc.ID,
		TenantID:     tenant.ID,
		IpBlockID:    &ipBlock.ID,
		Prefix:       prefix,
		PrefixLength: 24,
		Status:       VpcPrefixStatusReady,
		CreatedBy:    user.ID,
	})

	assert.Nil(t, err)
	assert.NotNil(t, VpcPrefix1)
	newPrefix := "198.0.1.0/16"
	newPrefixLength := 16

	dummyUUID := uuid.New()

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc                 string
		id                   uuid.UUID
		paramName            *string
		paramOrg             *string
		paramVpcID           *uuid.UUID
		paramTenantID        *uuid.UUID
		paramIPBlockID       *uuid.UUID
		paramPrefix          *string
		paramPrefixLength    *int
		paramStatus          *string
		paramIsMissingOnSite *bool

		expectedName            *string
		expectedOrg             *string
		expectedVpcID           *uuid.UUID
		expectedTenantID        *uuid.UUID
		expectedIPBlockID       *uuid.UUID
		expectedprefix          *string
		expectedPrefixLength    *int
		expectedStatus          *string
		expectedIsMissingOnSite *bool
		expectedError           bool
		verifyChildSpanner      bool
	}{
		{
			desc:                 "can update all fields",
			id:                   VpcPrefix1.ID,
			paramName:            db.GetStrPtr("updatedName"),
			paramOrg:             db.GetStrPtr("updatedOrg"),
			paramVpcID:           &vpc2.ID,
			paramTenantID:        &tenant2.ID,
			paramIPBlockID:       &ipBlock2.ID,
			paramPrefix:          db.GetStrPtr(newPrefix),
			paramPrefixLength:    &newPrefixLength,
			paramStatus:          db.GetStrPtr(VpcPrefixStatusReady),
			paramIsMissingOnSite: db.GetBoolPtr(true),

			expectedError:           false,
			expectedName:            db.GetStrPtr("updatedName"),
			expectedOrg:             db.GetStrPtr("updatedOrg"),
			expectedVpcID:           &vpc2.ID,
			expectedTenantID:        &tenant2.ID,
			expectedIPBlockID:       &ipBlock2.ID,
			expectedprefix:          db.GetStrPtr(newPrefix),
			expectedPrefixLength:    &newPrefixLength,
			expectedStatus:          db.GetStrPtr(VpcPrefixStatusReady),
			expectedIsMissingOnSite: db.GetBoolPtr(true),
			verifyChildSpanner:      true,
		},
		{
			desc:                 "can update some fields",
			id:                   VpcPrefix1.ID,
			paramName:            nil,
			paramVpcID:           &vpc.ID,
			paramPrefixLength:    nil,
			paramStatus:          db.GetStrPtr(VpcPrefixStatusReady),
			paramIsMissingOnSite: nil,

			expectedError:           false,
			expectedName:            db.GetStrPtr("updatedName"),
			expectedVpcID:           &vpc.ID,
			expectedprefix:          db.GetStrPtr(newPrefix),
			expectedPrefixLength:    &newPrefixLength,
			expectedStatus:          db.GetStrPtr(VpcPrefixStatusReady),
			expectedIsMissingOnSite: db.GetBoolPtr(true),
		},
		{
			desc:      "error updating when Vpc foreign key violated",
			id:        VpcPrefix1.ID,
			paramName: db.GetStrPtr("updatedName"),

			paramVpcID:           &dummyUUID,
			paramPrefix:          db.GetStrPtr(newPrefix),
			paramStatus:          db.GetStrPtr(VpcPrefixStatusReady),
			paramIsMissingOnSite: db.GetBoolPtr(true),

			expectedError: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := vpsd.Update(
				ctx, nil, VpcPrefixUpdateInput{
					VpcPrefixID:     tc.id,
					Name:            tc.paramName,
					TenantOrg:       tc.paramOrg,
					VpcID:           tc.paramVpcID,
					TenantID:        tc.paramTenantID,
					IpBlockID:       tc.paramIPBlockID,
					Prefix:          tc.paramPrefix,
					PrefixLength:    tc.paramPrefixLength,
					Status:          tc.paramStatus,
					IsMissingOnSite: tc.paramIsMissingOnSite,
				})
			assert.Equal(t, tc.expectedError, err != nil)
			if err == nil {
				assert.NotNil(t, got)
				assert.Equal(t, *tc.expectedName, got.Name)
				if tc.expectedOrg != nil {
					assert.Equal(t, *tc.expectedOrg, got.Org)
				}
				assert.Equal(t, *tc.expectedVpcID, got.VpcID)
				if tc.expectedTenantID != nil {
					assert.Equal(t, *tc.expectedTenantID, got.TenantID)
				}
				if tc.expectedIPBlockID != nil {
					assert.Equal(t, *tc.expectedIPBlockID, *got.IPBlockID)
				}
				if tc.expectedprefix != nil {
					assert.Equal(t, *tc.expectedprefix, got.Prefix)
				}
				assert.Equal(t, *tc.expectedPrefixLength, got.PrefixLength)
				assert.Equal(t, *tc.expectedStatus, got.Status)
				assert.Equal(t, *tc.expectedIsMissingOnSite, got.IsMissingOnSite)

				if got.Updated.String() == VpcPrefix1.Updated.String() {
					t.Errorf("got.Updated = %v, want different value", got.Updated)
				}

			} else {
				assert.Nil(t, got)
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

func testVpcPrefixSQLDAO_Delete(t *testing.T) {
	ctx := context.Background()
	dbSession := testVpcPrefixInitDB(t)
	defer dbSession.Close()
	testVpcPrefixSetupSchema(t, dbSession)
	ip := testVpcPrefixBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testVpcPrefixBuildSite(t, dbSession, ip, "testSite")
	tenant := testVpcPrefixBuildTenant(t, dbSession, "testTenant")
	user := testVpcPrefixBuildUser(t, dbSession, "testUser")
	ipBlock := testVpcPrefixBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipBlock", &user.ID)
	vpc := testVpcPrefixBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	vpsd := NewVpcPrefixDAO(dbSession)

	prefix := "192.0.2.0/24"

	vpcPrefix, err := vpsd.Create(ctx, nil, VpcPrefixCreateInput{
		Name:         "test",
		TenantOrg:    "test",
		SiteID:       site.ID,
		VpcID:        vpc.ID,
		TenantID:     tenant.ID,
		IpBlockID:    &ipBlock.ID,
		Prefix:       prefix,
		PrefixLength: 8,
		Status:       VpcPrefixStatusReady,
		CreatedBy:    user.ID,
	})

	assert.Nil(t, err)
	assert.NotNil(t, vpcPrefix)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		vpID               uuid.UUID
		expectedError      bool
		verifyChildSpanner bool
	}{
		{
			desc:               "can delete existing object",
			vpID:               vpcPrefix.ID,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:          "delete non-existing object",
			vpID:          vpcPrefix.ID,
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := vpsd.Delete(ctx, nil, tc.vpID)
			assert.Equal(t, tc.expectedError, err != nil)
			if !tc.expectedError {
				tmp, err := vpsd.GetByID(ctx, nil, tc.vpID, nil)
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
