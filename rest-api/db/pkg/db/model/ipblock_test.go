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

func testIPBlockInitDB(t *testing.T) *db.Session {
	dbSession := util.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv(""),
	))
	return dbSession
}

// reset the tables needed for IPBlock tests
func testIPBlockSetupSchema(t *testing.T, dbSession *db.Session) {
	// create Site table
	err := dbSession.DB.ResetModel(context.Background(), (*Site)(nil))
	assert.Nil(t, err)
	// create Infrastructure Provider table
	err = dbSession.DB.ResetModel(context.Background(), (*InfrastructureProvider)(nil))
	assert.Nil(t, err)
	// create tenant table
	err = dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	assert.Nil(t, err)
	// create NetworkSecurityGroup table
	err = dbSession.DB.ResetModel(context.Background(), (*NetworkSecurityGroup)(nil))
	assert.Nil(t, err)
	// create User table
	err = dbSession.DB.ResetModel(context.Background(), (*User)(nil))
	assert.Nil(t, err)
	// create IPBlock table
	err = dbSession.DB.ResetModel(context.Background(), (*IPBlock)(nil))
	assert.Nil(t, err)
}

func testIPBlockBuildSite(t *testing.T, dbSession *db.Session, ip *InfrastructureProvider, name string) *Site {
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

func testIPBlockBuildInfrastructureProvider(t *testing.T, dbSession *db.Session, name string) *InfrastructureProvider {
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

func testIPBlockBuildTenant(t *testing.T, dbSession *db.Session, name string) *Tenant {
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: name,
		Org:  "test",
	}
	_, err := dbSession.DB.NewInsert().Model(tenant).Exec(context.Background())
	assert.Nil(t, err)
	return tenant
}

func TestIPBlockSQLDAO_Create(t *testing.T) {
	ctx := context.Background()
	dbSession := testIPBlockInitDB(t)
	defer dbSession.Close()
	testIPBlockSetupSchema(t, dbSession)
	ip := testIPBlockBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testIPBlockBuildSite(t, dbSession, ip, "testSite")
	tenant := testIPBlockBuildTenant(t, dbSession, "testTenant")
	user := testInstanceBuildUser(t, dbSession, "testUser")

	ipsd := NewIPBlockDAO(dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		its                []IPBlock
		expectError        bool
		verifyChildSpanner bool
	}{
		{
			desc: "create one",
			its: []IPBlock{
				{
					Name: "test", SiteID: site.ID, InfrastructureProviderID: ip.ID, TenantID: &tenant.ID, PrefixLength: 32, Prefix: "10.0.1.0", FullGrant: false, Status: IPBlockStatusPending, CreatedBy: &user.ID,
				},
			},
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc: "create multiple, some with nullable site field",
			its: []IPBlock{
				{
					Name: "test1", SiteID: site.ID, InfrastructureProviderID: ip.ID, TenantID: &tenant.ID, PrefixLength: 32, Prefix: "10.0.1.0", FullGrant: false, Status: IPBlockStatusPending, CreatedBy: &user.ID,
				},
				{
					Name: "test2", SiteID: site.ID, InfrastructureProviderID: ip.ID, TenantID: &tenant.ID, PrefixLength: 32, Prefix: "10.0.2.0", FullGrant: false, Status: IPBlockStatusPending, CreatedBy: &user.ID,
				},
				{
					Name: "test3", SiteID: site.ID, InfrastructureProviderID: ip.ID, TenantID: &tenant.ID, PrefixLength: 32, Prefix: "10.0.3.0", FullGrant: true, Status: IPBlockStatusPending, CreatedBy: &user.ID,
				},
			},
			expectError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			for _, i := range tc.its {
				it, err := ipsd.Create(
					ctx,
					nil,
					IPBlockCreateInput{
						Name:                     i.Name,
						Description:              db.GetStrPtr("description"),
						SiteID:                   site.ID,
						InfrastructureProviderID: ip.ID,
						TenantID:                 &tenant.ID,
						RoutingType:              IPBlockRoutingTypePublic,
						Prefix:                   i.Prefix,
						PrefixLength:             i.PrefixLength,
						ProtocolVersion:          "v4",
						FullGrant:                i.FullGrant,
						Status:                   i.Status,
						CreatedBy:                i.CreatedBy,
					},
				)
				assert.Equal(t, tc.expectError, err != nil)
				if !tc.expectError {
					assert.NotNil(t, it)
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

func TestIPBlockSQLDAO_GetByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testIPBlockInitDB(t)
	defer dbSession.Close()
	testIPBlockSetupSchema(t, dbSession)
	ip := testIPBlockBuildInfrastructureProvider(t, dbSession, "testIP")
	site1 := testIPBlockBuildSite(t, dbSession, ip, "testSite1")
	tenant := testIPBlockBuildTenant(t, dbSession, "testTenant")
	user := testInstanceBuildUser(t, dbSession, "testUser")

	ipsd := NewIPBlockDAO(dbSession)

	ipb, err := ipsd.Create(
		ctx,
		nil,
		IPBlockCreateInput{
			Name:                     "test1",
			Description:              db.GetStrPtr("description"),
			SiteID:                   site1.ID,
			InfrastructureProviderID: ip.ID,
			TenantID:                 &tenant.ID,
			RoutingType:              IPBlockRoutingTypePublic,
			Prefix:                   "10.0.1.0",
			PrefixLength:             32,
			ProtocolVersion:          "v4",
			FullGrant:                false,
			Status:                   IPBlockStatusProvisioning,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, ipb)

	ipb2, err := ipsd.Create(
		ctx, nil, IPBlockCreateInput{
			Name:                     "test2",
			Description:              db.GetStrPtr("description"),
			SiteID:                   site1.ID,
			InfrastructureProviderID: ip.ID,
			RoutingType:              IPBlockRoutingTypePublic,
			Prefix:                   "10.0.2.0",
			PrefixLength:             32,
			ProtocolVersion:          "v4",
			FullGrant:                false,
			Status:                   IPBlockStatusProvisioning,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, ipb2)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc                           string
		id                             uuid.UUID
		ipb                            *IPBlock
		paramRelations                 []string
		expectedError                  bool
		expectedErrVal                 error
		expectedSite                   bool
		expectedInfrastructureProvider bool
		expectedTenant                 bool
		verifyChildSpanner             bool
	}{
		{
			desc:                           "GetById success when IPBlock exists",
			id:                             ipb.ID,
			ipb:                            ipb,
			paramRelations:                 []string{},
			expectedError:                  false,
			expectedSite:                   false,
			expectedInfrastructureProvider: false,
			expectedTenant:                 false,
			verifyChildSpanner:             true,
		},
		{
			desc:                           "GetById error when not found",
			id:                             uuid.New(),
			ipb:                            ipb,
			paramRelations:                 []string{},
			expectedError:                  true,
			expectedErrVal:                 db.ErrDoesNotExist,
			expectedSite:                   false,
			expectedInfrastructureProvider: false,
			expectedTenant:                 false,
		},
		{
			desc:                           "GetById with the site relation",
			id:                             ipb.ID,
			ipb:                            ipb,
			paramRelations:                 []string{"Site"},
			expectedError:                  false,
			expectedSite:                   true,
			expectedInfrastructureProvider: false,
			expectedTenant:                 false,
		},
		{
			desc:                           "GetById with site, infrastructure_provider relations",
			id:                             ipb.ID,
			ipb:                            ipb,
			paramRelations:                 []string{"Site", "InfrastructureProvider"},
			expectedError:                  false,
			expectedSite:                   true,
			expectedInfrastructureProvider: true,
			expectedTenant:                 false,
		},
		{
			desc:                           "GetById with site, infrastructure_provider and tenant relations",
			id:                             ipb.ID,
			ipb:                            ipb,
			paramRelations:                 []string{"Site", "InfrastructureProvider", "Tenant"},
			expectedError:                  false,
			expectedSite:                   true,
			expectedInfrastructureProvider: true,
			expectedTenant:                 true,
		},
		{
			desc:                           "GetById with site, infrastructure_provider and tenant relations when tenant is nil",
			id:                             ipb2.ID,
			ipb:                            ipb2,
			paramRelations:                 []string{"Site", "InfrastructureProvider", "Tenant"},
			expectedError:                  false,
			expectedSite:                   true,
			expectedInfrastructureProvider: true,
			expectedTenant:                 false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			tmp, err := ipsd.GetByID(ctx, nil, tc.id, tc.paramRelations)
			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				assert.Equal(t, tc.expectedErrVal, err)
			}
			if err == nil {
				assert.EqualValues(t, tc.ipb.ID, tmp.ID)
				assert.Equal(t, tc.expectedSite, tmp.Site != nil)
				if tc.expectedSite {
					assert.EqualValues(t, tc.ipb.SiteID, tmp.Site.ID)
				}
				assert.Equal(t, tc.expectedInfrastructureProvider, tmp.InfrastructureProvider != nil)
				if tc.expectedInfrastructureProvider {
					assert.EqualValues(t, tc.ipb.InfrastructureProviderID, tmp.InfrastructureProvider.ID)
				}
				assert.Equal(t, tc.expectedTenant, tmp.Tenant != nil)
				if tc.expectedTenant {
					assert.EqualValues(t, *tc.ipb.TenantID, tmp.Tenant.ID)
				} else {
					assert.Nil(t, tmp.Tenant)
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

func TestIPBlockSQLDAO_GetCountByStatus(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx context.Context
	}

	ctx := context.Background()
	dbSession := testIPBlockInitDB(t)
	defer dbSession.Close()
	testIPBlockSetupSchema(t, dbSession)
	ip := testIPBlockBuildInfrastructureProvider(t, dbSession, "testIP")
	site1 := testIPBlockBuildSite(t, dbSession, ip, "testSite1")
	tenant := testIPBlockBuildTenant(t, dbSession, "testTenant")
	user := testInstanceBuildUser(t, dbSession, "testUser")

	ipsd := NewIPBlockDAO(dbSession)

	ipb, err := ipsd.Create(
		ctx, nil, IPBlockCreateInput{
			Name:                     "test1",
			Description:              db.GetStrPtr("description"),
			SiteID:                   site1.ID,
			InfrastructureProviderID: ip.ID,
			TenantID:                 &tenant.ID,
			RoutingType:              IPBlockRoutingTypePublic,
			Prefix:                   "10.0.1.0",
			PrefixLength:             32,
			ProtocolVersion:          "v4",
			FullGrant:                false,
			Status:                   IPBlockStatusProvisioning,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, ipb)

	ipb2, err := ipsd.Create(
		ctx, nil, IPBlockCreateInput{
			Name:                     "test2",
			Description:              db.GetStrPtr("description"),
			SiteID:                   site1.ID,
			InfrastructureProviderID: ip.ID,
			RoutingType:              IPBlockRoutingTypePublic,
			Prefix:                   "10.0.2.0",
			PrefixLength:             32,
			ProtocolVersion:          "v4",
			FullGrant:                false,
			Status:                   IPBlockStatusProvisioning,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, ipb2)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		name               string
		id                 uuid.UUID
		fields             fields
		args               args
		wantErr            error
		wantEmpty          bool
		wantCount          int
		wantStatusMap      map[string]int
		reqIP              *uuid.UUID
		reqSite            *uuid.UUID
		reqTenant          *uuid.UUID
		verifyChildSpanner bool
	}{
		{
			name: "get ipblock status count by infrastructure provider with ipblock returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr:   nil,
			wantEmpty: false,
			wantCount: 2,
			wantStatusMap: map[string]int{
				IPBlockStatusDeleting:     0,
				IPBlockStatusError:        0,
				IPBlockStatusReady:        0,
				IPBlockStatusPending:      0,
				IPBlockStatusProvisioning: 2,
				"total":                   2,
			},
			reqIP:              db.GetUUIDPtr(ip.ID),
			verifyChildSpanner: true,
		},
		{
			name: "get ipblock status count by site with ipblock returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr:   nil,
			wantEmpty: false,
			wantCount: 2,
			wantStatusMap: map[string]int{
				IPBlockStatusDeleting:     0,
				IPBlockStatusError:        0,
				IPBlockStatusReady:        0,
				IPBlockStatusPending:      0,
				IPBlockStatusProvisioning: 2,
				"total":                   2,
			},
			reqSite: db.GetUUIDPtr(site1.ID),
		},
		{
			name: "get ipblock status count by tenant with ipblock returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr:   nil,
			wantEmpty: false,
			wantCount: 1,
			wantStatusMap: map[string]int{
				IPBlockStatusDeleting:     0,
				IPBlockStatusError:        0,
				IPBlockStatusReady:        0,
				IPBlockStatusPending:      0,
				IPBlockStatusProvisioning: 1,
				"total":                   1,
			},
			reqTenant: db.GetUUIDPtr(tenant.ID),
		},
		{
			name: "get ipblock status count by unexisted infrastructure provider with no ipblock returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr:   nil,
			wantEmpty: true,
			wantCount: 0,
			reqIP:     db.GetUUIDPtr(uuid.New()),
		},
		{
			name: "get ipblock status count with no filter ipblock returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr:   nil,
			wantCount: 2,
			wantStatusMap: map[string]int{
				IPBlockStatusDeleting:     0,
				IPBlockStatusError:        0,
				IPBlockStatusReady:        0,
				IPBlockStatusPending:      0,
				IPBlockStatusProvisioning: 2,
				"total":                   2,
			},
			wantEmpty: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isd := IPBlockSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			got, err := isd.GetCountByStatus(tt.args.ctx, nil, tt.reqIP, tt.reqSite, tt.reqTenant)
			if tt.wantErr != nil {
				assert.ErrorAs(t, err, &tt.wantErr)
				return
			}
			if tt.wantEmpty {
				assert.EqualValues(t, got["total"], 0)
			}
			if err == nil && !tt.wantEmpty {
				assert.EqualValues(t, tt.wantStatusMap, got)
				if len(got) > 0 {
					assert.EqualValues(t, got[IPBlockStatusProvisioning], tt.wantCount)
					assert.EqualValues(t, got["total"], tt.wantCount)
				}
			}

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestIPBlockSQLDAO_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := testIPBlockInitDB(t)
	defer dbSession.Close()
	testIPBlockSetupSchema(t, dbSession)
	ip := testIPBlockBuildInfrastructureProvider(t, dbSession, "testIP")
	site1 := testIPBlockBuildSite(t, dbSession, ip, "testSite1")
	site2 := testIPBlockBuildSite(t, dbSession, ip, "testSite2")
	site3 := testIPBlockBuildSite(t, dbSession, ip, "testSite3")
	tenant := testIPBlockBuildTenant(t, dbSession, "testTenant")
	user := testInstanceBuildUser(t, dbSession, "testUser")

	ipbsd := NewIPBlockDAO(dbSession)

	totalCount := 30

	site2ipbs := []IPBlock{}

	for i := 0; i < totalCount; i++ {
		if i%2 == 1 {
			_, err := ipbsd.Create(
				ctx, nil, IPBlockCreateInput{
					Name:                     fmt.Sprintf("test-%v", i),
					Description:              db.GetStrPtr("description"),
					SiteID:                   site1.ID,
					InfrastructureProviderID: ip.ID,
					RoutingType:              IPBlockRoutingTypePublic,
					Prefix:                   fmt.Sprintf("202.16.%v.0", i),
					PrefixLength:             10,
					ProtocolVersion:          "v4",
					FullGrant:                false,
					Status:                   IPBlockStatusProvisioning,
					CreatedBy:                &user.ID,
				},
			)
			assert.NoError(t, err)
		} else {
			ipb, err := ipbsd.Create(
				ctx, nil, IPBlockCreateInput{
					Name:                     fmt.Sprintf("test-%v", i),
					Description:              db.GetStrPtr("description"),
					SiteID:                   site2.ID,
					InfrastructureProviderID: ip.ID,
					TenantID:                 &tenant.ID,
					RoutingType:              IPBlockRoutingTypeDatacenterOnly,
					Prefix:                   fmt.Sprintf("10.0.%v.0", i),
					PrefixLength:             10,
					ProtocolVersion:          "v4",
					FullGrant:                false,
					Status:                   IPBlockStatusProvisioning,
					CreatedBy:                &user.ID,
				},
			)
			assert.NoError(t, err)
			site2ipbs = append(site2ipbs, *ipb)
		}
	}

	dummyUUID := uuid.New()

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc                      string
		siteIDs                   []uuid.UUID
		infrastructureProviderIDs []uuid.UUID
		tenantIDs                 []uuid.UUID
		routingTypes              []string
		ipbNames                  []string
		fullGrant                 *bool
		excludeDerived            bool
		prefixes                  []string
		prefixLengths             []int
		searchQuery               *string
		statuses                  []string
		ids                       []uuid.UUID
		offset                    *int
		limit                     *int
		orderBy                   *paginator.OrderBy
		firstEntry                *IPBlock
		expectedCount             int
		expectedTotal             *int
		expectedError             bool
		paramRelations            []string
		verifyChildSpanner        bool
	}{
		{
			desc:                      "GetAll with no filters returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			expectedCount:             paginator.DefaultLimit,
			expectedTotal:             &totalCount,
			expectedError:             false,
			verifyChildSpanner:        true,
		},
		{
			desc:                      "GetAll with relation returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			expectedCount:             paginator.DefaultLimit,
			expectedTotal:             &totalCount,
			expectedError:             false,
			paramRelations:            []string{"Site", "InfrastructureProvider", "Tenant"},
		},
		{
			desc:                      "GetAll returns no objects",
			siteIDs:                   []uuid.UUID{dummyUUID},
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			expectedCount:             0,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with site filter returns objects",
			siteIDs:                   []uuid.UUID{site1.ID},
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			ipbNames:                  nil,
			routingTypes:              nil,
			expectedCount:             totalCount / 2,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with RoutingTypePublic filter returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              []string{IPBlockRoutingTypePublic},
			ipbNames:                  nil,
			expectedCount:             totalCount / 2,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with RoutingTypeDatacenterOnly filter returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              []string{IPBlockRoutingTypeDatacenterOnly},
			ipbNames:                  nil,
			expectedCount:             totalCount / 2,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with site filter returns no objects",
			siteIDs:                   []uuid.UUID{site3.ID},
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			ipbNames:                  nil,
			routingTypes:              nil,
			expectedCount:             0,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with site and infrastructure provider filter returns objects",
			siteIDs:                   []uuid.UUID{site1.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			expectedCount:             totalCount / 2,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with site and infrastructure provider filter returns no objects",
			siteIDs:                   []uuid.UUID{site3.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			expectedCount:             0,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with site infrastructure and tenant filters returns objects",
			siteIDs:                   []uuid.UUID{site2.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 []uuid.UUID{tenant.ID},
			routingTypes:              nil,
			ipbNames:                  nil,
			expectedCount:             totalCount / 2,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with site infrastructure and exclude derived filters returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			excludeDerived:            true,
			routingTypes:              nil,
			ipbNames:                  nil,
			expectedCount:             totalCount / 2,
			expectedError:             false,
		}, {
			desc:                      "GetAll with site infrastructure and tenant filters returns no objects",
			siteIDs:                   []uuid.UUID{site3.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 []uuid.UUID{tenant.ID},
			routingTypes:              nil,
			ipbNames:                  nil,
			expectedCount:             0,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with site infrastructure tenant and name filters returns objects",
			siteIDs:                   []uuid.UUID{site2.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 []uuid.UUID{tenant.ID},
			routingTypes:              nil,
			ipbNames:                  []string{"test-0"},
			fullGrant:                 db.GetBoolPtr(false),
			expectedCount:             1,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with limit returns objects",
			siteIDs:                   []uuid.UUID{site1.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			offset:                    db.GetIntPtr(0),
			limit:                     db.GetIntPtr(5),
			expectedCount:             5,
			expectedTotal:             db.GetIntPtr(totalCount / 2),
			expectedError:             false,
		},
		{
			desc:                      "GetAll with offset returns objects",
			siteIDs:                   []uuid.UUID{site1.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			offset:                    db.GetIntPtr(5),
			expectedCount:             10,
			expectedTotal:             db.GetIntPtr(totalCount / 2),
			expectedError:             false,
		},
		{
			desc:                      "GetAll with order by returns objects",
			siteIDs:                   []uuid.UUID{site2.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			orderBy: &paginator.OrderBy{
				Field: "name",
				Order: paginator.OrderDescending,
			},
			firstEntry:    &site2ipbs[4], // 5th entry is "test-8" and would appear first in descending order
			expectedCount: totalCount / 2,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
		{
			desc:                      "GetAll with name search query returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			searchQuery:               db.GetStrPtr("test-"),
			expectedCount:             paginator.DefaultLimit,
			expectedTotal:             &totalCount,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with description  search query returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			searchQuery:               db.GetStrPtr("description"),
			expectedCount:             paginator.DefaultLimit,
			expectedTotal:             &totalCount,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with status search query returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			searchQuery:               db.GetStrPtr(IPBlockStatusProvisioning),
			expectedCount:             paginator.DefaultLimit,
			expectedTotal:             &totalCount,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with empty search query returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			searchQuery:               db.GetStrPtr(""),
			expectedCount:             paginator.DefaultLimit,
			expectedTotal:             &totalCount,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with IPBlockStatusProvisioning status returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			statuses:                  []string{IPBlockStatusProvisioning},
			expectedCount:             paginator.DefaultLimit,
			expectedTotal:             &totalCount,
			expectedError:             false,
		},
		{
			desc:                      "GetAll with ids filters returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			ids: []uuid.UUID{
				site2ipbs[0].ID,
				site2ipbs[1].ID,
				site2ipbs[2].ID,
			},
			expectedCount: 3,
			expectedTotal: db.GetIntPtr(3),
			expectedError: false,
		},
		{
			desc:                      "GetAll with status and ids filters returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			ids: []uuid.UUID{
				site2ipbs[0].ID,
				site2ipbs[1].ID,
				site2ipbs[2].ID,
			},
			statuses:      []string{IPBlockStatusProvisioning},
			expectedCount: 3,
			expectedTotal: db.GetIntPtr(3),
			expectedError: false,
		},
		{
			desc:                      "GetAll with status and ids filters returns no objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			ids: []uuid.UUID{
				site2ipbs[0].ID,
				site2ipbs[1].ID,
				site2ipbs[2].ID,
			},
			statuses:      []string{IPBlockStatusError},
			expectedCount: 0,
			expectedTotal: db.GetIntPtr(0),
			expectedError: false,
		},
		{
			desc:                      "GetAll with IPBlockStatusError status returns objects",
			siteIDs:                   nil,
			infrastructureProviderIDs: nil,
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			statuses:                  []string{IPBlockStatusError},
			expectedCount:             0,
			expectedTotal:             db.GetIntPtr(0),
			expectedError:             false,
		},
		{
			desc:                      "GetAll with site, prefix and prefixLenth returns object",
			siteIDs:                   []uuid.UUID{site2.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			prefixes:                  []string{"10.0.2.0"},
			prefixLengths:             []int{10},
			statuses:                  nil,
			expectedCount:             1,
			expectedTotal:             db.GetIntPtr(1),
			expectedError:             false,
		},
		{
			desc:                      "GetAll with site, prefix and prefixLenth returns no object",
			siteIDs:                   []uuid.UUID{site1.ID},
			infrastructureProviderIDs: []uuid.UUID{ip.ID},
			tenantIDs:                 nil,
			routingTypes:              nil,
			ipbNames:                  nil,
			prefixes:                  []string{"10.0.2.0"},
			prefixLengths:             []int{10},
			statuses:                  nil,
			expectedCount:             0,
			expectedTotal:             db.GetIntPtr(0),
			expectedError:             false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, total, err := ipbsd.GetAll(
				ctx,
				nil,
				IPBlockFilterInput{
					SiteIDs:                   tc.siteIDs,
					InfrastructureProviderIDs: tc.infrastructureProviderIDs,
					TenantIDs:                 tc.tenantIDs,
					RoutingTypes:              tc.routingTypes,
					Names:                     tc.ipbNames,
					FullGrant:                 tc.fullGrant,
					ExcludeDerived:            tc.excludeDerived,
					Prefixes:                  tc.prefixes,
					PrefixLengths:             tc.prefixLengths,
					Statuses:                  tc.statuses,
					SearchQuery:               tc.searchQuery,
					IPBlockIDs:                tc.ids,
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
					assert.NotNil(t, got[0].Site)
					assert.NotNil(t, got[0].Tenant)
					assert.NotNil(t, got[0].InfrastructureProvider)
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

func TestIPBlockSQLDAO_Update(t *testing.T) {
	ctx := context.Background()
	dbSession := testIPBlockInitDB(t)
	defer dbSession.Close()
	testIPBlockSetupSchema(t, dbSession)
	ip := testIPBlockBuildInfrastructureProvider(t, dbSession, "testIP")
	ip2 := testIPBlockBuildInfrastructureProvider(t, dbSession, "testIP2")
	site1 := testIPBlockBuildSite(t, dbSession, ip, "testSite1")
	site2 := testIPBlockBuildSite(t, dbSession, ip, "testSite2")
	tenant := testIPBlockBuildTenant(t, dbSession, "testTenant")
	tenant2 := testIPBlockBuildTenant(t, dbSession, "testTenant2")
	user := testInstanceBuildUser(t, dbSession, "testUser")

	ipbsd := NewIPBlockDAO(dbSession)

	ipb, err := ipbsd.Create(
		ctx, nil, IPBlockCreateInput{
			Name:                     "test1",
			Description:              db.GetStrPtr("description"),
			SiteID:                   site1.ID,
			InfrastructureProviderID: ip.ID,
			TenantID:                 &tenant.ID,
			RoutingType:              IPBlockRoutingTypePublic,
			Prefix:                   "10.0.1.0",
			PrefixLength:             32,
			ProtocolVersion:          "v4",
			FullGrant:                false,
			Status:                   IPBlockStatusProvisioning,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, ipb)

	newBlockSize := 128

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc string
		ipb  *IPBlock

		paramName                     *string
		paramDescription              *string
		paramSiteID                   *uuid.UUID
		paramInfrastructureProviderID *uuid.UUID
		paramTenantID                 *uuid.UUID
		paramRoutingType              *string
		paramPrefix                   *string
		paramBlockSize                *int
		paramProtocolVersion          *string
		paramFullGrant                *bool
		paramStatus                   *string

		expectedName                     *string
		expectedDescription              *string
		expectedSiteID                   *uuid.UUID
		expectedInfrastructureProviderID *uuid.UUID
		expectedTenantID                 *uuid.UUID
		expectedRoutingType              *string
		expectedPrefix                   *string
		expectedBlockSize                *int
		expectedProtocolVersion          *string
		expectedFullGrant                *bool
		expectedStatus                   *string
		verifyChildSpanner               bool
	}{
		{
			desc: "can update string, bool fields: name, description, routingtype, prefix, protocolversion, status",
			ipb:  ipb,

			paramName:                     db.GetStrPtr("updatedName"),
			paramDescription:              db.GetStrPtr("updatedDescription"),
			paramSiteID:                   nil,
			paramInfrastructureProviderID: nil,
			paramTenantID:                 nil,
			paramRoutingType:              db.GetStrPtr("updatedRoutingType"),
			paramPrefix:                   db.GetStrPtr("updatedPrefix"),
			paramBlockSize:                nil,
			paramProtocolVersion:          db.GetStrPtr("updatedProtocolVersion"),
			paramFullGrant:                db.GetBoolPtr(true),
			paramStatus:                   db.GetStrPtr(IPBlockStatusProvisioning),

			expectedName:                     db.GetStrPtr("updatedName"),
			expectedDescription:              db.GetStrPtr("updatedDescription"),
			expectedSiteID:                   &ipb.SiteID,
			expectedInfrastructureProviderID: &ipb.InfrastructureProviderID,
			expectedTenantID:                 ipb.TenantID,
			expectedRoutingType:              db.GetStrPtr("updatedRoutingType"),
			expectedPrefix:                   db.GetStrPtr("updatedPrefix"),
			expectedBlockSize:                &ipb.PrefixLength,
			expectedProtocolVersion:          db.GetStrPtr("updatedProtocolVersion"),
			expectedFullGrant:                db.GetBoolPtr(true),
			expectedStatus:                   db.GetStrPtr(IPBlockStatusProvisioning),
			verifyChildSpanner:               true,
		},
		{
			desc: "can update uuid fields: siteid, infrastructureproviderid, tenantid",
			ipb:  ipb,

			paramName:                     nil,
			paramDescription:              nil,
			paramSiteID:                   &site2.ID,
			paramInfrastructureProviderID: &ip2.ID,
			paramTenantID:                 &tenant2.ID,
			paramRoutingType:              nil,
			paramPrefix:                   nil,
			paramBlockSize:                nil,
			paramProtocolVersion:          nil,
			paramStatus:                   nil,

			expectedName:                     db.GetStrPtr("updatedName"),
			expectedDescription:              db.GetStrPtr("updatedDescription"),
			expectedSiteID:                   &site2.ID,
			expectedInfrastructureProviderID: &ip2.ID,
			expectedTenantID:                 &tenant2.ID,
			expectedRoutingType:              db.GetStrPtr("updatedRoutingType"),
			expectedPrefix:                   db.GetStrPtr("updatedPrefix"),
			expectedBlockSize:                &ipb.PrefixLength,
			expectedProtocolVersion:          db.GetStrPtr("updatedProtocolVersion"),
			expectedStatus:                   db.GetStrPtr(IPBlockStatusProvisioning),
		},
		{
			desc: "can update int fields: blocksize",
			ipb:  ipb,

			paramName:                     nil,
			paramDescription:              nil,
			paramSiteID:                   nil,
			paramInfrastructureProviderID: nil,
			paramTenantID:                 nil,
			paramRoutingType:              nil,
			paramPrefix:                   nil,
			paramBlockSize:                &newBlockSize,
			paramProtocolVersion:          nil,
			paramStatus:                   nil,

			expectedName:                     db.GetStrPtr("updatedName"),
			expectedDescription:              db.GetStrPtr("updatedDescription"),
			expectedSiteID:                   &site2.ID,
			expectedInfrastructureProviderID: &ip2.ID,
			expectedTenantID:                 &tenant2.ID,
			expectedRoutingType:              db.GetStrPtr("updatedRoutingType"),
			expectedPrefix:                   db.GetStrPtr("updatedPrefix"),
			expectedBlockSize:                &newBlockSize,
			expectedProtocolVersion:          db.GetStrPtr("updatedProtocolVersion"),
			expectedStatus:                   db.GetStrPtr(IPBlockStatusProvisioning),
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := ipbsd.Update(
				ctx,
				nil,
				IPBlockUpdateInput{
					IPBlockID:                tc.ipb.ID,
					Name:                     tc.paramName,
					Description:              tc.paramDescription,
					SiteID:                   tc.paramSiteID,
					InfrastructureProviderID: tc.paramInfrastructureProviderID,
					TenantID:                 tc.paramTenantID,
					RoutingType:              tc.paramRoutingType,
					Prefix:                   tc.paramPrefix,
					PrefixLength:             tc.paramBlockSize,
					ProtocolVersion:          tc.paramProtocolVersion,
					FullGrant:                tc.paramFullGrant,
					Status:                   tc.paramStatus,
				},
			)
			assert.Nil(t, err)
			assert.NotNil(t, got)

			assert.Equal(t, *tc.expectedName, got.Name)

			assert.Equal(t, tc.expectedDescription == nil, got.Description == nil)
			if tc.expectedDescription != nil {
				assert.Equal(t, *tc.expectedDescription, *got.Description)
			}
			assert.Equal(t, *tc.expectedSiteID, got.SiteID)
			assert.Equal(t, *tc.expectedInfrastructureProviderID, got.InfrastructureProviderID)
			assert.Equal(t, tc.expectedTenantID == nil, got.TenantID == nil)
			if tc.expectedTenantID != nil {
				assert.Equal(t, *tc.expectedTenantID, *got.TenantID)
			}
			assert.Equal(t, *tc.expectedRoutingType, got.RoutingType)
			assert.Equal(t, *tc.expectedPrefix, got.Prefix)
			assert.Equal(t, *tc.expectedBlockSize, got.PrefixLength)
			assert.Equal(t, *tc.expectedProtocolVersion, got.ProtocolVersion)
			assert.Equal(t, *tc.expectedStatus, got.Status)

			if tc.paramFullGrant != nil {
				assert.Equal(t, *tc.expectedFullGrant, got.FullGrant)
			}

			if got.Updated.String() == tc.ipb.Updated.String() {
				t.Errorf("got.Updated = %v, want different value", got.Updated)
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

func TestIPBlockSQLDAO_Clear(t *testing.T) {
	ctx := context.Background()
	dbSession := testIPBlockInitDB(t)
	defer dbSession.Close()
	testIPBlockSetupSchema(t, dbSession)
	ip := testIPBlockBuildInfrastructureProvider(t, dbSession, "testIP")
	site1 := testIPBlockBuildSite(t, dbSession, ip, "testSite1")
	site2 := testIPBlockBuildSite(t, dbSession, ip, "testSite2")
	tenant := testIPBlockBuildTenant(t, dbSession, "testTenant")
	user := testInstanceBuildUser(t, dbSession, "testUser")

	ipbsd := NewIPBlockDAO(dbSession)

	ipb, err := ipbsd.Create(
		ctx, nil, IPBlockCreateInput{
			Name:                     "test1",
			Description:              db.GetStrPtr("description"),
			SiteID:                   site1.ID,
			InfrastructureProviderID: ip.ID,
			TenantID:                 &tenant.ID,
			RoutingType:              IPBlockRoutingTypePublic,
			Prefix:                   "10.0.1.0",
			PrefixLength:             32,
			ProtocolVersion:          "v4",
			FullGrant:                false,
			Status:                   IPBlockStatusProvisioning,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, ipb)

	ipb2, err := ipbsd.Create(
		ctx, nil, IPBlockCreateInput{
			Name:                     "test2",
			Description:              db.GetStrPtr("description"),
			SiteID:                   site1.ID,
			InfrastructureProviderID: ip.ID,
			TenantID:                 &tenant.ID,
			RoutingType:              IPBlockRoutingTypePublic,
			Prefix:                   "10.0.2.0",
			PrefixLength:             32,
			ProtocolVersion:          "v4",
			FullGrant:                false,
			Status:                   IPBlockStatusProvisioning,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, ipb2)

	ipb3, err := ipbsd.Create(
		ctx, nil, IPBlockCreateInput{
			Name:                     "test1",
			Description:              db.GetStrPtr("description"),
			SiteID:                   site2.ID,
			InfrastructureProviderID: ip.ID,
			TenantID:                 &tenant.ID,
			RoutingType:              IPBlockRoutingTypePublic,
			Prefix:                   "10.0.3.0",
			PrefixLength:             32,
			ProtocolVersion:          "v4",
			FullGrant:                false,
			Status:                   IPBlockStatusProvisioning,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, ipb3)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc                string
		ipb                 *IPBlock
		paramDescription    bool
		paramTenantID       bool
		expectedUpdate      bool
		expectedDescription *string
		expectedTenantID    *uuid.UUID
		expectedError       bool
		verifyChildSpanner  bool
	}{
		{
			desc:                "can clear description",
			ipb:                 ipb,
			paramDescription:    true,
			paramTenantID:       false,
			expectedUpdate:      true,
			expectedDescription: nil,
			expectedTenantID:    ipb.TenantID,
			expectedError:       false,
			verifyChildSpanner:  true,
		},
		{
			desc:                "can clear tenant",
			ipb:                 ipb2,
			paramDescription:    false,
			paramTenantID:       true,
			expectedUpdate:      true,
			expectedDescription: db.GetStrPtr("description"),
			expectedTenantID:    nil,
			expectedError:       false,
		},
		{
			desc:                "can clear multiple fields at once",
			ipb:                 ipb3,
			paramDescription:    true,
			paramTenantID:       true,
			expectedUpdate:      true,
			expectedDescription: nil,
			expectedTenantID:    nil,
			expectedError:       false,
		},
		{
			desc:                "nop when no cleared fields are specified",
			ipb:                 ipb,
			paramDescription:    false,
			paramTenantID:       false,
			expectedUpdate:      false,
			expectedDescription: nil,
			expectedTenantID:    ipb.TenantID,
			expectedError:       false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			tmp, err := ipbsd.Clear(ctx, nil, IPBlockClearInput{
				IPBlockID:   tc.ipb.ID,
				Description: tc.paramDescription,
				TenantID:    tc.paramTenantID,
			})
			assert.Equal(t, tc.expectedError, err != nil)
			assert.NotNil(t, tmp)
			assert.Equal(t, tc.expectedDescription == nil, tmp.Description == nil)
			if tc.expectedDescription != nil {
				assert.Equal(t, *tc.expectedDescription, *tmp.Description)
			}
			assert.Equal(t, tc.expectedTenantID == nil, tmp.TenantID == nil)
			if tc.expectedTenantID != nil {
				assert.Equal(t, *tc.expectedTenantID, *tmp.TenantID)
			}

			if tc.expectedUpdate {
				assert.True(t, tmp.Updated.After(tc.ipb.Updated))
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

func TestIPBlockSQLDAO_Delete(t *testing.T) {
	ctx := context.Background()
	dbSession := testIPBlockInitDB(t)
	defer dbSession.Close()
	testIPBlockSetupSchema(t, dbSession)
	ip := testIPBlockBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testIPBlockBuildSite(t, dbSession, ip, "testSite")
	tenant := testIPBlockBuildTenant(t, dbSession, "testTenant")
	user := testInstanceBuildUser(t, dbSession, "testUser")

	ipbsd := NewIPBlockDAO(dbSession)

	ipb, err := ipbsd.Create(
		ctx, nil, IPBlockCreateInput{
			Name:                     "test1",
			Description:              db.GetStrPtr("description"),
			SiteID:                   site.ID,
			InfrastructureProviderID: ip.ID,
			TenantID:                 &tenant.ID,
			RoutingType:              IPBlockRoutingTypePublic,
			Prefix:                   "10.0.1.0",
			PrefixLength:             32,
			ProtocolVersion:          "v4",
			FullGrant:                false,
			Status:                   IPBlockStatusProvisioning,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, ipb)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		ipbID              uuid.UUID
		expectedError      bool
		verifyChildSpanner bool
	}{
		{
			desc:               "can delete existing object",
			ipbID:              ipb.ID,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:          "delete non-existing object",
			ipbID:         uuid.New(),
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := ipbsd.Delete(ctx, nil, tc.ipbID)
			assert.Equal(t, tc.expectedError, err != nil)
			if !tc.expectedError {
				tmp, err := ipbsd.GetByID(ctx, nil, tc.ipbID, nil)
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
