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

func testSubnetInitDB(t *testing.T) *db.Session {
	dbSession := util.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv(""),
	))
	return dbSession
}

// reset the tables needed for Subnet tests
func testSubnetSetupSchema(t *testing.T, dbSession *db.Session) {
	// create Vpc table
	err := dbSession.DB.ResetModel(context.Background(), (*Vpc)(nil))
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
	// create Subnet table
	err = dbSession.DB.ResetModel(context.Background(), (*Subnet)(nil))
	assert.Nil(t, err)
}

func testSubnetBuildTenant(t *testing.T, dbSession *db.Session, name string) *Tenant {
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: name,
		Org:  "test",
	}
	_, err := dbSession.DB.NewInsert().Model(tenant).Exec(context.Background())
	assert.Nil(t, err)
	return tenant
}

func testSubnetBuildInfrastructureProvider(t *testing.T, dbSession *db.Session, name string) *InfrastructureProvider {
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

func testSubnetBuildSite(t *testing.T, dbSession *db.Session, ip *InfrastructureProvider, name string) *Site {
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

func testSubnetBuildVpc(t *testing.T, dbSession *db.Session, infrastructureProvider *InfrastructureProvider, site *Site, tenant *Tenant, name string) *Vpc {
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

func testSubnetBuildDomain(t *testing.T, dbSession *db.Session, hostname string) *Domain {
	domain := &Domain{
		ID:       uuid.New(),
		Hostname: hostname,
		Org:      "test",
	}
	_, err := dbSession.DB.NewInsert().Model(domain).Exec(context.Background())
	assert.Nil(t, err)
	return domain
}

func testSubnetBuildIPBlock(t *testing.T, dbSession *db.Session, siteID, infrastructureProviderID *uuid.UUID, name string, createdBy *uuid.UUID) *IPBlock {
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

func testSubnetBuildUser(t *testing.T, dbSession *db.Session, starfleetID string) *User {
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

func TestSubnetSQLDAO_Create(t *testing.T) {
	ctx := context.Background()
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)
	ip := testSubnetBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testSubnetBuildSite(t, dbSession, ip, "testSite")
	tenant := testSubnetBuildTenant(t, dbSession, "testTenant")
	vpc := testSubnetBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	domain := testSubnetBuildDomain(t, dbSession, "testDomain")
	user := testSubnetBuildUser(t, dbSession, "testUser")
	ipv4Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block", &user.ID)
	ipv6Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv6Block", &user.ID)
	ssd := NewSubnetDAO(dbSession)
	dummyUUID := uuid.New()
	ipv4Prefix := "192.0.2.0/24"
	ipv4Gateway := "192.0.2.1"
	ipv6Prefix := "2001:db8:abcd:0012::0/24"
	ipv6Gateway := "2001:db8:abcd:0012::1"
	mtu := 1500

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		ss                 []Subnet
		expectError        bool
		verifyChildSpanner bool
	}{
		{
			desc: "create one",
			ss: []Subnet{
				{
					Name: "test", Description: db.GetStrPtr("test"), Org: "test", SiteID: site.ID, VpcID: vpc.ID, DomainID: &domain.ID, TenantID: tenant.ID, ControllerNetworkSegmentID: &dummyUUID, RoutingType: db.GetStrPtr(IPBlockRoutingTypeDatacenterOnly), IPv4Prefix: &ipv4Prefix, IPv4Gateway: &ipv4Gateway, IPv4BlockID: &ipv4Block.ID, IPv6Prefix: &ipv6Prefix, IPv6Gateway: &ipv6Gateway, IPv6BlockID: &ipv6Block.ID, PrefixLength: 8, Status: SubnetStatusPending, CreatedBy: user.ID, MTU: &mtu,
				},
			},
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc: "create mulitiple, some with null values in nullable fields",
			ss: []Subnet{
				{
					Name: "test1", Description: db.GetStrPtr("test"), Org: "test", SiteID: site.ID, VpcID: vpc.ID, DomainID: &domain.ID, TenantID: tenant.ID, ControllerNetworkSegmentID: &dummyUUID, RoutingType: db.GetStrPtr(IPBlockRoutingTypeDatacenterOnly), IPv4Prefix: &ipv4Prefix, IPv4Gateway: &ipv4Gateway, IPv4BlockID: &ipv4Block.ID, IPv6Prefix: &ipv6Prefix, IPv6Gateway: &ipv6Gateway, IPv6BlockID: &ipv6Block.ID, PrefixLength: 8, Status: SubnetStatusPending, CreatedBy: user.ID,
				},
				{
					Name: "test2", Description: db.GetStrPtr("test"), Org: "test", SiteID: site.ID, VpcID: vpc.ID, DomainID: nil, TenantID: tenant.ID, ControllerNetworkSegmentID: nil, RoutingType: db.GetStrPtr(IPBlockRoutingTypeDatacenterOnly), IPv4Prefix: &ipv4Prefix, IPv4Gateway: &ipv4Gateway, IPv4BlockID: &ipv4Block.ID, IPv6Prefix: nil, IPv6BlockID: nil, IPv6Gateway: nil, PrefixLength: 8, Status: SubnetStatusPending, CreatedBy: user.ID,
				},
				{
					Name: "test3", Description: db.GetStrPtr("test"), Org: "test", SiteID: site.ID, VpcID: vpc.ID, DomainID: &domain.ID, TenantID: tenant.ID, ControllerNetworkSegmentID: nil, RoutingType: db.GetStrPtr(IPBlockRoutingTypeDatacenterOnly), IPv4Prefix: &ipv4Prefix, IPv4Gateway: &ipv4Gateway, IPv4BlockID: &ipv4Block.ID, IPv6Prefix: nil, IPv6Gateway: nil, IPv6BlockID: nil, PrefixLength: 8, Status: SubnetStatusPending, CreatedBy: user.ID,
				},
			},
			expectError: false,
		},
		{
			desc: "create fails, due to foreign key violation on vpcID",
			ss: []Subnet{
				{
					Name: "test", Description: db.GetStrPtr("test"), Org: "test", SiteID: site.ID, VpcID: uuid.New(), DomainID: &domain.ID, TenantID: tenant.ID, ControllerNetworkSegmentID: &dummyUUID, RoutingType: db.GetStrPtr(IPBlockRoutingTypeDatacenterOnly), IPv4Prefix: &ipv4Prefix, IPv4BlockID: &ipv4Block.ID, IPv6Prefix: &ipv6Prefix, IPv6BlockID: &ipv6Block.ID, PrefixLength: 8, Status: SubnetStatusPending, CreatedBy: user.ID,
				},
			},
			expectError: true,
		},
		{
			desc: "create will succeed when nullable foreign keys have null values",
			ss: []Subnet{
				{
					Name: "test", Description: db.GetStrPtr("test"), Org: "test", SiteID: site.ID, VpcID: vpc.ID, DomainID: nil, TenantID: tenant.ID, ControllerNetworkSegmentID: &dummyUUID, RoutingType: db.GetStrPtr(IPBlockRoutingTypeDatacenterOnly), IPv4Prefix: &ipv4Prefix, IPv4BlockID: nil, IPv6Prefix: &ipv6Prefix, IPv6BlockID: nil, PrefixLength: 8, Status: SubnetStatusPending, CreatedBy: user.ID,
				},
			},
			expectError: false,
		},
		// Test case for creating a subnet with a specific MTU value
		{
			desc: "create with specific MTU value",
			ss: []Subnet{
				{
					Name: "testWithMTU", Description: db.GetStrPtr("With specific MTU"), Org: "test", SiteID: site.ID, VpcID: vpc.ID, TenantID: tenant.ID, PrefixLength: 24, Status: SubnetStatusPending, CreatedBy: user.ID, MTU: &mtu,
				},
			},
			expectError: false,
		},
		// Test case for creating a subnet without specifying an MTU (expecting nil MTU)
		{
			desc: "create without specifying MTU",
			ss: []Subnet{
				{
					Name: "testWithoutMTU", Description: db.GetStrPtr("Without MTU"), Org: "test", SiteID: site.ID, VpcID: vpc.ID, TenantID: tenant.ID, PrefixLength: 24, Status: SubnetStatusPending, CreatedBy: user.ID, MTU: nil,
				},
			},
			expectError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			for _, i := range tc.ss {
				got, err := ssd.Create(
					ctx, nil, SubnetCreateInput{
						Name:                       i.Name,
						Description:                i.Description,
						Org:                        i.Org,
						SiteID:                     i.SiteID,
						VpcID:                      i.VpcID,
						DomainID:                   i.DomainID,
						TenantID:                   i.TenantID,
						ControllerNetworkSegmentID: i.ControllerNetworkSegmentID,
						RoutingType:                i.RoutingType,
						IPv4Prefix:                 i.IPv4Prefix,
						IPv4Gateway:                i.IPv4Gateway,
						IPv4BlockID:                i.IPv4BlockID,
						IPv6Prefix:                 i.IPv6Prefix,
						IPv6Gateway:                i.IPv6Gateway,
						IPv6BlockID:                i.IPv6BlockID,
						PrefixLength:               i.PrefixLength,
						Mtu:                        &mtu,
						Status:                     i.Status,
						CreatedBy:                  i.CreatedBy,
					},
				)
				assert.Equal(t, tc.expectError, err != nil)
				if !tc.expectError {
					assert.NotNil(t, got)
					// If MTU is set, check it; otherwise, skip the check
					if i.MTU != nil {
						assert.Equal(t, *i.MTU, *got.MTU)
					}
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

func TestSubnetSQLDAO_GetByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)

	ip := testSubnetBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testSubnetBuildSite(t, dbSession, ip, "testSite")
	tenant := testSubnetBuildTenant(t, dbSession, "testTenant")
	vpc := testSubnetBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	domain := testSubnetBuildDomain(t, dbSession, "testDomain")
	user := testSubnetBuildUser(t, dbSession, "testUser")
	ipv4Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block", &user.ID)
	ipv6Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv6Block", &user.ID)
	ssd := NewSubnetDAO(dbSession)
	dummyUUID := uuid.New()
	ipv4Prefix := "192.0.2.0/24"
	ipv4Gateway := "192.0.2.1"
	ipv6Prefix := "2001:db8:abcd:0012::0/24"
	ipv6Gateway := "2001:db8:abcd:0012::1"
	subnet, err := ssd.Create(
		ctx, nil, SubnetCreateInput{
			Name:                       "test",
			Description:                db.GetStrPtr("test"),
			Org:                        "test",
			SiteID:                     site.ID,
			VpcID:                      vpc.ID,
			DomainID:                   &domain.ID,
			TenantID:                   tenant.ID,
			ControllerNetworkSegmentID: &dummyUUID,
			RoutingType:                &ipv4Block.RoutingType,
			IPv4Prefix:                 &ipv4Prefix,
			IPv4Gateway:                &ipv4Gateway,
			IPv4BlockID:                &ipv4Block.ID,
			IPv6Prefix:                 &ipv6Prefix,
			IPv6Gateway:                &ipv6Gateway,
			IPv6BlockID:                &ipv6Block.ID,
			PrefixLength:               8,
			Status:                     SubnetStatusPending,
			CreatedBy:                  user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, subnet)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		id                 uuid.UUID
		subnet             *Subnet
		paramRelations     []string
		expectedError      bool
		expectedErrVal     error
		expectedVpcID      *uuid.UUID
		expectedTenantID   *uuid.UUID
		expectedDomainID   *uuid.UUID
		verifyChildSpanner bool
	}{
		{
			desc:               "GetById success when exists",
			id:                 subnet.ID,
			subnet:             subnet,
			paramRelations:     []string{},
			expectedError:      false,
			expectedVpcID:      nil,
			expectedTenantID:   nil,
			expectedDomainID:   nil,
			verifyChildSpanner: true,
		},
		{
			desc:             "GetById error when not found",
			id:               uuid.New(),
			subnet:           subnet,
			paramRelations:   []string{},
			expectedError:    true,
			expectedErrVal:   db.ErrDoesNotExist,
			expectedVpcID:    nil,
			expectedTenantID: nil,
			expectedDomainID: nil,
		},
		{
			desc:             "GetById with the Vpc relation",
			id:               subnet.ID,
			subnet:           subnet,
			paramRelations:   []string{"Vpc"},
			expectedError:    false,
			expectedVpcID:    &vpc.ID,
			expectedTenantID: nil,
			expectedDomainID: nil,
		},
		{
			desc:             "GetById with the Vpc and Tenant relations",
			id:               subnet.ID,
			subnet:           subnet,
			paramRelations:   []string{"Vpc", "Tenant"},
			expectedError:    false,
			expectedVpcID:    &vpc.ID,
			expectedTenantID: &tenant.ID,
			expectedDomainID: nil,
		},
		{
			desc:             "GetById with the Vpc, Tenant, and Domain relations",
			id:               subnet.ID,
			subnet:           subnet,
			paramRelations:   []string{"Vpc", "Tenant", "Domain"},
			expectedError:    false,
			expectedVpcID:    &vpc.ID,
			expectedTenantID: &tenant.ID,
			expectedDomainID: &domain.ID,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := ssd.GetByID(ctx, nil, tc.id, tc.paramRelations)
			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				assert.Equal(t, tc.expectedErrVal, err)
			}
			if err == nil {
				assert.EqualValues(t, tc.subnet.ID, got.ID)
				assert.Equal(t, tc.expectedVpcID != nil, got.Vpc != nil)
				if tc.expectedVpcID != nil {
					assert.Equal(t, *tc.expectedVpcID, got.Vpc.ID)
				}
				assert.Equal(t, tc.expectedTenantID != nil, got.Tenant != nil)
				if tc.expectedTenantID != nil {
					assert.Equal(t, *tc.expectedTenantID, got.Tenant.ID)
				}
				assert.Equal(t, ipv4Block.RoutingType, *got.RoutingType)
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

func TestSubnetSQLDAO_GetCountByStatus(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx context.Context
	}

	ctx := context.Background()
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)
	ip := testSubnetBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testSubnetBuildSite(t, dbSession, ip, "testSite")
	tenant := testSubnetBuildTenant(t, dbSession, "testTenant")
	vpc := testSubnetBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	domain := testSubnetBuildDomain(t, dbSession, "testDomain")
	user := testSubnetBuildUser(t, dbSession, "testUser")
	ipv4Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block", &user.ID)
	ipv6Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv6Block", &user.ID)
	ssd := NewSubnetDAO(dbSession)
	dummyUUID := uuid.New()
	ipv4Prefix := "192.0.2.0/24"
	ipv4Gateway := "192.0.2.1"
	ipv6Prefix := "2001:db8:abcd:0012::0/24"
	ipv6Gateway := "2001:db8:abcd:0012::1"
	subnet, err := ssd.Create(
		ctx, nil, SubnetCreateInput{
			Name:                       "test",
			Description:                db.GetStrPtr("test"),
			Org:                        "test",
			SiteID:                     site.ID,
			VpcID:                      vpc.ID,
			DomainID:                   &domain.ID,
			TenantID:                   tenant.ID,
			ControllerNetworkSegmentID: &dummyUUID,
			RoutingType:                &ipv4Block.RoutingType,
			IPv4Prefix:                 &ipv4Prefix,
			IPv4Gateway:                &ipv4Gateway,
			IPv4BlockID:                &ipv4Block.ID,
			IPv6Prefix:                 &ipv6Prefix,
			IPv6Gateway:                &ipv6Gateway,
			IPv6BlockID:                &ipv6Block.ID,
			PrefixLength:               8,
			Status:                     SubnetStatusPending,
			CreatedBy:                  user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, subnet)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		name               string
		fields             fields
		args               args
		wantErr            error
		wantEmpty          bool
		wantCount          int
		wantStatusMap      map[string]int
		reqTenant          *uuid.UUID
		reqVpc             *uuid.UUID
		reqOrg             *string
		paramRelations     []string
		verifyChildSpanner bool
	}{
		{
			name: "get subnet status count by tenant with subnet returns success",
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
				SubnetStatusError:        0,
				SubnetStatusProvisioning: 0,
				SubnetStatusPending:      1,
				SubnetStatusDeleting:     0,
				SubnetStatusReady:        0,
				"total":                  1,
			},
			reqTenant:          db.GetUUIDPtr(tenant.ID),
			verifyChildSpanner: true,
		},
		{
			name: "get subnet status count by tenant with no subnet returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr:   nil,
			wantEmpty: true,
			reqTenant: db.GetUUIDPtr(uuid.New()),
		},
		{
			name: "get subnet status count with no filter subnet returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantCount: 1,
			wantStatusMap: map[string]int{
				SubnetStatusError:        0,
				SubnetStatusProvisioning: 0,
				SubnetStatusPending:      1,
				SubnetStatusDeleting:     0,
				SubnetStatusReady:        0,
				"total":                  1,
			},
			wantErr:   nil,
			wantEmpty: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ssd := SubnetSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			got, err := ssd.GetCountByStatus(tt.args.ctx, nil, tt.reqTenant, tt.reqVpc)
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
					assert.EqualValues(t, got[SubnetStatusPending], 1)
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

func TestSubnetSQLDAO_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)
	ip := testSubnetBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testSubnetBuildSite(t, dbSession, ip, "testSite")
	tenant1 := testSubnetBuildTenant(t, dbSession, "testTenant1")
	tenant2 := testSubnetBuildTenant(t, dbSession, "testTenant2")
	tenant3 := testSubnetBuildTenant(t, dbSession, "testTenant3")
	vpc1 := testSubnetBuildVpc(t, dbSession, ip, site, tenant1, "testVpc1")
	vpc2 := testSubnetBuildVpc(t, dbSession, ip, site, tenant2, "testVpc2")
	domain1 := testSubnetBuildDomain(t, dbSession, "testDomain1")
	domain2 := testSubnetBuildDomain(t, dbSession, "testDomain2")
	user := testSubnetBuildUser(t, dbSession, "testUser")
	ipv4Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block", &user.ID)
	ipv6Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv6Block", &user.ID)
	ssd := NewSubnetDAO(dbSession)
	dummyUUID := uuid.New()
	ipv4Prefix := "192.0.2.0/24"
	ipv4Gateway := "192.0.2.1"
	ipv6Prefix := "2001:db8:abcd:0012::0/24"
	ipv6Gateway := "2001:db8:abcd:0012::1"

	totalCount := 30

	ssTenant1 := []Subnet{}

	for i := 0; i < totalCount; i++ {
		if i%2 == 0 {
			subnet, err := ssd.Create(
				ctx, nil, SubnetCreateInput{
					Name:                       fmt.Sprintf("subnet-%v", i),
					Description:                db.GetStrPtr("Test Description"),
					Org:                        "test",
					SiteID:                     site.ID,
					VpcID:                      vpc1.ID,
					DomainID:                   &domain1.ID,
					TenantID:                   tenant1.ID,
					ControllerNetworkSegmentID: &dummyUUID,
					RoutingType:                &ipv4Block.RoutingType,
					IPv4Prefix:                 &ipv4Prefix,
					IPv4Gateway:                &ipv4Gateway,
					IPv4BlockID:                &ipv4Block.ID,
					IPv6Prefix:                 &ipv6Prefix,
					IPv6Gateway:                &ipv6Gateway,
					IPv6BlockID:                &ipv6Block.ID,
					PrefixLength:               8,
					Status:                     SubnetStatusPending,
					CreatedBy:                  user.ID,
				})
			assert.Nil(t, err)
			ssTenant1 = append(ssTenant1, *subnet)
		} else {
			_, err := ssd.Create(
				ctx, nil, SubnetCreateInput{
					Name:                       fmt.Sprintf("subnet-%v", i),
					Description:                db.GetStrPtr("Test Description"),
					Org:                        "test",
					SiteID:                     site.ID,
					VpcID:                      vpc2.ID,
					DomainID:                   &domain2.ID,
					TenantID:                   tenant2.ID,
					ControllerNetworkSegmentID: &dummyUUID,
					RoutingType:                &ipv4Block.RoutingType,
					IPv4Prefix:                 &ipv4Prefix,
					IPv4Gateway:                &ipv4Gateway,
					IPv4BlockID:                &ipv4Block.ID,
					IPv6Prefix:                 &ipv6Prefix,
					IPv6Gateway:                &ipv6Gateway,
					IPv6BlockID:                &ipv6Block.ID,
					PrefixLength:               8,
					Status:                     SubnetStatusPending,
					CreatedBy:                  user.ID,
				},
			)
			assert.Nil(t, err)
		}
	}

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		filter             SubnetFilterInput
		page               paginator.PageInput
		desc               string
		firstEntry         *Subnet
		expectedCount      int
		expectedTotal      *int
		expectedError      bool
		paramRelations     []string
		verifyChildSpanner bool
	}{
		{
			desc:               "GetAll with no filters returns objects",
			filter:             SubnetFilterInput{},
			page:               paginator.PageInput{},
			expectedCount:      paginator.DefaultLimit,
			expectedTotal:      &totalCount,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:           "GetAll with relation filters returns objects",
			filter:         SubnetFilterInput{},
			page:           paginator.PageInput{},
			expectedCount:  paginator.DefaultLimit,
			expectedTotal:  &totalCount,
			expectedError:  false,
			paramRelations: []string{VpcRelationName, TenantRelationName, IPv4BlockRelationName},
		},
		{
			desc:          "GetAll returns no objects",
			filter:        SubnetFilterInput{TenantIDs: []uuid.UUID{tenant3.ID}},
			page:          paginator.PageInput{},
			expectedCount: 0,
			expectedError: false,
		},
		{
			desc:          "GetAll with Site filter returns objects",
			filter:        SubnetFilterInput{SiteIDs: []uuid.UUID{site.ID}},
			page:          paginator.PageInput{},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with Vpc filter returns objects",
			filter:        SubnetFilterInput{VpcIDs: []uuid.UUID{vpc1.ID}},
			page:          paginator.PageInput{},
			expectedCount: totalCount / 2,
			expectedError: false,
		},
		{
			desc:          "GetAll with ipv4BlockID filter returns objects",
			filter:        SubnetFilterInput{TenantIDs: []uuid.UUID{tenant1.ID}, IPv4BlockIDs: []uuid.UUID{ipv4Block.ID}},
			page:          paginator.PageInput{},
			expectedCount: totalCount / 2,
			expectedError: false,
		},
		{
			desc:          "GetAll with ipv6BlockID filter returns objects",
			filter:        SubnetFilterInput{TenantIDs: []uuid.UUID{tenant1.ID}, IPv6BlockIDs: []uuid.UUID{ipv6Block.ID}},
			page:          paginator.PageInput{},
			expectedCount: totalCount / 2,
			expectedError: false,
		},
		{
			desc:          "GetAll with tenant filter returns objects",
			filter:        SubnetFilterInput{TenantIDs: []uuid.UUID{tenant2.ID}},
			page:          paginator.PageInput{},
			expectedCount: totalCount / 2,
			expectedError: false,
		},
		{
			desc:          "GetAll with tenant and name filters returns objects",
			filter:        SubnetFilterInput{Names: []string{"subnet-1"}, TenantIDs: []uuid.UUID{tenant2.ID}},
			page:          paginator.PageInput{},
			expectedCount: 1,
			expectedError: false,
		},
		{
			desc:          "GetAll with Domain filter returns objects",
			filter:        SubnetFilterInput{DomainIDs: []uuid.UUID{domain2.ID}},
			page:          paginator.PageInput{},
			expectedCount: totalCount / 2,
			expectedError: false,
		},
		{
			desc:          "GetAll with Vpc, Tenant, and Domain filters returns objects",
			filter:        SubnetFilterInput{DomainIDs: []uuid.UUID{domain1.ID}, TenantIDs: []uuid.UUID{tenant1.ID}, VpcIDs: []uuid.UUID{vpc1.ID}},
			page:          paginator.PageInput{},
			expectedCount: totalCount / 2,
			expectedError: false,
		},
		{
			desc:          "GetAll with limit returns objects",
			filter:        SubnetFilterInput{DomainIDs: []uuid.UUID{domain1.ID}, TenantIDs: []uuid.UUID{tenant1.ID}, VpcIDs: []uuid.UUID{vpc1.ID}},
			page:          paginator.PageInput{Offset: db.GetIntPtr(0), Limit: db.GetIntPtr(5)},
			expectedCount: 5,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
		{
			desc:          "GetAll with offset returns objects",
			filter:        SubnetFilterInput{DomainIDs: []uuid.UUID{domain1.ID}, TenantIDs: []uuid.UUID{tenant1.ID}, VpcIDs: []uuid.UUID{vpc1.ID}},
			page:          paginator.PageInput{Offset: db.GetIntPtr(5)},
			expectedCount: 10,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
		{
			desc:   "GetAll with order by returns objects",
			filter: SubnetFilterInput{DomainIDs: []uuid.UUID{domain1.ID}, TenantIDs: []uuid.UUID{tenant1.ID}, VpcIDs: []uuid.UUID{vpc1.ID}},
			page: paginator.PageInput{OrderBy: &paginator.OrderBy{
				Field: "name",
				Order: paginator.OrderDescending,
			}},
			firstEntry:    &ssTenant1[4], // 5th entry is "subnet-8" and would appear first on descending order
			expectedCount: totalCount / 2,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
		{
			desc:          "GetAll with name search query returns objects",
			filter:        SubnetFilterInput{SearchQuery: db.GetStrPtr("subnet-")},
			page:          paginator.PageInput{},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with description search query returns objects",
			filter:        SubnetFilterInput{SearchQuery: db.GetStrPtr("Test Description")},
			page:          paginator.PageInput{},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with status search query returns objects",
			filter:        SubnetFilterInput{SearchQuery: db.GetStrPtr(SubnetStatusPending)},
			page:          paginator.PageInput{},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with empty search query returns objects",
			filter:        SubnetFilterInput{SearchQuery: db.GetStrPtr("")},
			page:          paginator.PageInput{},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
		{
			desc:          "GetAll with status returns objects",
			filter:        SubnetFilterInput{Statuses: []string{SubnetStatusPending}},
			page:          paginator.PageInput{},
			expectedCount: paginator.DefaultLimit,
			expectedTotal: &totalCount,
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, total, err := ssd.GetAll(ctx, nil, tc.filter, tc.page, tc.paramRelations)
			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				assert.Equal(t, nil, got)
			} else {
				assert.Equal(t, tc.expectedCount, len(got))
				if len(tc.paramRelations) > 0 {
					assert.NotNil(t, got[0].Vpc)
					assert.NotNil(t, got[0].Tenant)
					assert.NotNil(t, got[0].IPv4Block)
				}
				if tc.expectedCount > 0 {
					assert.Equal(t, IPBlockRoutingTypeDatacenterOnly, *got[0].RoutingType)
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

func TestSubnetSQLDAO_Update(t *testing.T) {
	ctx := context.Background()
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)
	ip := testSubnetBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testSubnetBuildSite(t, dbSession, ip, "testSite")
	tenant := testSubnetBuildTenant(t, dbSession, "testTenant")
	tenant2 := testSubnetBuildTenant(t, dbSession, "testTenant2")
	vpc := testSubnetBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	vpc2 := testSubnetBuildVpc(t, dbSession, ip, site, tenant2, "testVpc2")
	domain := testSubnetBuildDomain(t, dbSession, "testDomain")
	domain2 := testSubnetBuildDomain(t, dbSession, "testDomain2")
	user := testSubnetBuildUser(t, dbSession, "testUser")
	ipv4Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block", &user.ID)
	ipv4Block2 := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block2", &user.ID)
	ipv6Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv6Block", &user.ID)
	ipv6Block2 := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv6Block2", &user.ID)
	ssd := NewSubnetDAO(dbSession)
	dummyUUID := uuid.New()
	dummyUUID2 := uuid.New()
	ipv4Prefix := "192.0.2.0/24"
	ipv4Gateway := "192.0.2.1"
	ipv6Prefix := "2001:db8:abcd:0012::0/24"
	ipv6Gateway := "2001:db8:abcd:0012::1"
	newMTU := 1400
	subnet1, err := ssd.Create(
		ctx, nil, SubnetCreateInput{
			Name:                       "test1",
			Description:                db.GetStrPtr("test"),
			Org:                        "test",
			SiteID:                     site.ID,
			VpcID:                      vpc.ID,
			DomainID:                   &domain.ID,
			TenantID:                   tenant.ID,
			ControllerNetworkSegmentID: &dummyUUID,
			RoutingType:                &ipv4Block.RoutingType,
			IPv4Prefix:                 &ipv4Prefix,
			IPv4Gateway:                &ipv4Gateway,
			IPv4BlockID:                &ipv4Block.ID,
			IPv6Prefix:                 &ipv6Prefix,
			IPv6Gateway:                &ipv6Gateway,
			IPv6BlockID:                &ipv6Block.ID,
			PrefixLength:               8,
			Status:                     SubnetStatusPending,
			CreatedBy:                  user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, subnet1)
	newPrefixLength := 16

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc                               string
		input                              SubnetUpdateInput
		expectedName                       *string
		expectedDescription                *string
		expectedOrg                        *string
		expectedSiteID                     *uuid.UUID
		expectedVpcID                      *uuid.UUID
		expectedDomainID                   *uuid.UUID
		expectedTenantID                   *uuid.UUID
		expectedControllerNetworkSegmentID *uuid.UUID
		expectedIpv4Prefix                 *string
		expectedIpv4Gateway                *string
		expectedIpv4BlockID                *uuid.UUID
		expectedIpv6Prefix                 *string
		expectedIpv6Gateway                *string
		expectedIPv6BlockID                *uuid.UUID
		expectedPrefixLength               *int
		expectedStatus                     *string
		expectedIsMissingOnSite            *bool
		expectedError                      bool
		expectedMTU                        *int
		verifyChildSpanner                 bool
	}{
		{
			desc: "can update all fields",
			input: SubnetUpdateInput{
				SubnetId:                   subnet1.ID,
				Name:                       db.GetStrPtr("updatedName"),
				Description:                db.GetStrPtr("updatedDescription"),
				Org:                        db.GetStrPtr("updatedOrg"),
				SiteID:                     &site.ID,
				VpcID:                      &vpc2.ID,
				DomainID:                   &domain2.ID,
				TenantID:                   &tenant2.ID,
				ControllerNetworkSegmentID: &dummyUUID2,
				IPv4Prefix:                 db.GetStrPtr("172.0.0.1/24"),
				IPv4Gateway:                db.GetStrPtr("172.0.0.1"),
				IPv4BlockID:                &ipv4Block2.ID,
				IPv6Prefix:                 db.GetStrPtr("2001:db8:abcd:1212::0/24"),
				IPv6Gateway:                db.GetStrPtr("2001:db8:abcd:1212::1"),
				IPv6BlockID:                &ipv6Block2.ID,
				PrefixLength:               &newPrefixLength,
				Status:                     db.GetStrPtr(SubnetStatusReady),
				IsMissingOnSite:            db.GetBoolPtr(true),
				Mtu:                        &newMTU,
			},
			expectedError:                      false,
			expectedName:                       db.GetStrPtr("updatedName"),
			expectedDescription:                db.GetStrPtr("updatedDescription"),
			expectedOrg:                        db.GetStrPtr("updatedOrg"),
			expectedSiteID:                     &site.ID,
			expectedVpcID:                      &vpc2.ID,
			expectedDomainID:                   &domain2.ID,
			expectedTenantID:                   &tenant2.ID,
			expectedControllerNetworkSegmentID: &dummyUUID2,
			expectedIpv4Prefix:                 db.GetStrPtr("172.0.0.1/24"),
			expectedIpv4Gateway:                db.GetStrPtr("172.0.0.1"),
			expectedIpv4BlockID:                &ipv4Block2.ID,
			expectedIpv6Prefix:                 db.GetStrPtr("2001:db8:abcd:1212::0/24"),
			expectedIpv6Gateway:                db.GetStrPtr("2001:db8:abcd:1212::1"),
			expectedIPv6BlockID:                &ipv6Block2.ID,
			expectedPrefixLength:               &newPrefixLength,
			expectedStatus:                     db.GetStrPtr(SubnetStatusReady),
			expectedIsMissingOnSite:            db.GetBoolPtr(true),
			expectedMTU:                        &newMTU,
			verifyChildSpanner:                 true,
		},
		{
			desc: "can update some fields",
			input: SubnetUpdateInput{
				SubnetId:                   subnet1.ID,
				Name:                       nil,
				Description:                db.GetStrPtr("otherDescription"),
				Org:                        nil,
				VpcID:                      &vpc.ID,
				DomainID:                   &domain.ID,
				TenantID:                   &tenant.ID,
				ControllerNetworkSegmentID: &dummyUUID,
				IPv4Prefix:                 db.GetStrPtr("172.0.0.1/24"),
				IPv4Gateway:                db.GetStrPtr("172.0.0.1"),
				IPv4BlockID:                &ipv4Block.ID,
				IPv6Prefix:                 db.GetStrPtr("2001:db8:abcd:0012::0/24"),
				IPv6Gateway:                db.GetStrPtr("2001:db8:abcd:1212::1"),
				IPv6BlockID:                &ipv6Block.ID,
				PrefixLength:               nil,
				Status:                     db.GetStrPtr(SubnetStatusReady),
				IsMissingOnSite:            nil,
			},

			expectedError:                      false,
			expectedName:                       db.GetStrPtr("updatedName"),
			expectedDescription:                db.GetStrPtr("otherDescription"),
			expectedOrg:                        db.GetStrPtr("updatedOrg"),
			expectedSiteID:                     &site.ID,
			expectedVpcID:                      &vpc.ID,
			expectedDomainID:                   &domain.ID,
			expectedTenantID:                   &tenant.ID,
			expectedControllerNetworkSegmentID: &dummyUUID,
			expectedIpv4Prefix:                 db.GetStrPtr("172.0.0.1/24"),
			expectedIpv4Gateway:                db.GetStrPtr("172.0.0.1"),
			expectedIpv4BlockID:                &ipv4Block.ID,
			expectedIpv6Prefix:                 db.GetStrPtr("2001:db8:abcd:0012::0/24"),
			expectedIpv6Gateway:                db.GetStrPtr("2001:db8:abcd:1212::1"),
			expectedIPv6BlockID:                &ipv6Block.ID,
			expectedPrefixLength:               &newPrefixLength,
			expectedStatus:                     db.GetStrPtr(SubnetStatusReady),
			expectedIsMissingOnSite:            db.GetBoolPtr(true),
		},
		{
			desc: "error updating when Site foreign key violated",
			input: SubnetUpdateInput{
				SubnetId:                   subnet1.ID,
				Name:                       db.GetStrPtr("updatedName"),
				Description:                db.GetStrPtr("updatedDescription"),
				SiteID:                     &dummyUUID,
				VpcID:                      nil,
				DomainID:                   &domain2.ID,
				TenantID:                   &tenant2.ID,
				ControllerNetworkSegmentID: &dummyUUID2,
				IPv4Prefix:                 db.GetStrPtr("172.0.0.1/24"),
				IPv4BlockID:                &ipv4Block2.ID,
				IPv6Prefix:                 db.GetStrPtr("2001:db8:abcd:1212::0/24"),
				IPv6BlockID:                &ipv6Block2.ID,
				Status:                     db.GetStrPtr(SubnetStatusReady),
				IsMissingOnSite:            db.GetBoolPtr(true),
			},
			expectedError: true,
		},
		{
			desc: "error updating when VPC foreign key violated",
			input: SubnetUpdateInput{
				SubnetId:                   subnet1.ID,
				Name:                       db.GetStrPtr("updatedName"),
				Description:                db.GetStrPtr("updatedDescription"),
				VpcID:                      &dummyUUID,
				DomainID:                   &domain2.ID,
				TenantID:                   &tenant2.ID,
				ControllerNetworkSegmentID: &dummyUUID2,
				IPv4Prefix:                 db.GetStrPtr("172.0.0.1/24"),
				IPv4BlockID:                &ipv4Block2.ID,
				IPv6Prefix:                 db.GetStrPtr("2001:db8:abcd:1212::0/24"),
				IPv6BlockID:                &ipv6Block2.ID,
				Status:                     db.GetStrPtr(SubnetStatusReady),
				IsMissingOnSite:            db.GetBoolPtr(true),
			},
			expectedError: true,
		},
		{
			desc: "update MTU to 2000",
			input: SubnetUpdateInput{
				SubnetId:                   subnet1.ID,
				Name:                       db.GetStrPtr("test1"),
				Description:                db.GetStrPtr("test"),
				Org:                        db.GetStrPtr("test"),
				SiteID:                     &site.ID,
				VpcID:                      &vpc.ID,
				DomainID:                   &domain.ID,
				TenantID:                   &tenant.ID,
				ControllerNetworkSegmentID: &dummyUUID,
				IPv4Prefix:                 &ipv4Prefix,
				IPv4Gateway:                &ipv4Gateway,
				IPv4BlockID:                &ipv4Block.ID,
				IPv6Prefix:                 &ipv6Prefix,
				IPv6Gateway:                &ipv6Gateway,
				IPv6BlockID:                &ipv6Block.ID,
				PrefixLength:               &newPrefixLength,
				Status:                     db.GetStrPtr(SubnetStatusPending),
				IsMissingOnSite:            db.GetBoolPtr(false),
				Mtu:                        db.GetIntPtr(2000), // Explicitly setting MTU to 2000
			},

			// Expected fields to verify after the update
			expectedName:                       db.GetStrPtr("test1"),
			expectedDescription:                db.GetStrPtr("test"),
			expectedOrg:                        db.GetStrPtr("test"),
			expectedSiteID:                     &site.ID,
			expectedVpcID:                      &vpc.ID,
			expectedDomainID:                   &domain.ID,
			expectedTenantID:                   &tenant.ID,
			expectedControllerNetworkSegmentID: &dummyUUID,
			expectedIpv4Prefix:                 &ipv4Prefix,
			expectedIpv4Gateway:                &ipv4Gateway,
			expectedIpv4BlockID:                &ipv4Block.ID,
			expectedIpv6Prefix:                 &ipv6Prefix,
			expectedIpv6Gateway:                &ipv6Gateway,
			expectedIPv6BlockID:                &ipv6Block.ID,
			expectedPrefixLength:               &newPrefixLength,
			expectedStatus:                     db.GetStrPtr(SubnetStatusPending),
			expectedIsMissingOnSite:            db.GetBoolPtr(false),
			expectedMTU:                        db.GetIntPtr(2000), // Verifying the MTU is updated to 2000
			expectedError:                      false,              // Expecting the operation to succeed without errors
			verifyChildSpanner:                 true,               // Assuming spanner verification is part of your testing strategy
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			fmt.Println("domainID=", *tc.input.DomainID)
			got, err := ssd.Update(
				ctx, nil, SubnetUpdateInput{
					SubnetId:                   tc.input.SubnetId,
					Name:                       tc.input.Name,
					Description:                tc.input.Description,
					Org:                        tc.input.Org,
					SiteID:                     tc.input.SiteID,
					VpcID:                      tc.input.VpcID,
					DomainID:                   tc.input.DomainID,
					TenantID:                   tc.input.TenantID,
					ControllerNetworkSegmentID: tc.input.ControllerNetworkSegmentID,
					IPv4Prefix:                 tc.input.IPv4Prefix,
					IPv4Gateway:                tc.input.IPv4Gateway,
					IPv4BlockID:                tc.input.IPv4BlockID,
					IPv6Prefix:                 tc.input.IPv6Prefix,
					IPv6Gateway:                tc.input.IPv6Gateway,
					IPv6BlockID:                tc.input.IPv6BlockID,
					PrefixLength:               tc.input.PrefixLength,
					Mtu:                        tc.input.Mtu,
					Status:                     tc.input.Status,
					IsMissingOnSite:            tc.input.IsMissingOnSite,
				},
			)
			assert.Equal(t, tc.expectedError, err != nil)
			if err == nil {
				assert.NotNil(t, got)
				assert.Equal(t, *tc.expectedName, got.Name)
				assert.Equal(t, tc.expectedDescription == nil, got.Description == nil)
				if tc.expectedDescription != nil {
					assert.Equal(t, *tc.expectedDescription, *got.Description)
				}
				assert.Equal(t, *tc.expectedOrg, got.Org)
				assert.Equal(t, *tc.expectedSiteID, got.SiteID)
				assert.Equal(t, *tc.expectedVpcID, got.VpcID)
				assert.Equal(t, tc.expectedDomainID == nil, got.DomainID == nil)
				if tc.expectedDomainID != nil {
					assert.Equal(t, *tc.expectedDomainID, *got.DomainID)
				}
				assert.Equal(t, *tc.expectedTenantID, got.TenantID)
				assert.Equal(t, tc.expectedControllerNetworkSegmentID == nil, got.ControllerNetworkSegmentID == nil)
				if tc.expectedControllerNetworkSegmentID != nil {
					assert.Equal(t, *tc.expectedControllerNetworkSegmentID, *got.ControllerNetworkSegmentID)
				}
				assert.Equal(t, tc.expectedIpv4Prefix == nil, got.IPv4Prefix == nil)
				if tc.expectedIpv4Prefix != nil {
					assert.Equal(t, *tc.expectedIpv4Prefix, *got.IPv4Prefix)
				}
				assert.Equal(t, tc.expectedIpv4Gateway == nil, got.IPv4Gateway == nil)
				if tc.expectedIpv4Gateway != nil {
					assert.Equal(t, *tc.expectedIpv4Gateway, *got.IPv4Gateway)
				}
				assert.Equal(t, tc.expectedIpv4BlockID == nil, got.IPv4BlockID == nil)
				if tc.expectedIpv4BlockID != nil {
					assert.Equal(t, *tc.expectedIpv4BlockID, *got.IPv4BlockID)
				}
				assert.Equal(t, tc.expectedIpv6Prefix == nil, got.IPv6Prefix == nil)
				if tc.expectedIpv6Prefix != nil {
					assert.Equal(t, *tc.expectedIpv6Prefix, *got.IPv6Prefix)
				}
				assert.Equal(t, tc.expectedIpv6Gateway == nil, got.IPv6Gateway == nil)
				if tc.expectedIpv6Gateway != nil {
					assert.Equal(t, *tc.expectedIpv6Gateway, *got.IPv6Gateway)
				}
				assert.Equal(t, tc.expectedIPv6BlockID == nil, got.IPv6BlockID == nil)
				if tc.expectedIPv6BlockID != nil {
					assert.Equal(t, *tc.expectedIPv6BlockID, *got.IPv6BlockID)
				}
				assert.Equal(t, *tc.expectedPrefixLength, got.PrefixLength)
				assert.Equal(t, *tc.expectedStatus, got.Status)
				assert.Equal(t, *tc.expectedIsMissingOnSite, got.IsMissingOnSite)
				if tc.expectedMTU != nil {
					if got.MTU == nil {
						t.Error("Expected MTU to be non-nil")
					} else if *got.MTU != *tc.expectedMTU {
						t.Errorf("Expected MTU %d, got %d", *tc.expectedMTU, *got.MTU)
					}
				}

				if got.Updated.String() == subnet1.Updated.String() {
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

func TestSubnetSQLDAO_Clear(t *testing.T) {
	ctx := context.Background()
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)
	ip := testSubnetBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testSubnetBuildSite(t, dbSession, ip, "testSite")
	tenant := testSubnetBuildTenant(t, dbSession, "testTenant")
	vpc := testSubnetBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	domain := testSubnetBuildDomain(t, dbSession, "testDomain")
	user := testSubnetBuildUser(t, dbSession, "testUser")
	ipv4Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block", &user.ID)
	ipv6Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv6Block", &user.ID)
	ssd := NewSubnetDAO(dbSession)
	dummyUUID := uuid.New()
	ipv4Prefix := "192.0.2.0/24"
	ipv4Gateway := "192.0.2.1"
	ipv6Prefix := "2001:db8:abcd:0012::0/24"
	ipv6Gateway := "2001:db8:abcd:0012::1"
	initialMTU := 1500
	subnet1, err := ssd.Create(
		ctx, nil, SubnetCreateInput{
			Name:                       "test1",
			Description:                db.GetStrPtr("test"),
			Org:                        "test",
			SiteID:                     site.ID,
			VpcID:                      vpc.ID,
			DomainID:                   &domain.ID,
			TenantID:                   tenant.ID,
			ControllerNetworkSegmentID: &dummyUUID,
			RoutingType:                &ipv4Block.RoutingType,
			IPv4Prefix:                 &ipv4Prefix,
			IPv4Gateway:                &ipv4Gateway,
			IPv4BlockID:                &ipv4Block.ID,
			IPv6Prefix:                 &ipv6Prefix,
			IPv6Gateway:                &ipv6Gateway,
			IPv6BlockID:                &ipv6Block.ID,
			PrefixLength:               8,
			Mtu:                        &initialMTU,
			Status:                     SubnetStatusPending,
			CreatedBy:                  user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, subnet1)
	subnet2, err := ssd.Create(
		ctx, nil, SubnetCreateInput{
			Name:                       "test1",
			Description:                db.GetStrPtr("test"),
			Org:                        "test",
			SiteID:                     site.ID,
			VpcID:                      vpc.ID,
			DomainID:                   &domain.ID,
			TenantID:                   tenant.ID,
			ControllerNetworkSegmentID: &dummyUUID,
			RoutingType:                &ipv4Block.RoutingType,
			IPv4Prefix:                 &ipv4Prefix,
			IPv4Gateway:                &ipv4Gateway,
			IPv4BlockID:                &ipv4Block.ID,
			IPv6Prefix:                 &ipv6Prefix,
			IPv6Gateway:                &ipv6Gateway,
			IPv6BlockID:                &ipv6Block.ID,
			PrefixLength:               8,
			Mtu:                        &initialMTU,
			Status:                     SubnetStatusPending,
			CreatedBy:                  user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, subnet2)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc   string
		subnet *Subnet
		input  SubnetClearInput

		expectedError                      bool
		expectedDescription                *string
		expectedDomainID                   *uuid.UUID
		expectedControllerNetworkSegmentID *uuid.UUID
		expectedIpv4Prefix                 *string
		expectedIpv4Gateway                *string
		expectedIpv4BlockID                *uuid.UUID
		expectedIpv6Prefix                 *string
		expectedIpv6Gateway                *string
		expectedIPv6BlockID                *uuid.UUID
		expectedUpdate                     bool
		expectedMTU                        *int
		verifyChildSpanner                 bool
	}{
		{
			desc:   "can clear string fields",
			subnet: subnet1,
			input: SubnetClearInput{
				Description:                true,
				DomainID:                   false,
				ControllerNetworkSegmentID: false,
				IPv4Prefix:                 true,
				IPv4Gateway:                true,
				IPv4BlockID:                false,
				IPv6Prefix:                 true,
				IPv6Gateway:                true,
				IPv6BlockID:                false,
			},

			expectedError:                      false,
			expectedDescription:                nil,
			expectedDomainID:                   subnet1.DomainID,
			expectedControllerNetworkSegmentID: subnet1.ControllerNetworkSegmentID,
			expectedIpv4Prefix:                 nil,
			expectedIpv4Gateway:                nil,
			expectedIpv4BlockID:                subnet1.IPv4BlockID,
			expectedIpv6Prefix:                 nil,
			expectedIpv6Gateway:                nil,
			expectedIPv6BlockID:                subnet1.IPv6BlockID,
			expectedUpdate:                     true,
			verifyChildSpanner:                 true,
			expectedMTU:                        &initialMTU,
		},
		{
			desc:   "can clear uuid fields",
			subnet: subnet1,
			input: SubnetClearInput{
				Description:                false,
				DomainID:                   true,
				ControllerNetworkSegmentID: true,
				IPv4Prefix:                 false,
				IPv4BlockID:                true,
				IPv6Prefix:                 false,
				IPv6BlockID:                true,
			},

			expectedError:                      false,
			expectedDescription:                nil,
			expectedDomainID:                   nil,
			expectedControllerNetworkSegmentID: nil,
			expectedIpv4Prefix:                 nil,
			expectedIpv4BlockID:                nil,
			expectedIpv6Prefix:                 nil,
			expectedIPv6BlockID:                nil,
			expectedUpdate:                     true,
			expectedMTU:                        &initialMTU,
		},
		{
			desc:   "can clear MTU field",
			subnet: subnet1,
			input: SubnetClearInput{
				Mtu: true,
			},

			expectedError: false,
			expectedMTU:   nil,
		},
		{
			desc:   "can clear all fields",
			subnet: subnet2,
			input: SubnetClearInput{
				Description:                true,
				DomainID:                   true,
				ControllerNetworkSegmentID: true,
				IPv4Prefix:                 true,
				IPv4Gateway:                true,
				IPv4BlockID:                true,
				IPv6Prefix:                 true,
				IPv6Gateway:                true,
				IPv6BlockID:                true,
				Mtu:                        true,
			},

			expectedError:                      false,
			expectedDescription:                nil,
			expectedDomainID:                   nil,
			expectedControllerNetworkSegmentID: nil,
			expectedIpv4Prefix:                 nil,
			expectedIpv4Gateway:                nil,
			expectedIpv4BlockID:                nil,
			expectedIpv6Prefix:                 nil,
			expectedIpv6Gateway:                nil,
			expectedIPv6BlockID:                nil,
			expectedUpdate:                     true,
			expectedMTU:                        nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := ssd.Clear(
				ctx, nil, SubnetClearInput{
					SubnetId:                   tc.subnet.ID,
					Description:                tc.input.Description,
					DomainID:                   tc.input.DomainID,
					ControllerNetworkSegmentID: tc.input.ControllerNetworkSegmentID,
					IPv4Prefix:                 tc.input.IPv4Prefix,
					IPv4Gateway:                tc.input.IPv4Gateway,
					IPv4BlockID:                tc.input.IPv4BlockID,
					IPv6Prefix:                 tc.input.IPv6Prefix,
					IPv6Gateway:                tc.input.IPv6Gateway,
					IPv6BlockID:                tc.input.IPv6BlockID,
					Mtu:                        tc.input.Mtu,
				},
			)
			assert.Equal(t, tc.expectedError, err != nil)
			assert.NotNil(t, got)
			assert.Equal(t, tc.expectedDescription == nil, got.Description == nil)
			if tc.expectedDescription != nil {
				assert.Equal(t, *tc.expectedDescription, *got.Description)
			}
			assert.Equal(t, tc.expectedDomainID == nil, got.DomainID == nil)
			if tc.expectedDomainID != nil {
				assert.Equal(t, *tc.expectedDomainID, *got.DomainID)
			}
			assert.Equal(t, tc.expectedControllerNetworkSegmentID == nil, got.ControllerNetworkSegmentID == nil)
			if tc.expectedControllerNetworkSegmentID != nil {
				assert.Equal(t, *tc.expectedControllerNetworkSegmentID, *got.ControllerNetworkSegmentID)
			}
			assert.Equal(t, tc.expectedIpv4Prefix == nil, got.IPv4Prefix == nil)
			if tc.expectedIpv4Prefix != nil {
				assert.Equal(t, *tc.expectedIpv4Prefix, *got.IPv4Prefix)
			}
			assert.Equal(t, tc.expectedIpv4Gateway == nil, got.IPv4Gateway == nil)
			if tc.expectedIpv4Gateway != nil {
				assert.Equal(t, *tc.expectedIpv4Gateway, *got.IPv4Gateway)
			}
			assert.Equal(t, tc.expectedIpv4BlockID == nil, got.IPv4BlockID == nil)
			if tc.expectedIpv4BlockID != nil {
				assert.Equal(t, *tc.expectedIpv4BlockID, *got.IPv4BlockID)
			}
			assert.Equal(t, tc.expectedIpv6Prefix == nil, got.IPv6Prefix == nil)
			if tc.expectedIpv6Prefix != nil {
				assert.Equal(t, *tc.expectedIpv6Prefix, *got.IPv6Prefix)
			}
			assert.Equal(t, tc.expectedIpv6Gateway == nil, got.IPv6Gateway == nil)
			if tc.expectedIpv6Gateway != nil {
				assert.Equal(t, *tc.expectedIpv6Gateway, *got.IPv6Gateway)
			}
			assert.Equal(t, tc.expectedIPv6BlockID == nil, got.IPv6BlockID == nil)
			if tc.expectedIPv6BlockID != nil {
				assert.Equal(t, *tc.expectedIPv6BlockID, *got.IPv6BlockID)
			}
			if tc.expectedMTU != nil {
				if got.MTU == nil {
					t.Error("Expected MTU to be non-nil")
				} else if *got.MTU != *tc.expectedMTU {
					t.Errorf("Expected MTU %d, got %d", *tc.expectedMTU, *got.MTU)
				}
			} else if got.MTU != nil {
				t.Error("Expected MTU to be nil")
			}

			if tc.expectedUpdate {
				assert.True(t, got.Updated.After(tc.subnet.Updated))
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

func TestSubnetSQLDAO_Delete(t *testing.T) {
	ctx := context.Background()
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)
	ip := testSubnetBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testSubnetBuildSite(t, dbSession, ip, "testSite")
	tenant := testSubnetBuildTenant(t, dbSession, "testTenant")
	vpc := testSubnetBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	domain := testSubnetBuildDomain(t, dbSession, "testDomain")
	user := testSubnetBuildUser(t, dbSession, "testUser")
	ipv4Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block", &user.ID)
	ipv6Block := testSubnetBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv6Block", &user.ID)
	ssd := NewSubnetDAO(dbSession)
	dummyUUID := uuid.New()
	ipv4Prefix := "192.0.2.0/24"
	ipv4Gateway := "192.0.2.1"
	ipv6Prefix := "2001:db8:abcd:0012::0/24"
	ipv6Gateway := "2001:db8:abcd:0012::1"
	subnet, err := ssd.Create(
		ctx, nil, SubnetCreateInput{
			Name:                       "test",
			Description:                db.GetStrPtr("test"),
			Org:                        "test",
			SiteID:                     site.ID,
			VpcID:                      vpc.ID,
			DomainID:                   &domain.ID,
			TenantID:                   tenant.ID,
			ControllerNetworkSegmentID: &dummyUUID,
			RoutingType:                &ipv4Block.RoutingType,
			IPv4Prefix:                 &ipv4Prefix,
			IPv4Gateway:                &ipv4Gateway,
			IPv4BlockID:                &ipv4Block.ID,
			IPv6Prefix:                 &ipv6Prefix,
			IPv6Gateway:                &ipv6Gateway,
			IPv6BlockID:                &ipv6Block.ID,
			PrefixLength:               8,
			Status:                     SubnetStatusPending,
			CreatedBy:                  user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, subnet)

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
			ipbID:              subnet.ID,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:          "delete non-existing object",
			ipbID:         subnet.ID,
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := ssd.Delete(ctx, nil, tc.ipbID)
			assert.Equal(t, tc.expectedError, err != nil)
			if !tc.expectedError {
				tmp, err := ssd.GetByID(ctx, nil, tc.ipbID, nil)
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
