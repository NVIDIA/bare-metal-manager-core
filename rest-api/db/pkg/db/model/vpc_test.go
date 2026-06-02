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
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

func testVpcSetupSchema(t *testing.T, dbSession *db.Session) {
	// Create tables

	err := dbSession.DB.ResetModel(context.Background(), (*InfrastructureProvider)(nil))
	require.NoError(t, err)

	err = dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	require.NoError(t, err)

	err = dbSession.DB.ResetModel(context.Background(), (*Site)(nil))
	require.NoError(t, err)

	err = dbSession.DB.ResetModel(context.Background(), (*NVLinkLogicalPartition)(nil))
	require.NoError(t, err)

	// create NetworkSecurityGroup table
	err = dbSession.DB.ResetModel(context.Background(), (*NetworkSecurityGroup)(nil))
	assert.Nil(t, err)

	err = dbSession.DB.ResetModel(context.Background(), (*Vpc)(nil))
	require.NoError(t, err)
}

func TestVpcSQLDAO_GetByID(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx context.Context
		id  uuid.UUID
	}

	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testVpcSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "Test Provider", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	networkSecurityGroup := testInstanceBuildNetworkSecurityGroup(t, dbSession, tn, st, "testNetworkSecurityGroup")

	vpc := testBuildVpc(t, dbSession, nil, "test-vpc", nil, tn.Org, ip.ID, tn.ID, st.ID, nil, db.GetStrPtr(VpcEthernetVirtualizer), db.GetUUIDPtr(uuid.New()), nil, db.GetStrPtr(VpcStatusReady), tnu.ID, &networkSecurityGroup.ID)

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		want               *Vpc
		wantErr            error
		paramRelations     []string
		verifyChildSpanner bool
	}{
		{
			name: "get VPC by ID returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: ctx,
				id:  vpc.ID,
			},
			want:               vpc,
			wantErr:            nil,
			paramRelations:     []string{TenantRelationName, SiteRelationName, NetworkSecurityGroupRelationName},
			verifyChildSpanner: true,
		},
		{
			name: "get VPC by non-existent ID returns error",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
				id:  uuid.New(),
			},
			want:    nil,
			wantErr: db.ErrDoesNotExist,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vsd := VpcSQLDAO{
				dbSession: tt.fields.dbSession,
			}

			got, err := vsd.GetByID(tt.args.ctx, nil, tt.args.id, tt.paramRelations)
			if tt.wantErr != nil {
				assert.ErrorAs(t, err, &tt.wantErr)
				return
			}
			if err == nil {
				if len(tt.paramRelations) > 0 {
					assert.NotNil(t, got.Site)
					assert.NotNil(t, got.Tenant)
				}
				assert.EqualValues(t, tt.want.ID, got.ID)
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

func TestVpcSQLDAO_GetCountByStatus(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx context.Context
	}

	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testVpcSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "Test Provider", ipu.ID)

	tnu1 := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe1@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tnu2 := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe2@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))

	tn1 := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu1.ID)
	assert.NotNil(t, tn1)

	tn2 := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu2.ID)
	assert.NotNil(t, tn2)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)
	assert.NotNil(t, st)

	vpc := testBuildVpc(t, dbSession, nil, "test-vpc", nil, tn1.Org, ip.ID, tn1.ID, st.ID, nil, db.GetStrPtr(VpcEthernetVirtualizer), db.GetUUIDPtr(uuid.New()), nil, db.GetStrPtr(VpcStatusReady), tnu1.ID, nil)
	assert.NotNil(t, vpc)
	vpc2 := testBuildVpc(t, dbSession, nil, "test-vpc-1", nil, tn1.Org, ip.ID, tn1.ID, st.ID, nil, db.GetStrPtr(VpcEthernetVirtualizer), db.GetUUIDPtr(uuid.New()), nil, db.GetStrPtr(VpcStatusDeleting), tnu1.ID, nil)
	assert.NotNil(t, vpc2)
	vpc3 := testBuildVpc(t, dbSession, nil, "test-vpc-1", nil, tn1.Org, ip.ID, tn1.ID, st.ID, nil, db.GetStrPtr(VpcEthernetVirtualizer), db.GetUUIDPtr(uuid.New()), nil, db.GetStrPtr(VpcStatusReady), tnu1.ID, nil)
	assert.NotNil(t, vpc3)

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name                        string
		fields                      fields
		args                        args
		wantErr                     error
		wantEmpty                   bool
		wantCount                   int
		wantStatusMap               map[string]int
		reqInfrastructureProviderID *uuid.UUID
		reqTenant                   *uuid.UUID
		reqSite                     *uuid.UUID
		reqOrg                      *string
		paramRelations              []string
		verifyChildSpanner          bool
	}{
		{
			name: "get vpc status count by tenant with vpc returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: ctx,
			},
			wantErr:   nil,
			wantEmpty: false,
			wantCount: 3,
			wantStatusMap: map[string]int{
				VpcStatusError:        0,
				VpcStatusProvisioning: 0,
				VpcStatusPending:      0,
				VpcStatusDeleting:     1,
				VpcStatusReady:        2,
				"total":               3,
			},
			reqTenant:          db.GetUUIDPtr(tn1.ID),
			verifyChildSpanner: true,
		},
		{
			name: "get vpc status count by tenant with no vpc returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr:   nil,
			wantEmpty: true,
			reqTenant: db.GetUUIDPtr(tn2.ID),
		},
		{
			name: "get vpc status count with no filter vpc returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantCount: 3,
			wantStatusMap: map[string]int{
				VpcStatusError:        0,
				VpcStatusProvisioning: 0,
				VpcStatusPending:      0,
				VpcStatusDeleting:     1,
				VpcStatusReady:        2,
				"total":               3,
			},
			wantErr:   nil,
			wantEmpty: false,
		},
		{
			name: "get vpc status count by infrastructure provider with vpc returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr:   nil,
			wantEmpty: false,
			wantCount: 3,
			wantStatusMap: map[string]int{
				VpcStatusError:        0,
				VpcStatusProvisioning: 0,
				VpcStatusPending:      0,
				VpcStatusDeleting:     1,
				VpcStatusReady:        2,
				"total":               3,
			},
			reqInfrastructureProviderID: db.GetUUIDPtr(ip.ID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vsd := VpcSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			got, err := vsd.GetCountByStatus(tt.args.ctx, nil, tt.reqInfrastructureProviderID, tt.reqTenant, tt.reqSite)
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
					assert.EqualValues(t, got[VpcStatusDeleting], 1)
					assert.EqualValues(t, got[VpcStatusReady], 2)
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

func TestVpc_GetAll(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}

	type args struct {
		ctx                       context.Context
		name                      *string
		infrastructureProviderID  *uuid.UUID
		tenantID                  *uuid.UUID
		siteID                    *uuid.UUID
		NVLinkLogicalPartitionID  *uuid.UUID
		VpcIDs                    []uuid.UUID
		org                       *string
		networkVirtualizationType *string
		searchQuery               *string
		status                    *string
		offset                    *int
		limit                     *int
		orderBy                   *paginator.OrderBy
		paramRelations            []string
	}

	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testVpcSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))

	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "Test Provider", ipu.ID)

	tnu1 := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("janed@test.com"), db.GetStrPtr("Jane"), db.GetStrPtr("Doe"))
	tn1 := testBuildTenant(t, dbSession, nil, "test-tenant-1", "test-tenant-org-1", tnu1.ID)

	tnu2 := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jimd@test.com"), db.GetStrPtr("Jim"), db.GetStrPtr("Doe"))
	tn2 := testBuildTenant(t, dbSession, nil, "test-tenant-2", "test-tenant-org-2", tnu2.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	networkSecurityGroup := testInstanceBuildNetworkSecurityGroup(t, dbSession, tn1, st, "testNetworkSecurityGroup")

	nvlinkLogicalPartition := testBuildNVLinkLogicalPartition(t, dbSession, nil, "test-nvlinklogicalpartition", nil, tn1.Org, tn1.ID, st.ID, db.GetStrPtr(NVLinkLogicalPartitionStatusReady), tnu1.ID)

	totalCount := 30

	vpcs := []Vpc{}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	for i := 0; i < totalCount; i++ {
		var vpc *Vpc
		var tn *Tenant

		if i%2 == 0 {
			tn = tn1
		} else {
			tn = tn2
		}

		if i%2 == 0 {
			vpc = testBuildVpc(t, dbSession, nil, fmt.Sprintf("test-vpc-batch-v1-%v", i), db.GetStrPtr(fmt.Sprintf("test-vpc-desc-batch-1-%v", i)), tn.Org, ip.ID, tn.ID, st.ID, db.GetUUIDPtr(nvlinkLogicalPartition.ID), db.GetStrPtr(VpcEthernetVirtualizer), db.GetUUIDPtr(uuid.New()), map[string]string{fmt.Sprintf("test-vpc-batch-key1-%v", i): fmt.Sprintf("test-vpc-batch-value1-%v", i)}, db.GetStrPtr(VpcStatusReady), tn.CreatedBy, &networkSecurityGroup.ID)
		} else {
			vpc = testBuildVpc(t, dbSession, nil, fmt.Sprintf("test-vpc-batch-v2-%v", i), db.GetStrPtr(fmt.Sprintf("test-vpc-desc-batch-2-%v", i)), tn.Org, ip.ID, tn.ID, st.ID, nil, db.GetStrPtr(VpcFNN), db.GetUUIDPtr(uuid.New()), map[string]string{fmt.Sprintf("test-vpc-batch-key2-%v", i): fmt.Sprintf("test-vpc-batch-value2-%v", i)}, db.GetStrPtr(VpcStatusDeleting), tn.CreatedBy, &networkSecurityGroup.ID)
		}

		vpcs = append(vpcs, *vpc)
	}

	tests := []struct {
		name               string
		fields             fields
		args               args
		wantCount          int
		wantTotalCount     int
		wantFirstEntry     *Vpc
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "get all Vpcs with filter on ID - success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:    ctx,
				VpcIDs: []uuid.UUID{vpcs[1].ID, vpcs[2].ID},
			},
			wantCount:          2,
			wantTotalCount:     2,
			wantErr:            false,
			verifyChildSpanner: true,
		},

		{
			name: "get all Vpcs with no relation filter success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      ctx,
				tenantID: nil,
				siteID:   nil,
				org:      nil,
			},
			wantCount:          paginator.DefaultLimit,
			wantTotalCount:     totalCount,
			wantErr:            false,
			verifyChildSpanner: true,
		},
		{
			name: "get all Vpcs with relation returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:            context.Background(),
				tenantID:       nil,
				siteID:         nil,
				org:            nil,
				paramRelations: []string{TenantRelationName, SiteRelationName},
			},
			wantCount:      paginator.DefaultLimit,
			wantTotalCount: totalCount,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with Tenant ID filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      context.Background(),
				tenantID: &tn1.ID,
				siteID:   nil,
				org:      nil,
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with Tenant ID and name filters returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      context.Background(),
				name:     db.GetStrPtr("test-vpc-batch-v1-8"),
				tenantID: &tn1.ID,
				siteID:   nil,
				org:      nil,
			},
			wantCount:      1,
			wantTotalCount: 1,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with Site ID filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      context.Background(),
				tenantID: nil,
				siteID:   &st.ID,
				org:      nil,
			},
			wantCount:      paginator.DefaultLimit,
			wantTotalCount: totalCount,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with NVLink Logical Partition ID filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                      context.Background(),
				NVLinkLogicalPartitionID: &nvlinkLogicalPartition.ID,
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with Org filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      context.Background(),
				tenantID: nil,
				siteID:   nil,
				org:      &tn1.Org,
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with tenant and Org filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      context.Background(),
				tenantID: &tn1.ID,
				siteID:   nil,
				org:      &tn1.Org,
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with network virtulization type filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                       context.Background(),
				tenantID:                  nil,
				siteID:                    nil,
				org:                       nil,
				networkVirtualizationType: db.GetStrPtr(VpcFNN),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all with limit returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      context.Background(),
				tenantID: nil,
				siteID:   &st.ID,
				org:      nil,
				limit:    db.GetIntPtr(10),
			},
			wantCount:      10,
			wantTotalCount: totalCount,
			wantErr:        false,
		},
		{
			name: "get all with offset returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      context.Background(),
				tenantID: &tn1.ID,
				siteID:   nil,
				org:      nil,
				offset:   db.GetIntPtr(5),
			},
			wantCount:      10,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Sites ordered by name",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      context.Background(),
				tenantID: &tn1.ID,
				siteID:   nil,
				org:      nil,
				orderBy:  &paginator.OrderBy{Field: "name", Order: paginator.OrderDescending},
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantFirstEntry: &vpcs[8],
			wantErr:        false,
		},
		{
			name: "get all Vpcs with Org filter with site/tenant include relation returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:            context.Background(),
				tenantID:       nil,
				siteID:         nil,
				org:            &tn1.Org,
				paramRelations: []string{SiteRelationName, TenantRelationName},
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with infrastructure ID filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                      context.Background(),
				tenantID:                 nil,
				siteID:                   nil,
				infrastructureProviderID: &ip.ID,
				org:                      nil,
			},
			wantCount:      paginator.DefaultLimit,
			wantTotalCount: totalCount,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query as name returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-batch-v1-"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query as a description returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-desc-batch-1-"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query as label key returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-batch-key1-"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query as label value returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-batch-value1-"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query with exact key label string return success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-batch-key1-6"),
			},
			wantCount:      1,
			wantTotalCount: 1,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query with exact value label string return success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-batch-value2-7"),
			},
			wantCount:      1,
			wantTotalCount: 1,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query with exact key value label string return success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-batch-value2-7 test-vpc-batch-key1-6"),
			},
			wantCount:      2,
			wantTotalCount: 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query with no label exits return none success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-desc-batch-key12-"),
			},
			wantCount:      0,
			wantTotalCount: 0,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query as a status ready returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr(VpcStatusReady),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query as a status deleting returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr(VpcStatusDeleting),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query with combination of name and status returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-batch-v1- | ready"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query with combination of description and status returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-desc-batch-1- error"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query with network virtulization type returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr(VpcFNN),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with search query with combination of description and status returns none success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr("test-vpc-desc-batch-3- error"),
			},
			wantCount:      0,
			wantTotalCount: 0,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with empty search query returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantID:    nil,
				siteID:      nil,
				org:         nil,
				searchQuery: db.GetStrPtr(""),
			},
			wantCount:      20,
			wantTotalCount: 30,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with empty search query returns success with ip",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                      context.Background(),
				tenantID:                 nil,
				siteID:                   nil,
				infrastructureProviderID: &ip.ID,
				org:                      nil,
				searchQuery:              db.GetStrPtr(""),
			},
			wantCount:      20,
			wantTotalCount: 30,
			wantErr:        false,
		},
		{
			name: "get all Vpcs with status returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:      context.Background(),
				tenantID: nil,
				siteID:   nil,
				org:      nil,
				status:   db.GetStrPtr(VpcStatusDeleting),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vsd := VpcSQLDAO{
				dbSession: tt.fields.dbSession,
			}

			filterInput := VpcFilterInput{
				Name:                      tt.args.name,
				InfrastructureProviderID:  tt.args.infrastructureProviderID,
				Org:                       tt.args.org,
				NetworkVirtualizationType: tt.args.networkVirtualizationType,
				SearchQuery:               tt.args.searchQuery,
				VpcIDs:                    tt.args.VpcIDs,
			}

			if tt.args.tenantID != nil {
				filterInput.TenantIDs = []uuid.UUID{*tt.args.tenantID}
			}

			if tt.args.siteID != nil {
				filterInput.SiteIDs = []uuid.UUID{*tt.args.siteID}
			}
			if tt.args.NVLinkLogicalPartitionID != nil {
				filterInput.NVLinkLogicalPartitionIDs = []uuid.UUID{*tt.args.NVLinkLogicalPartitionID}
			}

			if tt.args.status != nil {
				filterInput.Statuses = []string{*tt.args.status}
			}

			pageInput := paginator.PageInput{
				Offset:  tt.args.offset,
				Limit:   tt.args.limit,
				OrderBy: tt.args.orderBy,
			}

			got, total, err := vsd.GetAll(tt.args.ctx, nil, filterInput, pageInput, tt.args.paramRelations)
			if tt.wantErr {
				require.Error(t, err)
			}

			assert.Equal(t, tt.wantCount, len(got))
			assert.Equal(t, tt.wantTotalCount, total)

			if len(got) > 0 && len(tt.args.paramRelations) > 0 {
				assert.NotNil(t, got[0].Site)
				assert.NotNil(t, got[0].Tenant)
			}

			if tt.wantFirstEntry != nil {
				assert.Equal(t, tt.wantFirstEntry.Name, got[0].Name)
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

func TestVpcSQLDAO_CreateFromParams(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx                                    context.Context
		name                                   string
		description                            *string
		org                                    string
		infrastructureProviderID               uuid.UUID
		tenantID                               uuid.UUID
		siteID                                 uuid.UUID
		networkVirtualizationType              *string
		routingProfile                         *string
		controllerVpcID                        *uuid.UUID
		activeVni                              *int
		networkSecurityGroupID                 *string
		networkSecurityGroupPropagationDetails *NetworkSecurityGroupPropagationDetails
		labels                                 map[string]string
		status                                 string
		createdBy                              User
		vni                                    *int
		id                                     *uuid.UUID
	}

	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testVpcSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "Test Provider", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	networkSecurityGroup := testInstanceBuildNetworkSecurityGroup(t, dbSession, tn, st, "testNetworkSecurityGroup")

	vpc := &Vpc{
		Name:                      "test-vpc",
		Description:               db.GetStrPtr("Test VPC"),
		Org:                       tn.Org,
		InfrastructureProviderID:  ip.ID,
		TenantID:                  tn.ID,
		SiteID:                    st.ID,
		NetworkVirtualizationType: db.GetStrPtr(VpcEthernetVirtualizer),
		RoutingProfile:            db.GetStrPtr("INTERNAL"),
		ControllerVpcID:           db.GetUUIDPtr(uuid.New()),
		ActiveVni:                 nil,
		Vni:                       db.GetIntPtr(555),
		NetworkSecurityGroupID:    &networkSecurityGroup.ID,
		NetworkSecurityGroupPropagationDetails: &NetworkSecurityGroupPropagationDetails{
			NetworkSecurityGroupPropagationObjectStatus: &cwssaws.NetworkSecurityGroupPropagationObjectStatus{
				Id:                      "",
				RelatedInstanceIds:      []string{},
				UnpropagatedInstanceIds: []string{},
				Status:                  cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_FULL,
			},
		},
		Labels: map[string]string{
			"zone1": "gpu",
			"zone2": "dpu",
		},
		Status:    VpcStatusPending,
		CreatedBy: tnu.ID,
		ID:        uuid.New(),
	}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		want               *Vpc
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "create VPC from params returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                                    ctx,
				name:                                   vpc.Name,
				description:                            vpc.Description,
				org:                                    vpc.Org,
				infrastructureProviderID:               vpc.InfrastructureProviderID,
				tenantID:                               vpc.TenantID,
				siteID:                                 vpc.SiteID,
				networkVirtualizationType:              vpc.NetworkVirtualizationType,
				routingProfile:                         vpc.RoutingProfile,
				controllerVpcID:                        vpc.ControllerVpcID,
				activeVni:                              vpc.ActiveVni,
				vni:                                    vpc.Vni,
				networkSecurityGroupID:                 vpc.NetworkSecurityGroupID,
				networkSecurityGroupPropagationDetails: vpc.NetworkSecurityGroupPropagationDetails,
				labels:                                 vpc.Labels,
				status:                                 vpc.Status,
				createdBy:                              User{ID: vpc.CreatedBy},
				id:                                     db.GetUUIDPtr(vpc.ID),
			},
			want:               vpc,
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vsd := VpcSQLDAO{
				dbSession: tt.fields.dbSession,
			}

			input := VpcCreateInput{
				ID:                                     tt.args.id,
				Name:                                   tt.args.name,
				Description:                            tt.args.description,
				Org:                                    tt.args.org,
				InfrastructureProviderID:               tt.args.infrastructureProviderID,
				TenantID:                               tt.args.tenantID,
				SiteID:                                 tt.args.siteID,
				NetworkVirtualizationType:              tt.args.networkVirtualizationType,
				RoutingProfile:                         tt.args.routingProfile,
				ControllerVpcID:                        tt.args.controllerVpcID,
				Vni:                                    tt.args.vni,
				NetworkSecurityGroupID:                 tt.args.networkSecurityGroupID,
				NetworkSecurityGroupPropagationDetails: tt.args.networkSecurityGroupPropagationDetails,
				Labels:                                 tt.args.labels,
				Status:                                 tt.args.status,
				CreatedBy:                              tt.args.createdBy,
			}

			got, err := vsd.Create(tt.args.ctx, nil, input)
			require.Equal(t, tt.wantErr, err != nil)

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, *tt.want.Description, *got.Description)
			assert.Equal(t, tt.want.Org, got.Org)
			assert.Equal(t, tt.want.InfrastructureProviderID, got.InfrastructureProviderID)
			assert.Equal(t, tt.want.TenantID, got.TenantID)
			assert.Equal(t, tt.want.SiteID, got.SiteID)
			assert.Equal(t, *tt.want.NetworkVirtualizationType, *got.NetworkVirtualizationType)
			assert.Equal(t, len(tt.want.Labels), len(got.Labels))
			assert.Equal(t, *tt.want.ControllerVpcID, *got.ControllerVpcID)
			assert.Equal(t, tt.want.RoutingProfile, got.RoutingProfile)
			if tt.want.Vni != nil {
				assert.NotNil(t, got.Vni)
				assert.Equal(t, *tt.want.Vni, *got.Vni)
			}
			assert.Equal(t, tt.want.ID, got.ID)
			assert.Equal(t, *tt.want.NetworkSecurityGroupID, *got.NetworkSecurityGroupID)
			assert.True(t, proto.Equal(tt.want.NetworkSecurityGroupPropagationDetails, got.NetworkSecurityGroupPropagationDetails))
			assert.Equal(t, tt.want.Status, got.Status)
			assert.Equal(t, tt.want.CreatedBy, got.CreatedBy)

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestVpcSQLDAO_UpdateFromParams(t *testing.T) {
	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testVpcSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "test-provider-org", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	networkSecurityGroup := testInstanceBuildNetworkSecurityGroup(t, dbSession, tn, st, "testNetworkSecurityGroup")
	networkSecurityGroup2 := testInstanceBuildNetworkSecurityGroup(t, dbSession, tn, st, "testNetworkSecurityGroup2")

	vpc := testBuildVpc(t, dbSession, nil, "test-vpc", nil, tn.Org, ip.ID, tn.ID, st.ID, nil, db.GetStrPtr(VpcEthernetVirtualizer), nil, nil, nil, tnu.ID, &networkSecurityGroup.ID)

	uvpc := &Vpc{
		Name:                      "test-updated",
		Description:               db.GetStrPtr("Test Updated"),
		NetworkVirtualizationType: db.GetStrPtr(VpcEthernetVirtualizerWithNVUE),
		RoutingProfile:            db.GetStrPtr("EXTERNAL"),
		NetworkSecurityGroupID:    &networkSecurityGroup2.ID,
		ControllerVpcID:           db.GetUUIDPtr(uuid.New()),
		ActiveVni:                 db.GetIntPtr(777),
		Vni:                       db.GetIntPtr(888),
		Status:                    VpcStatusReady,
		IsMissingOnSite:           true,
		Labels: map[string]string{
			"zone": "west1",
		},
		NetworkSecurityGroupPropagationDetails: &NetworkSecurityGroupPropagationDetails{
			NetworkSecurityGroupPropagationObjectStatus: &cwssaws.NetworkSecurityGroupPropagationObjectStatus{
				Id:                      "",
				RelatedInstanceIds:      []string{},
				UnpropagatedInstanceIds: []string{},
				Status:                  cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_FULL,
			},
		},
	}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx                                    context.Context
		id                                     uuid.UUID
		name                                   *string
		description                            *string
		networkVirtualizationType              *string
		routingProfile                         *string
		networkSecurityGroupID                 *string
		NetworkSecurityGroupPropagationDetails *NetworkSecurityGroupPropagationDetails
		ControllervpcID                        *uuid.UUID
		ActiveVni                              *int
		Vni                                    *int
		labels                                 map[string]string
		Status                                 string
		IsMissingOnSite                        bool
	}
	tests := []struct {
		name               string
		fields             fields
		args               args
		want               *Vpc
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "update Vpc from params returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                                    ctx,
				id:                                     vpc.ID,
				name:                                   &uvpc.Name,
				description:                            uvpc.Description,
				networkVirtualizationType:              uvpc.NetworkVirtualizationType,
				routingProfile:                         uvpc.RoutingProfile,
				networkSecurityGroupID:                 uvpc.NetworkSecurityGroupID,
				NetworkSecurityGroupPropagationDetails: uvpc.NetworkSecurityGroupPropagationDetails,
				ControllervpcID:                        uvpc.ControllerVpcID,
				ActiveVni:                              uvpc.ActiveVni,
				Vni:                                    uvpc.Vni,
				labels:                                 uvpc.Labels,
				Status:                                 uvpc.Status,
				IsMissingOnSite:                        uvpc.IsMissingOnSite,
			},
			want:               uvpc,
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vsd := VpcSQLDAO{
				dbSession: tt.fields.dbSession,
			}

			input := VpcUpdateInput{
				VpcID:                                  tt.args.id,
				Name:                                   tt.args.name,
				Description:                            tt.args.description,
				NetworkVirtualizationType:              tt.args.networkVirtualizationType,
				RoutingProfile:                         tt.args.routingProfile,
				NetworkSecurityGroupID:                 tt.args.networkSecurityGroupID,
				NetworkSecurityGroupPropagationDetails: tt.args.NetworkSecurityGroupPropagationDetails,
				ControllerVpcID:                        tt.args.ControllervpcID,
				ActiveVni:                              tt.args.ActiveVni,
				Vni:                                    tt.args.Vni,
				Labels:                                 tt.args.labels,
				Status:                                 &tt.args.Status,
				IsMissingOnSite:                        &tt.args.IsMissingOnSite,
			}

			got, err := vsd.Update(tt.args.ctx, nil, input)

			fmt.Printf("\ngot ID: %v, Created: %v, Updated: %v", got.ID.String(), got.Created, got.Updated)

			require.Equal(t, tt.wantErr, err != nil)

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, *tt.want.Description, *got.Description)
			assert.Equal(t, *tt.want.NetworkVirtualizationType, *got.NetworkVirtualizationType)
			assert.Equal(t, tt.want.RoutingProfile, got.RoutingProfile)
			assert.Equal(t, *tt.want.ControllerVpcID, *got.ControllerVpcID)
			assert.Equal(t, *tt.want.ActiveVni, *got.ActiveVni)
			assert.Equal(t, *tt.want.Vni, *got.Vni)

			if tt.want.NetworkSecurityGroupID != nil {
				assert.NotNil(t, got.NetworkSecurityGroupID)
				assert.Equal(t, *tt.want.NetworkSecurityGroupID, *got.NetworkSecurityGroupID)
			}

			if tt.args.NetworkSecurityGroupPropagationDetails != nil {
				assert.True(t, proto.Equal(tt.want.NetworkSecurityGroupPropagationDetails, got.NetworkSecurityGroupPropagationDetails))
			}
			assert.Equal(t, tt.want.Labels, got.Labels)
			assert.Equal(t, tt.want.Status, got.Status)

			assert.NotEqualValues(t, got.Updated, vpc.Updated)

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestVpcSQLDAO_DeleteByID(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx context.Context
		id  uuid.UUID
	}

	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testVpcSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "Test Provider", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	networkSecurityGroup := testInstanceBuildNetworkSecurityGroup(t, dbSession, tn, st, "testNetworkSecurityGroup")

	vpc := testBuildVpc(t, dbSession, nil, "test-vpc", nil, tn.Org, ip.ID, tn.ID, st.ID, nil, db.GetStrPtr(VpcEthernetVirtualizer), nil, nil, nil, tnu.ID, &networkSecurityGroup.ID)

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "delete Vpc by ID",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: ctx,
				id:  vpc.ID,
			},
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vsd := VpcSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			err := vsd.DeleteByID(tt.args.ctx, nil, tt.args.id)
			require.Equal(t, tt.wantErr, err != nil)

			dvpc := &Vpc{}
			err = dbSession.DB.NewSelect().Model(dvpc).WhereDeleted().Where("id = ?", vpc.ID).Scan(context.Background())
			require.NoError(t, err)
			assert.NotNil(t, dvpc.Deleted)

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestVpcSQLDAO_ClearFromParams(t *testing.T) {
	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testVpcSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "test-provider-org", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	networkSecurityGroup := testInstanceBuildNetworkSecurityGroup(t, dbSession, tn, st, "testNetworkSecurityGroup")

	vpc := testBuildVpc(t, dbSession, nil, "test-vpc", db.GetStrPtr("Test Description"), tn.Org, ip.ID, tn.ID, st.ID, nil, db.GetStrPtr(VpcEthernetVirtualizer), db.GetUUIDPtr(uuid.New()), nil, db.GetStrPtr(VpcStatusReady), tnu.ID, &networkSecurityGroup.ID)
	vpc.NetworkSecurityGroupPropagationDetails = &NetworkSecurityGroupPropagationDetails{
		NetworkSecurityGroupPropagationObjectStatus: &cwssaws.NetworkSecurityGroupPropagationObjectStatus{},
	}

	testUpdateVpc(t, dbSession, vpc)

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	type fields struct {
		dbSession  *db.Session
		tracerSpan *stracer.TracerSpan
	}
	type args struct {
		ctx                                    context.Context
		tx                                     *db.Tx
		id                                     uuid.UUID
		description                            bool
		controllerVpcID                        bool
		labels                                 bool
		networkSecuritygroupID                 bool
		networkSecurityGroupPropagationDetails bool
	}
	tests := []struct {
		name               string
		fields             fields
		args               args
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "clearing VPC attributes returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                                    ctx,
				id:                                     vpc.ID,
				description:                            true,
				controllerVpcID:                        true,
				labels:                                 true,
				networkSecuritygroupID:                 true,
				networkSecurityGroupPropagationDetails: true,
			},
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vsd := VpcSQLDAO{
				dbSession:  tt.fields.dbSession,
				tracerSpan: tt.fields.tracerSpan,
			}

			input := VpcClearInput{
				VpcID:                                  tt.args.id,
				Description:                            tt.args.description,
				ControllerVpcID:                        tt.args.controllerVpcID,
				Labels:                                 tt.args.labels,
				NetworkSecurityGroupPropagationDetails: tt.args.networkSecurityGroupPropagationDetails,
			}

			got, err := vsd.Clear(tt.args.ctx, tt.args.tx, input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.args.networkSecurityGroupPropagationDetails {
				assert.Nil(t, got.NetworkSecurityGroupPropagationDetails)
			}

			if tt.args.description {
				assert.Nil(t, got.Description)
			}

			if tt.args.controllerVpcID {
				assert.Nil(t, got.ControllerVpcID)
			}

			if tt.args.labels {
				assert.Nil(t, got.Labels)
			}

			if tt.args.networkSecuritygroupID {
				assert.Nil(t, got.NetworkSecurityGroup)
			}
		})
	}
}

func TestVpc_GetSiteID(t *testing.T) {
	id := uuid.New()
	ctrlID := uuid.New()

	t.Run("falls back to ID when ControllerVpcID is nil", func(t *testing.T) {
		v := &Vpc{ID: id}
		got := v.GetSiteID()
		require.NotNil(t, got)
		assert.Equal(t, id, *got)
	})

	t.Run("uses ControllerVpcID when set", func(t *testing.T) {
		v := &Vpc{ID: id, ControllerVpcID: &ctrlID}
		got := v.GetSiteID()
		require.NotNil(t, got)
		assert.Equal(t, ctrlID, *got)
	})
}

func TestVpc_ToDeletionRequestProto(t *testing.T) {
	id := uuid.New()
	v := &Vpc{ID: id}
	req := v.ToDeletionRequestProto()
	require.NotNil(t, req)
	require.NotNil(t, req.Id)
	assert.Equal(t, id.String(), req.Id.Value)
}

func TestVpc_ToProto(t *testing.T) {
	id := uuid.New()
	desc := "primary"
	nsg := "nsg-1"
	nvllpID := uuid.New()

	t.Run("populates id, org, metadata, NSG, and NVLink partition", func(t *testing.T) {
		v := &Vpc{
			ID:                       id,
			Org:                      "org-1",
			Name:                     "vpc-a",
			Description:              &desc,
			NetworkSecurityGroupID:   &nsg,
			NVLinkLogicalPartitionID: &nvllpID,
			Labels:                   map[string]string{"env": "prod"},
		}
		got := v.ToProto()
		require.NotNil(t, got)
		require.NotNil(t, got.Id)
		assert.Equal(t, id.String(), got.Id.Value)
		assert.Equal(t, "vpc-a", got.Name)
		assert.Equal(t, "org-1", got.TenantOrganizationId)
		require.NotNil(t, got.NetworkSecurityGroupId)
		assert.Equal(t, "nsg-1", *got.NetworkSecurityGroupId)
		require.NotNil(t, got.Metadata)
		assert.Equal(t, "vpc-a", got.Metadata.Name)
		assert.Equal(t, "primary", got.Metadata.Description)
		require.Len(t, got.Metadata.Labels, 1)
		assert.Equal(t, "env", got.Metadata.Labels[0].Key)
		require.NotNil(t, got.Metadata.Labels[0].Value)
		assert.Equal(t, "prod", *got.Metadata.Labels[0].Value)
		require.NotNil(t, got.DefaultNvlinkLogicalPartitionId)
		assert.Equal(t, nvllpID.String(), got.DefaultNvlinkLogicalPartitionId.Value)
	})

	t.Run("nil description and labels yield zero-value metadata", func(t *testing.T) {
		v := &Vpc{ID: id, Org: "org-1", Name: "vpc-a"}
		got := v.ToProto()
		require.NotNil(t, got.Metadata)
		assert.Equal(t, "", got.Metadata.Description)
		assert.Nil(t, got.Metadata.Labels)
		assert.Nil(t, got.NetworkSecurityGroupId)
		assert.Nil(t, got.DefaultNvlinkLogicalPartitionId)
	})

	t.Run("uses ControllerVpcID for the proto Id when set", func(t *testing.T) {
		ctrlID := uuid.New()
		v := &Vpc{ID: id, ControllerVpcID: &ctrlID, Name: "vpc-a"}
		got := v.ToProto()
		require.NotNil(t, got.Id)
		assert.Equal(t, ctrlID.String(), got.Id.Value)
	})

	t.Run("explicit NSG clear preserves empty string (distinct from nil)", func(t *testing.T) {
		empty := ""
		v := &Vpc{ID: id, Name: "vpc-a", NetworkSecurityGroupID: &empty}
		got := v.ToProto()
		require.NotNil(t, got.NetworkSecurityGroupId)
		assert.Equal(t, "", *got.NetworkSecurityGroupId)
	})

	t.Run("maps NetworkVirtualizationType FNN string to the FNN enum", func(t *testing.T) {
		fnn := VpcFNN
		v := &Vpc{ID: id, Name: "vpc-a", NetworkVirtualizationType: &fnn}
		got := v.ToProto()
		require.NotNil(t, got.NetworkVirtualizationType)
		assert.Equal(t, cwssaws.VpcVirtualizationType_FNN, *got.NetworkVirtualizationType)
	})

	t.Run("maps NetworkVirtualizationType ethernet string to ETHERNET_VIRTUALIZER", func(t *testing.T) {
		eth := VpcEthernetVirtualizer
		v := &Vpc{ID: id, Name: "vpc-a", NetworkVirtualizationType: &eth}
		got := v.ToProto()
		require.NotNil(t, got.NetworkVirtualizationType)
		assert.Equal(t, cwssaws.VpcVirtualizationType_ETHERNET_VIRTUALIZER, *got.NetworkVirtualizationType)
	})

	t.Run("omits NetworkVirtualizationType when the entity has none", func(t *testing.T) {
		v := &Vpc{ID: id, Name: "vpc-a"}
		got := v.ToProto()
		assert.Nil(t, got.NetworkVirtualizationType)
	})
}

func TestVpc_FromProto(t *testing.T) {
	id := uuid.New()
	nvllpID := uuid.New()
	nsg := "nsg-1"

	t.Run("nil proto leaves receiver unchanged", func(t *testing.T) {
		v := &Vpc{ID: id, Name: "preserved", Org: "org-1"}
		v.FromProto(nil)
		assert.Equal(t, id, v.ID)
		assert.Equal(t, "preserved", v.Name)
		assert.Equal(t, "org-1", v.Org)
	})

	t.Run("invalid id leaves vpc.ID unchanged", func(t *testing.T) {
		v := &Vpc{ID: id}
		v.FromProto(&cwssaws.Vpc{
			Id:   &cwssaws.VpcId{Value: "not-a-uuid"},
			Name: "vpc-a",
		})
		assert.Equal(t, id, v.ID)
		assert.Equal(t, "vpc-a", v.Name)
	})

	t.Run("populates fields from proto", func(t *testing.T) {
		v := &Vpc{}
		v.FromProto(&cwssaws.Vpc{
			Id:                              &cwssaws.VpcId{Value: id.String()},
			Name:                            "vpc-a",
			TenantOrganizationId:            "org-1",
			NetworkSecurityGroupId:          &nsg,
			DefaultNvlinkLogicalPartitionId: &cwssaws.NVLinkLogicalPartitionId{Value: nvllpID.String()},
			Metadata: &cwssaws.Metadata{
				Name:        "vpc-a",
				Description: "primary",
				Labels: []*cwssaws.Label{
					{Key: "env", Value: db.GetStrPtr("prod")},
				},
			},
		})
		assert.Equal(t, id, v.ID)
		assert.Equal(t, "vpc-a", v.Name)
		assert.Equal(t, "org-1", v.Org)
		require.NotNil(t, v.NetworkSecurityGroupID)
		assert.Equal(t, "nsg-1", *v.NetworkSecurityGroupID)
		require.NotNil(t, v.NVLinkLogicalPartitionID)
		assert.Equal(t, nvllpID, *v.NVLinkLogicalPartitionID)
		require.NotNil(t, v.Description)
		assert.Equal(t, "primary", *v.Description)
		assert.Equal(t, Labels{"env": "prod"}, v.Labels)
	})

	t.Run("missing optional fields are explicitly cleared", func(t *testing.T) {
		stale := "stale"
		staleNvllp := uuid.New()
		v := &Vpc{
			ID:                       id,
			Description:              &stale,
			NetworkSecurityGroupID:   &stale,
			NVLinkLogicalPartitionID: &staleNvllp,
			Labels:                   map[string]string{"old": "val"},
		}
		v.FromProto(&cwssaws.Vpc{
			Id:   &cwssaws.VpcId{Value: id.String()},
			Name: "vpc-a",
		})
		assert.Nil(t, v.NetworkSecurityGroupID)
		assert.Nil(t, v.NVLinkLogicalPartitionID)
		assert.Nil(t, v.Description)
		assert.Nil(t, v.Labels)
	})

	t.Run("invalid NVLink partition id clears the field", func(t *testing.T) {
		staleNvllp := uuid.New()
		v := &Vpc{ID: id, NVLinkLogicalPartitionID: &staleNvllp}
		v.FromProto(&cwssaws.Vpc{
			Id:                              &cwssaws.VpcId{Value: id.String()},
			Name:                            "vpc-a",
			DefaultNvlinkLogicalPartitionId: &cwssaws.NVLinkLogicalPartitionId{Value: "not-a-uuid"},
		})
		assert.Nil(t, v.NVLinkLogicalPartitionID)
	})

	t.Run("prefers Metadata.Name over the deprecated top-level Name field", func(t *testing.T) {
		v := &Vpc{}
		v.FromProto(&cwssaws.Vpc{
			Id:       &cwssaws.VpcId{Value: id.String()},
			Name:     "deprecated-top-level",
			Metadata: &cwssaws.Metadata{Name: "metadata-name"},
		})
		assert.Equal(t, "metadata-name", v.Name)
	})

	t.Run("falls back to top-level Name when Metadata.Name is empty", func(t *testing.T) {
		v := &Vpc{}
		v.FromProto(&cwssaws.Vpc{
			Id:       &cwssaws.VpcId{Value: id.String()},
			Name:     "top-level-fallback",
			Metadata: &cwssaws.Metadata{Name: ""},
		})
		assert.Equal(t, "top-level-fallback", v.Name)
	})
}
