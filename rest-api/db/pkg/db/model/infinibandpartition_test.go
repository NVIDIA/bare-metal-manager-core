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
	"github.com/stretchr/testify/require"
	otrace "go.opentelemetry.io/otel/trace"
)

func testInfiniBandPartitionSetupSchema(t *testing.T, dbSession *db.Session) {
	// Create tables
	err := dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	require.NoError(t, err)

	err = dbSession.DB.ResetModel(context.Background(), (*Site)(nil))
	require.NoError(t, err)

	err = dbSession.DB.ResetModel(context.Background(), (*InfrastructureProvider)(nil))
	require.NoError(t, err)

	err = dbSession.DB.ResetModel(context.Background(), (*InfiniBandPartition)(nil))
	require.NoError(t, err)
}

func TestInfiniBandPartitionSQLDAO_GetByID(t *testing.T) {
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
	testInfiniBandPartitionSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "Test Provider", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	ibpr := testBuildInfiniBandPartition(t, dbSession, nil, "test-InfiniBandPartition", nil, tn.Org, tn.ID, st.ID, db.GetUUIDPtr(uuid.New()), nil, nil, nil, nil, nil, nil, nil, db.GetStrPtr(InfiniBandPartitionStatusReady), tnu.ID)

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		want               *InfiniBandPartition
		wantErr            error
		paramRelations     []string
		verifyChildSpanner bool
	}{
		{
			name: "get InfiniBandPartition by ID returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: ctx,
				id:  ibpr.ID,
			},
			want:               ibpr,
			wantErr:            nil,
			paramRelations:     []string{TenantRelationName, SiteRelationName},
			verifyChildSpanner: true,
		},
		{
			name: "get InfiniBandPartition by non-existent ID returns error",
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
			ibpsd := InfiniBandPartitionSQLDAO{
				dbSession: tt.fields.dbSession,
			}

			got, err := ibpsd.GetByID(tt.args.ctx, nil, tt.args.id, tt.paramRelations)
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

func TestInfiniBandPartition_GetAll(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}

	type args struct {
		ctx            context.Context
		names          []string
		ids            []uuid.UUID
		tenantIDs      []uuid.UUID
		siteIDs        []uuid.UUID
		orgs           []string
		searchQuery    *string
		statuses       []string
		offset         *int
		limit          *int
		orderBy        *paginator.OrderBy
		paramRelations []string
	}

	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testInfiniBandPartitionSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))

	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "Test Provider", ipu.ID)

	tnu1 := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("janed@test.com"), db.GetStrPtr("Jane"), db.GetStrPtr("Doe"))
	tn1 := testBuildTenant(t, dbSession, nil, "test-tenant-1", "test-tenant-org-1", tnu1.ID)

	tnu2 := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jimd@test.com"), db.GetStrPtr("Jim"), db.GetStrPtr("Doe"))
	tn2 := testBuildTenant(t, dbSession, nil, "test-tenant-2", "test-tenant-org-2", tnu2.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	totalCount := 30

	InfiniBandPartitions := []InfiniBandPartition{}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	for i := 0; i < totalCount; i++ {
		var pt *InfiniBandPartition
		var tn *Tenant

		if i%2 == 0 {
			tn = tn1
		} else {
			tn = tn2
		}

		if i%2 == 0 {
			pt = testBuildInfiniBandPartition(t, dbSession, nil, fmt.Sprintf("test-InfiniBandPartition-batch-v1-%v", i), db.GetStrPtr(fmt.Sprintf("test-InfiniBandPartition-desc-batch-1-%v", i)), tn.Org, tn.ID, st.ID, db.GetUUIDPtr(uuid.New()), nil, nil, nil, nil, nil, nil, map[string]string{fmt.Sprintf("test-InfiniBandPartition-batch-key1-%v", i): fmt.Sprintf("test-InfiniBandPartition-batch-value1-%v", i)}, db.GetStrPtr(InfiniBandPartitionStatusReady), tn.CreatedBy)
		} else {
			pt = testBuildInfiniBandPartition(t, dbSession, nil, fmt.Sprintf("test-InfiniBandPartition-batch-v2-%v", i), db.GetStrPtr(fmt.Sprintf("test-InfiniBandPartition-desc-batch-2-%v", i)), tn.Org, tn.ID, st.ID, db.GetUUIDPtr(uuid.New()), nil, nil, nil, nil, nil, nil, map[string]string{fmt.Sprintf("test-InfiniBandPartition-batch-key2-%v", i): fmt.Sprintf("test-InfiniBandPartition-batch-value2-%v", i)}, db.GetStrPtr(InfiniBandPartitionStatusDeleting), tn.CreatedBy)
		}

		InfiniBandPartitions = append(InfiniBandPartitions, *pt)
	}

	tests := []struct {
		name               string
		fields             fields
		args               args
		wantCount          int
		wantTotalCount     int
		wantFirstEntry     *InfiniBandPartition
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "get all InfiniBandPartitions with no filters returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:       ctx,
				tenantIDs: nil,
				siteIDs:   nil,
				orgs:      nil,
			},
			wantCount:          paginator.DefaultLimit,
			wantTotalCount:     totalCount,
			wantErr:            false,
			verifyChildSpanner: true,
		},
		{
			name: "get all InfiniBandPartitions with relation returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:            context.Background(),
				tenantIDs:      nil,
				siteIDs:        nil,
				orgs:           nil,
				paramRelations: []string{TenantRelationName, SiteRelationName},
			},
			wantCount:      paginator.DefaultLimit,
			wantTotalCount: totalCount,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with Tenant ID filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:       context.Background(),
				tenantIDs: []uuid.UUID{tn1.ID},
				siteIDs:   nil,
				orgs:      nil,
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with Tenant ID and name filters returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:       context.Background(),
				names:     []string{"test-InfiniBandPartition-batch-v1-8"},
				tenantIDs: []uuid.UUID{tn1.ID},
				siteIDs:   nil,
				orgs:      nil,
			},
			wantCount:      1,
			wantTotalCount: 1,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with Site ID filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:       context.Background(),
				tenantIDs: nil,
				siteIDs:   []uuid.UUID{st.ID},
				orgs:      nil,
			},
			wantCount:      paginator.DefaultLimit,
			wantTotalCount: totalCount,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with Org filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:       context.Background(),
				tenantIDs: nil,
				siteIDs:   nil,
				orgs:      []string{tn1.Org},
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
				ctx:       context.Background(),
				tenantIDs: nil,
				siteIDs:   []uuid.UUID{st.ID},
				orgs:      nil,
				limit:     db.GetIntPtr(10),
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
				ctx:       context.Background(),
				tenantIDs: []uuid.UUID{tn1.ID},
				siteIDs:   nil,
				orgs:      nil,
				offset:    db.GetIntPtr(5),
			},
			wantCount:      10,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all ordered by name",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:       context.Background(),
				tenantIDs: []uuid.UUID{tn1.ID},
				siteIDs:   nil,
				orgs:      nil,
				orderBy:   &paginator.OrderBy{Field: "name", Order: paginator.OrderDescending},
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantFirstEntry: &InfiniBandPartitions[8],
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with Org filter with site/tenant include relation returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:            context.Background(),
				tenantIDs:      nil,
				siteIDs:        nil,
				orgs:           []string{tn1.Org},
				paramRelations: []string{SiteRelationName, TenantRelationName},
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with infrastructure ID filter returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:       context.Background(),
				tenantIDs: nil,
				siteIDs:   nil,
				orgs:      nil,
			},
			wantCount:      paginator.DefaultLimit,
			wantTotalCount: totalCount,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with search query as name returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantIDs:   nil,
				siteIDs:     nil,
				orgs:        nil,
				searchQuery: db.GetStrPtr("test-InfiniBandPartition-batch-v1-"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with search query as a description returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantIDs:   nil,
				siteIDs:     nil,
				orgs:        nil,
				searchQuery: db.GetStrPtr("test-InfiniBandPartition-desc-batch-1-"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with search query as a status ready returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				ids:         nil,
				tenantIDs:   nil,
				siteIDs:     nil,
				orgs:        nil,
				searchQuery: db.GetStrPtr(InfiniBandPartitionStatusReady),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with search query as a status deleting returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantIDs:   nil,
				siteIDs:     nil,
				orgs:        nil,
				searchQuery: db.GetStrPtr(InfiniBandPartitionStatusDeleting),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with search query with combination of name and status returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantIDs:   nil,
				siteIDs:     nil,
				orgs:        nil,
				searchQuery: db.GetStrPtr("test-InfiniBandPartition-batch-v1- | ready"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with search query with combination of description and status returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantIDs:   nil,
				siteIDs:     nil,
				orgs:        nil,
				searchQuery: db.GetStrPtr("test-InfiniBandPartition-desc-batch-1- error"),
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with search query with combination of description and status returns none success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantIDs:   nil,
				siteIDs:     nil,
				orgs:        nil,
				searchQuery: db.GetStrPtr("test-InfiniBandPartition-desc-batch-3- error"),
			},
			wantCount:      0,
			wantTotalCount: 0,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with empty search query returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantIDs:   nil,
				siteIDs:     nil,
				orgs:        nil,
				searchQuery: db.GetStrPtr(""),
			},
			wantCount:      20,
			wantTotalCount: 30,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with empty search query returns success with ip",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:         context.Background(),
				tenantIDs:   nil,
				siteIDs:     nil,
				orgs:        nil,
				searchQuery: db.GetStrPtr(""),
			},
			wantCount:      20,
			wantTotalCount: 30,
			wantErr:        false,
		},
		{
			name: "get all InfiniBandPartitions with status returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:       context.Background(),
				tenantIDs: nil,
				siteIDs:   nil,
				orgs:      nil,
				statuses:  []string{InfiniBandPartitionStatusDeleting},
			},
			wantCount:      totalCount / 2,
			wantTotalCount: totalCount / 2,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ibpsd := InfiniBandPartitionSQLDAO{
				dbSession: tt.fields.dbSession,
			}

			got, total, err := ibpsd.GetAll(
				tt.args.ctx,
				nil,
				InfiniBandPartitionFilterInput{
					Names:                  tt.args.names,
					SiteIDs:                tt.args.siteIDs,
					TenantOrgs:             tt.args.orgs,
					TenantIDs:              tt.args.tenantIDs,
					Statuses:               tt.args.statuses,
					InfiniBandPartitionIDs: tt.args.ids,
					SearchQuery:            tt.args.searchQuery,
				},
				paginator.PageInput{
					Offset:  tt.args.offset,
					Limit:   tt.args.limit,
					OrderBy: tt.args.orderBy,
				},
				tt.args.paramRelations,
			)
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

func TestInfiniBandPartitionSQLDAO_Create(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx                               context.Context
		name                              string
		description                       *string
		org                               string
		siteID                            uuid.UUID
		tenantID                          uuid.UUID
		ControllerIBInfiniBandPartitionID *uuid.UUID
		Labels                            map[string]string
		status                            string
		createdBy                         User
	}

	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testInfiniBandPartitionSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "Test Provider", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	ibpr := &InfiniBandPartition{
		Name:                    "test-InfiniBandPartition",
		Description:             db.GetStrPtr("Test InfiniBandPartition"),
		Org:                     tn.Org,
		SiteID:                  st.ID,
		TenantID:                tn.ID,
		ControllerIBPartitionID: db.GetUUIDPtr(uuid.New()),
		Labels: map[string]string{
			"ibp1": "us-east-1",
			"ibp2": "us-east-2",
		},
		Status:    InfiniBandPartitionStatusPending,
		CreatedBy: tnu.ID,
	}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		want               *InfiniBandPartition
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "create InfiniBandPartition from params returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                               ctx,
				name:                              ibpr.Name,
				description:                       ibpr.Description,
				org:                               ibpr.Org,
				tenantID:                          ibpr.TenantID,
				siteID:                            ibpr.SiteID,
				ControllerIBInfiniBandPartitionID: ibpr.ControllerIBPartitionID,
				Labels:                            ibpr.Labels,
				status:                            ibpr.Status,
				createdBy:                         User{ID: ibpr.CreatedBy},
			},
			want:               ibpr,
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ibpsd := InfiniBandPartitionSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			got, err := ibpsd.Create(
				tt.args.ctx,
				nil,
				InfiniBandPartitionCreateInput{
					Name:                    tt.args.name,
					Description:             tt.args.description,
					TenantOrg:               tt.args.org,
					SiteID:                  tt.args.siteID,
					TenantID:                tt.args.tenantID,
					ControllerIBPartitionID: tt.args.ControllerIBInfiniBandPartitionID,
					Labels:                  tt.args.Labels,
					Status:                  tt.args.status,
					CreatedBy:               tt.args.createdBy.ID,
				},
			)
			require.Equal(t, tt.wantErr, err != nil)

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, *tt.want.Description, *got.Description)
			assert.Equal(t, tt.want.Org, got.Org)
			assert.Equal(t, tt.want.SiteID, got.SiteID)
			assert.Equal(t, tt.want.TenantID, got.TenantID)
			assert.Equal(t, *tt.want.ControllerIBPartitionID, *got.ControllerIBPartitionID)
			assert.Equal(t, tt.want.Labels, got.Labels)
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

func TestInfiniBandPartitionSQLDAO_Update(t *testing.T) {
	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testInfiniBandPartitionSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "test-provider-org", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	pt := testBuildInfiniBandPartition(t, dbSession, nil, "test-InfiniBandPartition", nil, tn.Org, tn.ID, st.ID, db.GetUUIDPtr(uuid.New()), nil, nil, nil, nil, nil, nil, nil, db.GetStrPtr(InfiniBandPartitionStatusReady), tnu.ID)

	uInfiniBandPartition := &InfiniBandPartition{
		Name:                    "test-updated",
		Description:             db.GetStrPtr("Test Updated"),
		ControllerIBPartitionID: db.GetUUIDPtr(uuid.New()),
		Labels: map[string]string{
			"ibp1": "us-east-1",
			"ibp2": "us-east-2",
		},
		Status:          InfiniBandPartitionStatusReady,
		IsMissingOnSite: true,
	}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx                     context.Context
		id                      uuid.UUID
		name                    *string
		description             *string
		ControllerIBPartitionID *uuid.UUID
		Labels                  map[string]string
		Status                  string
		IsMissingOnSite         bool
	}
	tests := []struct {
		name               string
		fields             fields
		args               args
		want               *InfiniBandPartition
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "update InfiniBandPartition from params returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                     ctx,
				id:                      pt.ID,
				name:                    &uInfiniBandPartition.Name,
				description:             uInfiniBandPartition.Description,
				ControllerIBPartitionID: uInfiniBandPartition.ControllerIBPartitionID,
				Labels:                  uInfiniBandPartition.Labels,
				Status:                  uInfiniBandPartition.Status,
				IsMissingOnSite:         uInfiniBandPartition.IsMissingOnSite,
			},
			want:               uInfiniBandPartition,
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ibpsd := InfiniBandPartitionSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			got, err := ibpsd.Update(
				tt.args.ctx,
				nil,
				InfiniBandPartitionUpdateInput{
					InfiniBandPartitionID:   tt.args.id,
					Name:                    tt.args.name,
					Description:             tt.args.description,
					ControllerIBPartitionID: tt.args.ControllerIBPartitionID,
					Labels:                  tt.args.Labels,
					Status:                  &tt.args.Status,
					IsMissingOnSite:         &tt.args.IsMissingOnSite,
				},
			)

			fmt.Printf("\ngot ID: %v, Created: %v, Updated: %v", got.ID.String(), got.Created, got.Updated)

			require.Equal(t, tt.wantErr, err != nil)

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, *tt.want.Description, *got.Description)
			assert.Equal(t, *tt.want.ControllerIBPartitionID, *got.ControllerIBPartitionID)
			assert.Equal(t, tt.want.Labels, got.Labels)
			assert.Equal(t, tt.want.Status, got.Status)

			assert.NotEqualValues(t, got.Updated, pt.Updated)

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestInfiniBandPartitionSQLDAO_Delete(t *testing.T) {
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
	testInfiniBandPartitionSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "Test Provider", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	pt := testBuildInfiniBandPartition(t, dbSession, nil, "test-InfiniBandPartition", nil, tn.Org, tn.ID, st.ID, db.GetUUIDPtr(uuid.New()), nil, nil, nil, nil, nil, nil, nil, db.GetStrPtr(InfiniBandPartitionStatusReady), tnu.ID)

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
			name: "delete InfiniBandPartition by ID",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: ctx,
				id:  pt.ID,
			},
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ibpsd := InfiniBandPartitionSQLDAO{
				dbSession: tt.fields.dbSession,
			}

			err := ibpsd.Delete(tt.args.ctx, nil, tt.args.id)
			require.Equal(t, tt.wantErr, err != nil)

			dInfiniBandPartition := &InfiniBandPartition{}
			err = dbSession.DB.NewSelect().Model(dInfiniBandPartition).WhereDeleted().Where("id = ?", pt.ID).Scan(context.Background())
			require.NoError(t, err)
			assert.NotNil(t, dInfiniBandPartition.Deleted)

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestInfiniBandPartitionSQLDAO_Clear(t *testing.T) {
	// Create test DB
	dbSession := testInitDB(t)
	defer dbSession.Close()

	// Create tables
	testInfiniBandPartitionSetupSchema(t, dbSession)

	// Create necessary objects
	ipu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("johnd@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	ip := testBuildInfrastructureProvider(t, dbSession, nil, "test-ip", "test-provider-org", ipu.ID)

	tnu := testBuildUser(t, dbSession, nil, testGenerateStarfleetID(), db.GetStrPtr("jdoe@test.com"), db.GetStrPtr("John"), db.GetStrPtr("Doe"))
	tn := testBuildTenant(t, dbSession, nil, "test-tenant", "test-tenant-org", tnu.ID)

	st := testBuildSite(t, dbSession, nil, ip.ID, "test-site", "Test Site", ip.Org, ipu.ID)

	pt := testBuildInfiniBandPartition(t, dbSession, nil, "test-InfiniBandPartition", nil, tn.Org, tn.ID, st.ID, db.GetUUIDPtr(uuid.New()), nil, nil, nil, nil, nil, nil, nil, db.GetStrPtr(InfiniBandPartitionStatusReady), tnu.ID)

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	type fields struct {
		dbSession  *db.Session
		tracerSpan *stracer.TracerSpan
	}
	type args struct {
		ctx                     context.Context
		tx                      *db.Tx
		id                      uuid.UUID
		description             bool
		ControllerIBPartitionID bool
	}
	tests := []struct {
		name               string
		fields             fields
		args               args
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "clearing InfiniBandPartition attributes returns success",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:                     ctx,
				id:                      pt.ID,
				description:             true,
				ControllerIBPartitionID: true,
			},
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ibpsd := InfiniBandPartitionSQLDAO{
				dbSession:  tt.fields.dbSession,
				tracerSpan: tt.fields.tracerSpan,
			}
			got, err := ibpsd.Clear(
				tt.args.ctx,
				tt.args.tx,
				InfiniBandPartitionClearInput{
					InfiniBandPartitionID:   tt.args.id,
					Description:             tt.args.description,
					ControllerIBPartitionID: tt.args.ControllerIBPartitionID,
				},
			)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.args.description {
				assert.Nil(t, got.Description)
			}

			if tt.args.ControllerIBPartitionID {
				assert.Nil(t, got.ControllerIBPartitionID)
			}
		})
	}
}
