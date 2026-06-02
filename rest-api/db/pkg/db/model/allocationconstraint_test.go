// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
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

func testAllocationConstraintInitDB(t *testing.T) *db.Session {
	dbSession := util.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv(""),
	))
	return dbSession
}

// reset the tables needed for AllocationConstraint tests
func testAllocationConstraintSetupSchema(t *testing.T, dbSession *db.Session) {
	// create Infrastructure Provider table
	err := dbSession.DB.ResetModel(context.Background(), (*InfrastructureProvider)(nil))
	assert.Nil(t, err)
	// create Site table
	err = dbSession.DB.ResetModel(context.Background(), (*Site)(nil))
	assert.Nil(t, err)
	// create Tenant table
	err = dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	assert.Nil(t, err)
	// create User table
	err = dbSession.DB.ResetModel(context.Background(), (*User)(nil))
	assert.Nil(t, err)
	// create NetworkSecurityGroup table
	err = dbSession.DB.ResetModel(context.Background(), (*NetworkSecurityGroup)(nil))
	assert.Nil(t, err)
	// create Instance Type table
	err = dbSession.DB.ResetModel(context.Background(), (*InstanceType)(nil))
	assert.Nil(t, err)
	// create IPBlock table
	err = dbSession.DB.ResetModel(context.Background(), (*IPBlock)(nil))
	assert.Nil(t, err)
	// create Allocation table
	err = dbSession.DB.ResetModel(context.Background(), (*Allocation)(nil))
	assert.Nil(t, err)
	// create AllocationConstraint table
	err = dbSession.DB.ResetModel(context.Background(), (*AllocationConstraint)(nil))
	assert.Nil(t, err)
}

func testAllocationConstraintBuildInfrastructureProvider(t *testing.T, dbSession *db.Session,
	name string) *InfrastructureProvider {
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

func testAllocationConstraintBuildSite(t *testing.T, dbSession *db.Session,
	ip *InfrastructureProvider, name string) *Site {
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

func testAllocationConstraintBuildTenant(t *testing.T, dbSession *db.Session, name string) *Tenant {
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: name,
		Org:  "test",
	}
	_, err := dbSession.DB.NewInsert().Model(tenant).Exec(context.Background())
	assert.Nil(t, err)
	return tenant
}

func testAllocationConstraintBuildUser(t *testing.T, dbSession *db.Session,
	starfleetID string) *User {
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

func testAllocationConstraintBuildAllocation(t *testing.T, dbSession *db.Session,
	ipID uuid.UUID, tenantID uuid.UUID, siteID uuid.UUID, userID uuid.UUID) *Allocation {
	alloc := &Allocation{
		ID:                       uuid.New(),
		Name:                     "test1",
		Description:              db.GetStrPtr("description"),
		InfrastructureProviderID: ipID,
		TenantID:                 tenantID,
		SiteID:                   siteID,
		CreatedBy:                userID,
	}
	_, err := dbSession.DB.NewInsert().Model(alloc).Exec(context.Background())
	assert.Nil(t, err)
	return alloc
}

func testAllocationConstraintBuildInstanceType(t *testing.T, dbSession *db.Session,
	ipID uuid.UUID, siteID uuid.UUID, userID uuid.UUID, name string) *InstanceType {
	insType := &InstanceType{
		ID:                       uuid.New(),
		Name:                     name,
		DisplayName:              db.GetStrPtr("display name"),
		Description:              db.GetStrPtr("description"),
		ControllerMachineType:    db.GetStrPtr("controllerMachineType"),
		InfrastructureProviderID: ipID,
		SiteID:                   &siteID,
		Status:                   InstanceTypeStatusPending,
		CreatedBy:                userID,
	}
	_, err := dbSession.DB.NewInsert().Model(insType).Exec(context.Background())
	assert.Nil(t, err)
	return insType
}

func testAllocationConstraintBuildIPBlock(t *testing.T, dbSession *db.Session,
	siteID, infrastructureProviderID *uuid.UUID, name string) *IPBlock {
	ipBlock := &IPBlock{
		ID:                       uuid.New(),
		Name:                     name,
		SiteID:                   *siteID,
		InfrastructureProviderID: *infrastructureProviderID,
		PrefixLength:             8,
	}
	_, err := dbSession.DB.NewInsert().Model(ipBlock).Exec(context.Background())
	assert.Nil(t, err)
	return ipBlock
}

func TestAllocationConstraintSQLDAO_CreateFromParams(t *testing.T) {
	ctx := context.Background()
	dbSession := testAllocationConstraintInitDB(t)
	defer dbSession.Close()
	testAllocationConstraintSetupSchema(t, dbSession)
	ip := testAllocationConstraintBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testAllocationConstraintBuildSite(t, dbSession, ip, "testSite")
	tenant := testAllocationConstraintBuildTenant(t, dbSession, "testTenant")
	user := testAllocationConstraintBuildUser(t, dbSession, "testUser")
	insType := testAllocationConstraintBuildInstanceType(t, dbSession,
		ip.ID, site.ID, user.ID, "instance-type-1")
	ipv4Block := testAllocationConstraintBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block")
	alloc1 := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)
	alloc2 := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)

	asd := NewAllocationConstraintDAO(dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		as                 []AllocationConstraint
		expectError        bool
		verifyChildSpanner bool
	}{
		{
			desc: "create constraint of InstanceType and IPBlock",
			as: []AllocationConstraint{
				{
					AllocationID:      alloc1.ID,
					ResourceType:      AllocationResourceTypeInstanceType,
					ResourceTypeID:    insType.ID,
					ConstraintType:    AllocationConstraintTypeReserved,
					ConstraintValue:   100,
					DerivedResourceID: nil,
					CreatedBy:         user.ID,
				},
				{
					AllocationID:      alloc2.ID,
					ResourceType:      AllocationResourceTypeIPBlock,
					ResourceTypeID:    ipv4Block.ID,
					ConstraintType:    AllocationConstraintTypeReserved,
					ConstraintValue:   100,
					DerivedResourceID: nil,
					CreatedBy:         user.ID,
				},
			},
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc: "failure - foreign key violation on allocation_id",
			as: []AllocationConstraint{
				{
					AllocationID:      uuid.New(),
					ResourceType:      AllocationResourceTypeIPBlock,
					ResourceTypeID:    ipv4Block.ID,
					ConstraintType:    AllocationConstraintTypeReserved,
					ConstraintValue:   100,
					DerivedResourceID: nil,
					CreatedBy:         user.ID,
				},
			},
			expectError: true,
		},
		{
			desc: "failure - multiple fields with nil",
			as: []AllocationConstraint{
				{
					AllocationID:      alloc1.ID,
					ResourceType:      "   ",
					ResourceTypeID:    ipv4Block.ID,
					ConstraintType:    AllocationConstraintTypeReserved,
					ConstraintValue:   100,
					DerivedResourceID: nil,
					CreatedBy:         user.ID,
				},
				{
					AllocationID:      alloc1.ID,
					ResourceType:      AllocationResourceTypeIPBlock,
					ResourceTypeID:    ipv4Block.ID,
					ConstraintType:    " ",
					ConstraintValue:   100,
					DerivedResourceID: nil,
					CreatedBy:         user.ID,
				},
			},
			expectError: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			for _, i := range tc.as {
				it, err := asd.CreateFromParams(
					ctx, nil, i.AllocationID, i.ResourceType,
					i.ResourceTypeID, i.ConstraintType,
					i.ConstraintValue, i.DerivedResourceID,
					i.CreatedBy)
				assert.Equal(t, tc.expectError, err != nil)
				if !tc.expectError {
					assert.NotNil(t, it)
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

func TestAllocationConstraintSQLDAO_GetByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testAllocationConstraintInitDB(t)
	defer dbSession.Close()
	testAllocationConstraintSetupSchema(t, dbSession)
	ip := testAllocationConstraintBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testAllocationConstraintBuildSite(t, dbSession, ip, "testSite")
	tenant := testAllocationConstraintBuildTenant(t, dbSession, "testTenant")
	user := testAllocationConstraintBuildUser(t, dbSession, "testUser")
	insType := testAllocationConstraintBuildInstanceType(t, dbSession,
		ip.ID, site.ID, user.ID, "instance-type-1")
	ipv4Block := testAllocationConstraintBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block")
	alloc1 := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)
	alloc2 := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)

	asd := NewAllocationConstraintDAO(dbSession)

	a1, err := asd.CreateFromParams(
		ctx, nil, alloc1.ID, AllocationResourceTypeInstanceType,
		insType.ID, AllocationConstraintTypeReserved, 10, nil, user.ID)
	assert.Nil(t, err)
	assert.NotNil(t, a1)

	a2, err := asd.CreateFromParams(
		ctx, nil, alloc2.ID, AllocationResourceTypeIPBlock,
		ipv4Block.ID, AllocationConstraintTypeReserved, 10, nil, user.ID)
	assert.Nil(t, err)
	assert.NotNil(t, a2)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		id                 uuid.UUID
		a                  *AllocationConstraint
		paramRelations     []string
		expectedError      bool
		expectedErrVal     error
		expectedAllocation bool
		verifyChildSpanner bool
	}{
		{
			desc:               "GetById success when AllocationConstraint exists",
			id:                 a1.ID,
			a:                  a1,
			paramRelations:     []string{},
			expectedError:      false,
			expectedAllocation: false,
		},
		{
			desc:               "GetById error when not found",
			id:                 uuid.New(),
			paramRelations:     []string{},
			expectedError:      true,
			expectedErrVal:     db.ErrDoesNotExist,
			expectedAllocation: false,
		},
		{
			desc:               "GetById with Allocation relation",
			id:                 a2.ID,
			a:                  a2,
			paramRelations:     []string{AllocationRelationName},
			expectedError:      false,
			expectedAllocation: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := asd.GetByID(ctx, nil, tc.id, tc.paramRelations)
			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				assert.Equal(t, tc.expectedErrVal, err)
			}
			if err == nil {
				assert.EqualValues(t, tc.a.ID, got.ID)
				if tc.expectedAllocation {
					assert.EqualValues(t, tc.a.AllocationID, got.Allocation.ID)
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

func TestAllocationConstraintSQLDAO_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := testAllocationConstraintInitDB(t)
	defer dbSession.Close()
	testAllocationConstraintSetupSchema(t, dbSession)
	ip := testAllocationConstraintBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testAllocationConstraintBuildSite(t, dbSession, ip, "testSite")
	tenant := testAllocationConstraintBuildTenant(t, dbSession, "testTenant")
	user := testAllocationConstraintBuildUser(t, dbSession, "testUser")
	insType := testAllocationConstraintBuildInstanceType(t, dbSession,
		ip.ID, site.ID, user.ID, "instance-type-1")
	ipv4Block := testAllocationConstraintBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block")

	alloc1 := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)
	alloc2 := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)

	asd := NewAllocationConstraintDAO(dbSession)

	totalCount := 30

	asc1it := []AllocationConstraint{}
	for i := 0; i < totalCount/2; i++ {
		asc1, err := asd.CreateFromParams(
			ctx, nil, alloc1.ID, AllocationResourceTypeInstanceType,
			insType.ID, AllocationConstraintTypeReserved, 10, nil, user.ID)
		assert.Nil(t, err)
		assert.NotNil(t, asc1)
		asc1it = append(asc1it, *asc1)
	}

	asc2ipb := []AllocationConstraint{}
	for i := 0; i < totalCount/2; i++ {
		asc2, err := asd.CreateFromParams(
			ctx, nil, alloc2.ID, AllocationResourceTypeIPBlock,
			ipv4Block.ID, AllocationConstraintTypeReserved, 10, db.GetUUIDPtr(uuid.New()), user.ID)
		assert.Nil(t, err)
		assert.NotNil(t, asc2)
		asc2ipb = append(asc2ipb, *asc2)
	}

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		allocationIDs      []uuid.UUID
		resourceType       *string
		resourceTypeID     *uuid.UUID
		constraintType     *string
		derivedResourceID  *uuid.UUID
		offset             *int
		limit              *int
		orderBy            *paginator.OrderBy
		firstEntry         *AllocationConstraint
		expectedCount      int
		expectedTotal      *int
		expectedError      bool
		paramRelations     []string
		verifyChildSpanner bool
	}{
		{
			desc:               "GetAll with no filters returns objects",
			allocationIDs:      nil,
			resourceType:       nil,
			resourceTypeID:     nil,
			constraintType:     nil,
			expectedCount:      paginator.DefaultLimit,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:           "GetAll with Allocation ID filter returns objects",
			allocationIDs:  []uuid.UUID{alloc2.ID},
			resourceType:   nil,
			resourceTypeID: nil,
			constraintType: nil,
			expectedCount:  totalCount / 2,
			expectedError:  false,
			paramRelations: []string{AllocationRelationName},
		},
		{
			desc:           "GetAll with Resource Type filter returns objects",
			allocationIDs:  nil,
			resourceType:   db.GetStrPtr(AllocationResourceTypeIPBlock),
			resourceTypeID: nil,
			constraintType: nil,
			expectedCount:  totalCount / 2,
			expectedError:  false,
		},
		{
			desc:           "GetAll with Resource Type ID filter returns objects",
			allocationIDs:  nil,
			resourceType:   nil,
			resourceTypeID: &insType.ID,
			constraintType: nil,
			expectedCount:  totalCount / 2,
			expectedError:  false,
		},
		{
			desc:              "GetAll with Derived Resource ID filter returns objects",
			allocationIDs:     nil,
			resourceType:      nil,
			resourceTypeID:    nil,
			constraintType:    nil,
			derivedResourceID: asc2ipb[0].DerivedResourceID,
			expectedCount:     1,
			expectedError:     false,
		},
		{
			desc:           "GetAll with invalid Resource Type ID filter returns no objects",
			allocationIDs:  nil,
			resourceType:   nil,
			resourceTypeID: db.GetUUIDPtr(uuid.New()),
			constraintType: nil,
			expectedCount:  0,
			expectedError:  false,
		},
		{
			desc:           "GetAll with Constraint Type filter returns objects",
			allocationIDs:  nil,
			resourceType:   db.GetStrPtr(AllocationResourceTypeIPBlock),
			resourceTypeID: nil,
			constraintType: db.GetStrPtr(AllocationConstraintTypeReserved),
			expectedCount:  totalCount / 2,
			expectedError:  false,
		},
		{
			desc:           "GetAll with limit returns objects",
			allocationIDs:  []uuid.UUID{alloc1.ID},
			resourceType:   nil,
			resourceTypeID: nil,
			constraintType: nil,
			offset:         db.GetIntPtr(0),
			limit:          db.GetIntPtr(5),
			expectedCount:  5,
			expectedTotal:  db.GetIntPtr(totalCount / 2),
			expectedError:  false,
		},
		{
			desc:           "GetAll with offset returns objects",
			allocationIDs:  []uuid.UUID{alloc2.ID},
			resourceType:   nil,
			resourceTypeID: nil,
			constraintType: nil,
			offset:         db.GetIntPtr(5),
			expectedCount:  10,
			expectedTotal:  db.GetIntPtr(totalCount / 2),
			expectedError:  false,
		},
		{
			desc:           "GetAll with order by returns objects",
			allocationIDs:  []uuid.UUID{alloc1.ID},
			resourceType:   nil,
			resourceTypeID: nil,
			constraintType: nil,
			orderBy: &paginator.OrderBy{
				Field: "created",
				Order: paginator.OrderAscending,
			},
			firstEntry:    &asc1it[0],
			expectedCount: totalCount / 2,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
		{
			desc:          "GetAll with resource Type filter returns none objects",
			allocationIDs: []uuid.UUID{alloc1.ID},
			resourceType:  db.GetStrPtr(AllocationResourceTypeIPBlock),
			expectedCount: 0,
			expectedTotal: db.GetIntPtr(0),
			expectedError: false,
		},
		{
			desc:          "GetAll with resource Type filter returns objects",
			allocationIDs: []uuid.UUID{alloc2.ID},
			resourceType:  db.GetStrPtr(AllocationResourceTypeIPBlock),
			expectedCount: totalCount / 2,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
		{
			desc:          "GetAll with resource Type filter with mixed allocation uuids returns objects",
			allocationIDs: []uuid.UUID{alloc1.ID, alloc2.ID},
			resourceType:  db.GetStrPtr(AllocationResourceTypeIPBlock),
			expectedCount: totalCount / 2,
			expectedTotal: db.GetIntPtr(totalCount / 2),
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			var resourceIDs []uuid.UUID
			if tc.resourceTypeID != nil {
				resourceIDs = append(resourceIDs, *tc.resourceTypeID)
			}
			got, total, err := asd.GetAll(ctx, nil, tc.allocationIDs, tc.resourceType, resourceIDs, tc.constraintType,
				tc.derivedResourceID, tc.paramRelations, tc.offset, tc.limit, tc.orderBy)
			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				assert.Equal(t, nil, got)
			} else {
				assert.Equal(t, tc.expectedCount, len(got))
				if len(tc.paramRelations) > 0 && len(tc.allocationIDs) > 0 {
					assert.Equal(t, tc.allocationIDs[0], got[0].Allocation.ID)
				}
			}

			if tc.expectedTotal != nil {
				assert.Equal(t, *tc.expectedTotal, total)
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

func TestAllocationConstraintSQLDAO_UpdateFromParams(t *testing.T) {
	ctx := context.Background()
	dbSession := testAllocationConstraintInitDB(t)
	defer dbSession.Close()
	testAllocationConstraintSetupSchema(t, dbSession)
	ip := testAllocationConstraintBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testAllocationConstraintBuildSite(t, dbSession, ip, "testSite")
	tenant := testAllocationConstraintBuildTenant(t, dbSession, "testTenant")
	user := testAllocationConstraintBuildUser(t, dbSession, "testUser")
	insType := testAllocationConstraintBuildInstanceType(t, dbSession,
		ip.ID, site.ID, user.ID, "instance-type-1")
	ipv4Block := testAllocationConstraintBuildIPBlock(t, dbSession, &site.ID, &ip.ID, "ipv4Block")
	alloc1 := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)
	alloc2 := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)

	asd := NewAllocationConstraintDAO(dbSession)

	derivedResourceID := uuid.New()
	derivedResourceID2 := uuid.New()
	constraintValue := 1
	constraintValue2 := 2
	a1, err := asd.CreateFromParams(
		ctx, nil, alloc1.ID, AllocationResourceTypeInstanceType, insType.ID,
		AllocationConstraintTypeReserved, constraintValue, &derivedResourceID, user.ID)
	assert.Nil(t, err)
	assert.NotNil(t, a1)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc string

		paramAllocationID      *uuid.UUID
		paramResourceType      *string
		paramResourceTypeID    *uuid.UUID
		paramConstraintType    *string
		paramConstraintValue   *int
		paramDerivedResourceID *uuid.UUID

		expectedError bool

		expectedAllocationID      *uuid.UUID
		expectedResourceType      *string
		expectedResourceTypeID    *uuid.UUID
		expectedConstraintType    *string
		expectedConstraintValue   *int
		expectedDerivedResourceID *uuid.UUID
		expectedUpdate            bool
		verifyChildSpanner        bool
	}{
		{
			desc:                   "can update nothing",
			paramAllocationID:      nil,
			paramResourceType:      nil,
			paramResourceTypeID:    nil,
			paramConstraintType:    nil,
			paramConstraintValue:   nil,
			paramDerivedResourceID: nil,

			expectedError:             false,
			expectedAllocationID:      &alloc1.ID,
			expectedResourceType:      db.GetStrPtr(AllocationResourceTypeInstanceType),
			expectedResourceTypeID:    &insType.ID,
			expectedConstraintType:    db.GetStrPtr(AllocationConstraintTypeReserved),
			expectedConstraintValue:   &constraintValue,
			expectedDerivedResourceID: &derivedResourceID,
			expectedUpdate:            false,
			verifyChildSpanner:        true,
		},
		{
			desc:                   "error updating due to foreign key violation",
			paramAllocationID:      &derivedResourceID,
			paramResourceType:      nil,
			paramResourceTypeID:    nil,
			paramConstraintType:    nil,
			paramConstraintValue:   nil,
			paramDerivedResourceID: nil,

			expectedError:             true,
			expectedAllocationID:      &alloc1.ID,
			expectedResourceType:      db.GetStrPtr(AllocationResourceTypeInstanceType),
			expectedResourceTypeID:    &insType.ID,
			expectedConstraintType:    db.GetStrPtr(AllocationConstraintTypeReserved),
			expectedConstraintValue:   &constraintValue,
			expectedDerivedResourceID: &derivedResourceID,
			expectedUpdate:            true,
		},
		{
			desc:                   "can update AllocationID ResourceType n ID",
			paramAllocationID:      &alloc2.ID,
			paramResourceType:      db.GetStrPtr(AllocationResourceTypeIPBlock),
			paramResourceTypeID:    &ipv4Block.ID,
			paramConstraintType:    nil,
			paramConstraintValue:   nil,
			paramDerivedResourceID: nil,

			expectedError:             false,
			expectedAllocationID:      &alloc2.ID,
			expectedResourceType:      db.GetStrPtr(AllocationResourceTypeIPBlock),
			expectedResourceTypeID:    &ipv4Block.ID,
			expectedConstraintType:    db.GetStrPtr(AllocationConstraintTypeReserved),
			expectedConstraintValue:   &constraintValue,
			expectedDerivedResourceID: &derivedResourceID,
			expectedUpdate:            true,
		},
		{
			desc:                   "can update Constraint Type Value n ResourceID",
			paramAllocationID:      nil,
			paramResourceType:      nil,
			paramResourceTypeID:    nil,
			paramConstraintType:    db.GetStrPtr(AllocationConstraintTypePreemptible),
			paramConstraintValue:   &constraintValue2,
			paramDerivedResourceID: &derivedResourceID2,

			expectedError:             false,
			expectedAllocationID:      &alloc2.ID,
			expectedResourceType:      db.GetStrPtr(AllocationResourceTypeIPBlock),
			expectedResourceTypeID:    &ipv4Block.ID,
			expectedConstraintType:    db.GetStrPtr(AllocationConstraintTypePreemptible),
			expectedConstraintValue:   &constraintValue2,
			expectedDerivedResourceID: &derivedResourceID2,
			expectedUpdate:            true,
		},
		{
			desc:                   "invalid Constraint Type",
			paramAllocationID:      nil,
			paramResourceType:      nil,
			paramResourceTypeID:    nil,
			paramConstraintType:    db.GetStrPtr(" "),
			paramConstraintValue:   nil,
			paramDerivedResourceID: nil,

			expectedError:             true,
			expectedAllocationID:      &alloc2.ID,
			expectedResourceType:      db.GetStrPtr(AllocationResourceTypeIPBlock),
			expectedResourceTypeID:    &ipv4Block.ID,
			expectedConstraintType:    db.GetStrPtr(AllocationConstraintTypePreemptible),
			expectedConstraintValue:   &constraintValue2,
			expectedDerivedResourceID: &derivedResourceID2,
			expectedUpdate:            true,
		},
		{
			desc:                   "invalid Constraint Type",
			paramAllocationID:      nil,
			paramResourceType:      db.GetStrPtr(" "),
			paramResourceTypeID:    nil,
			paramConstraintType:    nil,
			paramConstraintValue:   nil,
			paramDerivedResourceID: nil,

			expectedError:             true,
			expectedAllocationID:      &alloc2.ID,
			expectedResourceType:      db.GetStrPtr(AllocationResourceTypeIPBlock),
			expectedResourceTypeID:    &ipv4Block.ID,
			expectedConstraintType:    db.GetStrPtr(AllocationConstraintTypePreemptible),
			expectedConstraintValue:   &constraintValue2,
			expectedDerivedResourceID: &derivedResourceID2,
			expectedUpdate:            true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := asd.UpdateFromParams(ctx, nil, a1.ID,
				tc.paramAllocationID, tc.paramResourceType,
				tc.paramResourceTypeID, tc.paramConstraintType,
				tc.paramConstraintValue, tc.paramDerivedResourceID)
			assert.Equal(t, tc.expectedError, err != nil)
			if !tc.expectedError {
				assert.NotNil(t, got)
				assert.Equal(t, *tc.expectedAllocationID, got.AllocationID)
				assert.Equal(t, *tc.expectedResourceType, got.ResourceType)
				assert.Equal(t, *tc.expectedResourceTypeID, got.ResourceTypeID)
				assert.Equal(t, *tc.expectedConstraintType, got.ConstraintType)
				assert.Equal(t, *tc.expectedConstraintValue, got.ConstraintValue)
				assert.Equal(t, tc.expectedDerivedResourceID, got.DerivedResourceID)

				if tc.expectedUpdate && got.Updated.String() == a1.Updated.String() {
					t.Errorf("got.Updated = %v, want different value", got.Updated)
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

func TestAllocationConstraintSQLDAO_ClearFromParams(t *testing.T) {
	ctx := context.Background()
	dbSession := testAllocationConstraintInitDB(t)
	defer dbSession.Close()
	testAllocationConstraintSetupSchema(t, dbSession)
	ip := testAllocationConstraintBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testAllocationConstraintBuildSite(t, dbSession, ip, "testSite")
	tenant := testAllocationConstraintBuildTenant(t, dbSession, "testTenant")
	user := testAllocationConstraintBuildUser(t, dbSession, "testUser")
	insType := testAllocationConstraintBuildInstanceType(t, dbSession,
		ip.ID, site.ID, user.ID, "instance-type-1")
	alloc := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)
	dummyUID := uuid.New()

	asd := NewAllocationConstraintDAO(dbSession)

	a1, err := asd.CreateFromParams(
		ctx, nil, alloc.ID, AllocationResourceTypeInstanceType,
		insType.ID, AllocationConstraintTypeReserved, 10,
		&dummyUID, user.ID)
	assert.Nil(t, err)
	assert.NotNil(t, a1)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc                      string
		a                         *AllocationConstraint
		paramDerivedResourceID    bool
		expectedDerivedResourceID *uuid.UUID
		verifyChildSpanner        bool
	}{
		{
			desc:                      "can clear derivedResourceId",
			a:                         a1,
			paramDerivedResourceID:    true,
			expectedDerivedResourceID: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := asd.ClearFromParams(ctx, nil, tc.a.ID, tc.paramDerivedResourceID)
			assert.Nil(t, err)
			assert.NotNil(t, got)
			assert.Equal(t, tc.expectedDerivedResourceID == nil,
				got.DerivedResourceID == nil)
			if tc.expectedDerivedResourceID != nil {
				assert.Equal(t, *tc.expectedDerivedResourceID,
					*got.DerivedResourceID)
			}

			assert.True(t, got.Updated.After(tc.a.Updated))

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestAllocationConstraintSQLDAO_DeleteByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testAllocationConstraintInitDB(t)
	defer dbSession.Close()
	testAllocationConstraintSetupSchema(t, dbSession)
	ip := testAllocationConstraintBuildInfrastructureProvider(t, dbSession, "testIP")
	site := testAllocationConstraintBuildSite(t, dbSession, ip, "testSite")
	tenant := testAllocationConstraintBuildTenant(t, dbSession, "testTenant")
	user := testAllocationConstraintBuildUser(t, dbSession, "testUser")
	insType := testAllocationConstraintBuildInstanceType(t, dbSession,
		ip.ID, site.ID, user.ID, "instance-type-1")
	alloc := testAllocationConstraintBuildAllocation(t, dbSession, ip.ID,
		tenant.ID, site.ID, user.ID)

	asd := NewAllocationConstraintDAO(dbSession)

	a1, err := asd.CreateFromParams(
		ctx, nil, alloc.ID, AllocationResourceTypeInstanceType,
		insType.ID, AllocationConstraintTypeReserved, 10, nil, user.ID)
	assert.Nil(t, err)
	assert.NotNil(t, a1)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		aID                uuid.UUID
		expectedError      bool
		verifyChildSpanner bool
	}{
		{
			desc:               "can delete existing object",
			aID:                a1.ID,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:          "delete non-existing object",
			aID:           uuid.New(),
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := asd.DeleteByID(ctx, nil, tc.aID)
			assert.Equal(t, tc.expectedError, err != nil)
			if !tc.expectedError {
				tmp, err := asd.GetByID(ctx, nil, tc.aID, nil)
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
