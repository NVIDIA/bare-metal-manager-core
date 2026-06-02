// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otrace "go.opentelemetry.io/otel/trace"
)

// reset the tables needed for SKU tests
func testSKUSetupSchema(t *testing.T, dbSession *db.Session) {
	// create User table
	err := dbSession.DB.ResetModel(context.Background(), (*User)(nil))
	assert.Nil(t, err)
	// create InfrastructureProvider table
	err = dbSession.DB.ResetModel(context.Background(), (*InfrastructureProvider)(nil))
	assert.Nil(t, err)
	// create Site table
	err = dbSession.DB.ResetModel(context.Background(), (*Site)(nil))
	assert.Nil(t, err)
	// create the SKU table
	err = dbSession.DB.ResetModel(context.Background(), (*SKU)(nil))
	assert.Nil(t, err)
}

func testSKUInitDB(t *testing.T) *db.Session {
	dbSession := util.GetTestDBSession(t, false)
	return dbSession
}

func testSkuCreateSkus(ctx context.Context, t *testing.T, dbSession *db.Session, siteId uuid.UUID) (created []SKU) {
	ssd := NewSkuDAO(dbSession)

	ids := []string{"sku-1", "sku-2", "sku-3"}
	for _, id := range ids {
		protoSku := &cwssaws.SkuComponents{}
		sk, err := ssd.Create(ctx, nil, SkuCreateInput{SkuID: id, Components: &SkuComponents{SkuComponents: protoSku}, SiteID: siteId})
		require.NoError(t, err)
		require.NotNil(t, sk)
		created = append(created, *sk)
	}
	return
}

func TestSkuSQLDAO_Create(t *testing.T) {
	ctx := context.Background()
	dbSession := testSKUInitDB(t)
	defer dbSession.Close()
	testSKUSetupSchema(t, dbSession)

	// Create test dependencies
	user := TestBuildUser(t, dbSession, "test-user", "test-org", []string{"admin"})
	ip := TestBuildInfrastructureProvider(t, dbSession, "test-provider", "test-org", user)
	site := TestBuildSite(t, dbSession, ip, "test-site", user)

	ssd := NewSkuDAO(dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		inputs             []SkuCreateInput
		expectError        bool
		verifyChildSpanner bool
	}{
		{
			desc:               "create one",
			inputs:             []SkuCreateInput{{SkuID: "sku-1", Components: &SkuComponents{SkuComponents: &cwssaws.SkuComponents{}}, SiteID: site.ID}},
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc:        "create multiple",
			inputs:      []SkuCreateInput{{SkuID: "sku-2", Components: &SkuComponents{SkuComponents: &cwssaws.SkuComponents{}}, SiteID: site.ID}, {SkuID: "sku-3", Components: &SkuComponents{SkuComponents: &cwssaws.SkuComponents{}}, SiteID: site.ID}},
			expectError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			for _, input := range tc.inputs {
				got, err := ssd.Create(ctx, nil, input)
				assert.Equal(t, tc.expectError, err != nil)
				if !tc.expectError {
					assert.NotNil(t, got)
					assert.Equal(t, input.SkuID, got.ID)
					if input.Components != nil {
						assert.NotNil(t, got.Components)
					}
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

func TestSkuSQLDAO_Get(t *testing.T) {
	ctx := context.Background()
	dbSession := testSKUInitDB(t)
	defer dbSession.Close()
	testSKUSetupSchema(t, dbSession)

	// Create test dependencies
	user := TestBuildUser(t, dbSession, "test-user", "test-org", []string{"admin"})
	ip := TestBuildInfrastructureProvider(t, dbSession, "test-provider", "test-org", user)
	site := TestBuildSite(t, dbSession, ip, "test-site", user)

	created := testSkuCreateSkus(ctx, t, dbSession, site.ID)
	ssd := NewSkuDAO(dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		id                 string
		expectError        bool
		verifyChildSpanner bool
	}{
		{desc: "success existing", id: created[0].ID, verifyChildSpanner: true},
		{desc: "not found", id: "does-not-exist", expectError: true},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := ssd.Get(ctx, nil, tc.id)
			assert.Equal(t, tc.expectError, err != nil)
			if !tc.expectError {
				assert.NotNil(t, got)
				assert.Equal(t, tc.id, got.ID)
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

func TestSkuSQLDAO_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := testSKUInitDB(t)
	defer dbSession.Close()
	testSKUSetupSchema(t, dbSession)

	// Create test dependencies
	user := TestBuildUser(t, dbSession, "test-user", "test-org", []string{"admin"})
	ip := TestBuildInfrastructureProvider(t, dbSession, "test-provider", "test-org", user)
	site := TestBuildSite(t, dbSession, ip, "test-site", user)

	created := testSkuCreateSkus(ctx, t, dbSession, site.ID)
	ssd := NewSkuDAO(dbSession)

	// Populate associated machine IDs for filter testing
	_, err := ssd.Update(ctx, nil, SkuUpdateInput{SkuID: created[0].ID, AssociatedMachineIds: []string{"machine-1", "machine-2"}})
	require.NoError(t, err)
	_, err = ssd.Update(ctx, nil, SkuUpdateInput{SkuID: created[2].ID, AssociatedMachineIds: []string{"machine-2"}})
	require.NoError(t, err)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc          string
		filter        SkuFilterInput
		pageInput     paginator.PageInput
		expectedCount int
		expectedTotal *int
	}{
		{desc: "no filters", expectedCount: 3, expectedTotal: db.GetIntPtr(3)},
		{desc: "filter IDs", filter: SkuFilterInput{SkuIDs: []string{created[0].ID, created[2].ID}}, expectedCount: 2},
		{desc: "limit applies", pageInput: paginator.PageInput{Offset: db.GetIntPtr(0), Limit: db.GetIntPtr(2)}, expectedCount: 2, expectedTotal: db.GetIntPtr(3)},
		{desc: "offset applies", pageInput: paginator.PageInput{Offset: db.GetIntPtr(1)}, expectedCount: 2, expectedTotal: db.GetIntPtr(3)},
		{desc: "filter associated machine IDs", filter: SkuFilterInput{AssociatedMachineIds: []string{"machine-2"}}, expectedCount: 2},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, total, err := ssd.GetAll(ctx, nil, tc.filter, tc.pageInput)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedCount, len(got))
			if tc.expectedTotal != nil {
				assert.Equal(t, *tc.expectedTotal, total)
			}
			// tracer
			span := otrace.SpanFromContext(ctx)
			assert.True(t, span.SpanContext().IsValid())
			_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
			assert.True(t, ok)
		})
	}
}

func TestSkuSQLDAO_Update(t *testing.T) {
	ctx := context.Background()
	dbSession := testSKUInitDB(t)
	defer dbSession.Close()
	testSKUSetupSchema(t, dbSession)

	// Create test dependencies
	user := TestBuildUser(t, dbSession, "test-user", "test-org", []string{"admin"})
	ip := TestBuildInfrastructureProvider(t, dbSession, "test-provider", "test-org", user)
	site := TestBuildSite(t, dbSession, ip, "test-site", user)

	created := testSkuCreateSkus(ctx, t, dbSession, site.ID)
	ssd := NewSkuDAO(dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc  string
		input SkuUpdateInput
		check bool
	}{
		{desc: "update sku data", input: SkuUpdateInput{SkuID: created[0].ID, Components: &SkuComponents{SkuComponents: &cwssaws.SkuComponents{}}}, check: true},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := ssd.Update(ctx, nil, tc.input)
			require.NoError(t, err)
			if tc.check {
				assert.NotNil(t, got)
				assert.Equal(t, tc.input.SkuID, got.ID)
				assert.NotNil(t, got.Components)
			}
			// tracer
			span := otrace.SpanFromContext(ctx)
			assert.True(t, span.SpanContext().IsValid())
			_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
			assert.True(t, ok)
		})
	}
}

func TestSkuSQLDAO_Delete(t *testing.T) {
	ctx := context.Background()
	dbSession := testSKUInitDB(t)
	defer dbSession.Close()
	testSKUSetupSchema(t, dbSession)

	// Create test dependencies
	user := TestBuildUser(t, dbSession, "test-user", "test-org", []string{"admin"})
	ip := TestBuildInfrastructureProvider(t, dbSession, "test-provider", "test-org", user)
	site := TestBuildSite(t, dbSession, ip, "test-site", user)

	created := testSkuCreateSkus(ctx, t, dbSession, site.ID)
	ssd := NewSkuDAO(dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc      string
		id        string
		wantErr   bool
		checkGone bool
	}{
		{desc: "delete existing", id: created[1].ID, checkGone: true},
		{desc: "delete non-existing ok", id: "not-exist", wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := ssd.Delete(ctx, nil, tc.id)
			assert.Equal(t, tc.wantErr, err != nil)
			if tc.checkGone && !tc.wantErr {
				_, err := ssd.Get(ctx, nil, tc.id)
				assert.NotNil(t, err)
			}
			// tracer
			span := otrace.SpanFromContext(ctx)
			assert.True(t, span.SpanContext().IsValid())
			_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
			assert.True(t, ok)
		})
	}
}

func TestSkuSQLDAO_Create_DefaultAssociatedMachineIds(t *testing.T) {
	ctx := context.Background()
	dbSession := testSKUInitDB(t)
	defer dbSession.Close()
	testSKUSetupSchema(t, dbSession)

	// Create test dependencies
	user := TestBuildUser(t, dbSession, "test-user", "test-org", []string{"admin"})
	ip := TestBuildInfrastructureProvider(t, dbSession, "test-provider", "test-org", user)
	site := TestBuildSite(t, dbSession, ip, "test-site", user)

	ssd := NewSkuDAO(dbSession)

	// Create a SKU without specifying AssociatedMachineIds
	protoSku := &cwssaws.SkuComponents{}
	created, err := ssd.Create(ctx, nil, SkuCreateInput{
		SkuID:      "sku-default-test",
		Components: &SkuComponents{SkuComponents: protoSku},
		SiteID:     site.ID,
		// AssociatedMachineIds intentionally not set
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	// Verify the created record has an empty string array (not nil)
	assert.NotNil(t, created.AssociatedMachineIds)
	assert.Equal(t, []string{}, created.AssociatedMachineIds)

	// Read it back to ensure the default persists
	retrieved, err := ssd.Get(ctx, nil, created.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	// Verify the retrieved record also has an empty string array
	assert.NotNil(t, retrieved.AssociatedMachineIds)
	assert.Equal(t, []string{}, retrieved.AssociatedMachineIds)
}
