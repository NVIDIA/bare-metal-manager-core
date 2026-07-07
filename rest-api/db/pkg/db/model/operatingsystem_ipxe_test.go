// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"testing"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOperatingSystemSQLDAO_TemplatedIPXERoundTrip exercises the iPXE template definition
// columns and the ipxe_os_scope column added for the Templated iPXE OS variant: create,
// read-back of the JSONB parameter/artifact slices, scope update, and scope/iPXE clear.
func TestOperatingSystemSQLDAO_TemplatedIPXERoundTrip(t *testing.T) {
	ctx := context.Background()
	dbSession := testOperatingSystemInitDB(t)
	defer dbSession.Close()
	testOperatingSystemSetupSchema(t, dbSession)

	tenant := testOperatingSystemBuildTenant(t, dbSession, "testTenant")
	user := testOperatingSystemBuildUser(t, dbSession, "testUser")

	dao := NewOperatingSystemDAO(dbSession)

	templateID := uuid.New().String()
	created, err := dao.Create(ctx, nil, OperatingSystemCreateInput{
		Name:           "templated-ipxe-os",
		Org:            "test",
		TenantID:       &tenant.ID,
		OsType:         OperatingSystemTypeTemplatedIPXE,
		IpxeTemplateId: &templateID,
		IpxeTemplateParameters: []OperatingSystemIpxeParameter{
			{Name: "kernel_params", Value: "quiet"},
		},
		IpxeTemplateArtifacts: []OperatingSystemIpxeArtifact{
			{
				Name:          "kernel",
				URL:           "https://example.test/kernel",
				AuthToken:     cutil.GetPtr("secret-token"),
				CacheStrategy: OperatingSystemIpxeArtifactCacheStrategyCacheAsNeeded,
			},
		},
		IpxeOSHash:  cutil.GetPtr("hash-1"),
		IpxeOsScope: cutil.GetPtr(OperatingSystemScopeGlobal),
		Status:      OperatingSystemStatusPending,
		CreatedBy:   user.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	got, err := dao.GetByID(ctx, nil, created.ID, nil)
	require.NoError(t, err)
	assert.Equal(t, OperatingSystemTypeTemplatedIPXE, got.Type)
	require.NotNil(t, got.IpxeOsScope)
	assert.Equal(t, OperatingSystemScopeGlobal, *got.IpxeOsScope)
	require.NotNil(t, got.IpxeTemplateId)
	assert.Equal(t, templateID, *got.IpxeTemplateId)
	require.NotNil(t, got.IpxeTemplateDefinitionHash)
	assert.Equal(t, "hash-1", *got.IpxeTemplateDefinitionHash)

	require.Len(t, got.IpxeTemplateParameters, 1)
	assert.Equal(t, "kernel_params", got.IpxeTemplateParameters[0].Name)
	assert.Equal(t, "quiet", got.IpxeTemplateParameters[0].Value)

	require.Len(t, got.IpxeTemplateArtifacts, 1)
	assert.Equal(t, "kernel", got.IpxeTemplateArtifacts[0].Name)
	require.NotNil(t, got.IpxeTemplateArtifacts[0].AuthToken)
	assert.Equal(t, "secret-token", *got.IpxeTemplateArtifacts[0].AuthToken)
	assert.Equal(t, OperatingSystemIpxeArtifactCacheStrategyCacheAsNeeded, got.IpxeTemplateArtifacts[0].CacheStrategy)

	// Update scope and artifacts.
	updated, err := dao.Update(ctx, nil, OperatingSystemUpdateInput{
		OperatingSystemId: created.ID,
		Scope:             cutil.GetPtr(OperatingSystemScopeLimited),
		IpxeTemplateArtifacts: &[]OperatingSystemIpxeArtifact{
			{Name: "initrd", URL: "https://example.test/initrd", CacheStrategy: OperatingSystemIpxeArtifactCacheStrategyCachedOnly},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, updated.IpxeOsScope)
	assert.Equal(t, OperatingSystemScopeLimited, *updated.IpxeOsScope)
	require.Len(t, updated.IpxeTemplateArtifacts, 1)
	assert.Equal(t, "initrd", updated.IpxeTemplateArtifacts[0].Name)
	assert.Equal(t, OperatingSystemIpxeArtifactCacheStrategyCachedOnly, updated.IpxeTemplateArtifacts[0].CacheStrategy)

	// Clear the iPXE definition and scope.
	cleared, err := dao.Clear(ctx, nil, OperatingSystemClearInput{
		OperatingSystemId:      created.ID,
		IpxeTemplateId:         true,
		IpxeTemplateParameters: true,
		IpxeTemplateArtifacts:  true,
		IpxeOSHash:             true,
		Scope:                  true,
	})
	require.NoError(t, err)
	assert.Nil(t, cleared.IpxeOsScope)
	assert.Nil(t, cleared.IpxeTemplateId)
	assert.Nil(t, cleared.IpxeTemplateParameters)
	assert.Nil(t, cleared.IpxeTemplateArtifacts)
	assert.Nil(t, cleared.IpxeTemplateDefinitionHash)
}

// TestOperatingSystemSQLDAO_ScopeFilter verifies the Scopes filter only matches iPXE OS rows
// and never coerces Image rows (NULL scope) into the "Local" bucket.
func TestOperatingSystemSQLDAO_ScopeFilter(t *testing.T) {
	ctx := context.Background()
	dbSession := testOperatingSystemInitDB(t)
	defer dbSession.Close()
	testOperatingSystemSetupSchema(t, dbSession)

	ip := testOperatingSystemBuildInfrastructureProvider(t, dbSession, "testIP")
	tenant := testOperatingSystemBuildTenant(t, dbSession, "testTenant")
	user := testOperatingSystemBuildUser(t, dbSession, "testUser")

	dao := NewOperatingSystemDAO(dbSession)

	// Global-scoped Templated iPXE OS.
	_, err := dao.Create(ctx, nil, OperatingSystemCreateInput{
		Name: "global-ipxe", Org: "test", TenantID: &tenant.ID,
		OsType: OperatingSystemTypeTemplatedIPXE, IpxeOsScope: cutil.GetPtr(OperatingSystemScopeGlobal),
		Status: OperatingSystemStatusReady, CreatedBy: user.ID,
	})
	require.NoError(t, err)

	// Raw iPXE OS with no explicit scope (treated as Local via COALESCE).
	_, err = dao.Create(ctx, nil, OperatingSystemCreateInput{
		Name: "local-ipxe", Org: "test", TenantID: &tenant.ID,
		OsType: OperatingSystemTypeIPXE,
		Status: OperatingSystemStatusReady, CreatedBy: user.ID,
	})
	require.NoError(t, err)

	// Image OS: scope does not apply (NULL scope) and must never match a scope filter.
	_ = testBuildImageOperatingSystem(t, dbSession, "image-os", cutil.GetPtr("img"), "test", &ip.ID, &tenant.ID, nil, false, OperatingSystemStatusReady, user.ID)

	globalRows, _, err := dao.GetAll(ctx, nil, OperatingSystemFilterInput{Scopes: []string{OperatingSystemScopeGlobal}}, paginator.PageInput{}, nil)
	require.NoError(t, err)
	assert.Len(t, globalRows, 1)
	assert.Equal(t, "global-ipxe", globalRows[0].Name)

	localRows, _, err := dao.GetAll(ctx, nil, OperatingSystemFilterInput{Scopes: []string{OperatingSystemScopeLocal}}, paginator.PageInput{}, nil)
	require.NoError(t, err)
	assert.Len(t, localRows, 1)
	assert.Equal(t, "local-ipxe", localRows[0].Name)
}
