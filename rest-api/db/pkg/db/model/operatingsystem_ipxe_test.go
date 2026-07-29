// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"testing"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOperatingSystemSQLDAO_TemplatedIPXERoundTrip exercises the iPXE template definition
// columns added for the Templated iPXE OS variant: create, read-back of the JSONB
// parameter/artifact slices, artifact update, and iPXE definition clear.
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
		IpxeOSHash: cutil.GetPtr("hash-1"),
		Status:     OperatingSystemStatusPending,
		CreatedBy:  user.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	got, err := dao.GetByID(ctx, nil, created.ID, nil)
	require.NoError(t, err)
	assert.Equal(t, OperatingSystemTypeTemplatedIPXE, got.Type)
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

	// Update artifacts.
	updated, err := dao.Update(ctx, nil, OperatingSystemUpdateInput{
		OperatingSystemId: created.ID,
		IpxeTemplateArtifacts: &[]OperatingSystemIpxeArtifact{
			{Name: "initrd", URL: "https://example.test/initrd", CacheStrategy: OperatingSystemIpxeArtifactCacheStrategyCachedOnly},
		},
	})
	require.NoError(t, err)
	require.Len(t, updated.IpxeTemplateArtifacts, 1)
	assert.Equal(t, "initrd", updated.IpxeTemplateArtifacts[0].Name)
	assert.Equal(t, OperatingSystemIpxeArtifactCacheStrategyCachedOnly, updated.IpxeTemplateArtifacts[0].CacheStrategy)

	// Clear the iPXE definition.
	cleared, err := dao.Clear(ctx, nil, OperatingSystemClearInput{
		OperatingSystemId:      created.ID,
		IpxeTemplateId:         true,
		IpxeTemplateParameters: true,
		IpxeTemplateArtifacts:  true,
		IpxeOSHash:             true,
	})
	require.NoError(t, err)
	assert.Nil(t, cleared.IpxeTemplateId)
	assert.Nil(t, cleared.IpxeTemplateParameters)
	assert.Nil(t, cleared.IpxeTemplateArtifacts)
	assert.Nil(t, cleared.IpxeTemplateDefinitionHash)
}
