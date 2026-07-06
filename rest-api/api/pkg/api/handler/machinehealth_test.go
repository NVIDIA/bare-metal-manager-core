// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

func TestGetAllMachineHealthReportHandlerProxiesRequest(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, &cwssaws.ListHealthReportResponse{
		HealthReportEntries: []*cwssaws.HealthReportEntry{
			{
				Mode: cwssaws.HealthReportApplyMode_Merge,
				Report: &cwssaws.HealthReport{
					Source: "overrides.sre",
					Alerts: []*cwssaws.HealthProbeAlert{{Id: "probe.alert", Message: "forced unhealthy"}},
				},
			},
		},
	})
	handler := NewGetAllMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)

	rec := fixture.Request(t, handler.Handle, http.MethodGet, "/", nil, "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, cwssaws.Forge_ListMachineHealthReports_FullMethodName, fixture.ProxiedReq.FullMethod)
	assert.Empty(t, fixture.ProxiedReq.EncryptedSecrets)

	var coreReq cwssaws.MachineId
	require.NoError(t, protojson.Unmarshal(fixture.ProxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, fixture.MachineID, coreReq.GetId())
	assert.Contains(t, rec.Body.String(), "overrides.sre")
	assert.NotContains(t, rec.Body.String(), "password")
}

func TestGetAllMachineHealthReportHandlerAllowsPrivilegedTenant(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, &cwssaws.ListHealthReportResponse{
		HealthReportEntries: []*cwssaws.HealthReportEntry{
			{
				Mode: cwssaws.HealthReportApplyMode_Merge,
				Report: &cwssaws.HealthReport{
					Source: "overrides.sre",
					Alerts: []*cwssaws.HealthProbeAlert{{Id: "probe.alert", Message: "forced unhealthy"}},
				},
			},
		},
	})
	handler := NewGetAllMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)
	configureMachineHealthFixtureForPrivilegedTenant(t, &fixture)

	rec := fixture.Request(t, handler.Handle, http.MethodGet, "/", nil, "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, cwssaws.Forge_ListMachineHealthReports_FullMethodName, fixture.ProxiedReq.FullMethod)

	var coreReq cwssaws.MachineId
	require.NoError(t, protojson.Unmarshal(fixture.ProxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, fixture.MachineID, coreReq.GetId())
}

func TestCreateOrUpdateMachineHealthReportHandlerProxiesRequest(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewCreateOrUpdateMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)
	req := model.APIMachineHealthReportEntryRequest{
		Source:    "overrides.sre",
		Mode:      model.MachineHealthReportModeMerge,
		Successes: []model.APIMachineHealthProbeSuccess{{ID: "probe.ok"}},
	}

	rec := fixture.Request(t, handler.Handle, http.MethodPut, "/", req, "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, cwssaws.Forge_InsertMachineHealthReport_FullMethodName, fixture.ProxiedReq.FullMethod)
	assert.Empty(t, fixture.ProxiedReq.EncryptedSecrets)

	var coreReq cwssaws.InsertMachineHealthReportRequest
	require.NoError(t, protojson.Unmarshal(fixture.ProxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, fixture.MachineID, coreReq.GetMachineId().GetId())
	assert.Equal(t, "overrides.sre", coreReq.GetHealthReportEntry().GetReport().GetSource())
	assert.NotContains(t, rec.Body.String(), "password")
}

func TestCreateOrUpdateMachineHealthReportHandlerAllowsPrivilegedTenant(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewCreateOrUpdateMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)
	configureMachineHealthFixtureForPrivilegedTenant(t, &fixture)
	req := model.APIMachineHealthReportEntryRequest{
		Source:    "overrides.sre",
		Mode:      model.MachineHealthReportModeMerge,
		Successes: []model.APIMachineHealthProbeSuccess{{ID: "probe.ok"}},
	}

	rec := fixture.Request(t, handler.Handle, http.MethodPut, "/", req, "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, cwssaws.Forge_InsertMachineHealthReport_FullMethodName, fixture.ProxiedReq.FullMethod)

	var coreReq cwssaws.InsertMachineHealthReportRequest
	require.NoError(t, protojson.Unmarshal(fixture.ProxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, fixture.MachineID, coreReq.GetMachineId().GetId())
	assert.Equal(t, "overrides.sre", coreReq.GetHealthReportEntry().GetReport().GetSource())
}

func TestCreateOrUpdateMachineHealthReportHandlerRejectsInvalidRequest(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewCreateOrUpdateMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)

	rec := fixture.Request(t, handler.Handle, http.MethodPut, "/", model.APIMachineHealthReportEntryRequest{Mode: model.MachineHealthReportModeMerge}, "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, fixture.ProxiedReq.FullMethod)
}

func TestDeleteMachineHealthReportHandlerProxiesRequest(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewDeleteMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)

	rec := fixture.Request(t, handler.Handle, http.MethodDelete, "/", nil, "overrides.sre")
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, cwssaws.Forge_RemoveMachineHealthReport_FullMethodName, fixture.ProxiedReq.FullMethod)
	assert.Empty(t, fixture.ProxiedReq.EncryptedSecrets)

	var coreReq cwssaws.RemoveMachineHealthReportRequest
	require.NoError(t, protojson.Unmarshal(fixture.ProxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, fixture.MachineID, coreReq.GetMachineId().GetId())
	assert.Equal(t, "overrides.sre", coreReq.GetSource())
	assert.Empty(t, rec.Body.String())
}

func TestDeleteMachineHealthReportHandlerAllowsPrivilegedTenant(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewDeleteMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)
	configureMachineHealthFixtureForPrivilegedTenant(t, &fixture)

	rec := fixture.Request(t, handler.Handle, http.MethodDelete, "/", nil, "overrides.sre")
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, cwssaws.Forge_RemoveMachineHealthReport_FullMethodName, fixture.ProxiedReq.FullMethod)

	var coreReq cwssaws.RemoveMachineHealthReportRequest
	require.NoError(t, protojson.Unmarshal(fixture.ProxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, fixture.MachineID, coreReq.GetMachineId().GetId())
	assert.Equal(t, "overrides.sre", coreReq.GetSource())
}

func configureMachineHealthFixtureForPrivilegedTenant(t *testing.T, fixture *common.TestSetupProviderMachineHandlerFixture) {
	t.Helper()

	ctx := context.Background()
	tenantOrg := "test-tenant-org"
	tenantUser := common.TestBuildUser(t, fixture.DBSession, "test-tenant-starfleet-id", tenantOrg, []string{authz.TenantAdminRole})
	tenant := common.TestBuildTenant(t, fixture.DBSession, "test-tenant", tenantOrg, tenantUser)
	tenant, err := cdbm.NewTenantDAO(fixture.DBSession).Update(ctx, nil, cdbm.TenantUpdateInput{
		TenantID: tenant.ID,
		Config: &cdbm.TenantConfig{
			TargetedInstanceCreation: true,
		},
	})
	require.NoError(t, err)

	machine, err := cdbm.NewMachineDAO(fixture.DBSession).GetByID(ctx, nil, fixture.MachineID, []string{}, false)
	require.NoError(t, err)
	provider, err := cdbm.NewInfrastructureProviderDAO(fixture.DBSession).GetByID(ctx, nil, machine.InfrastructureProviderID, []string{})
	require.NoError(t, err)
	common.TestBuildTenantAccount(t, fixture.DBSession, provider, &tenant.ID, tenant.Org, cdbm.TenantAccountStatusReady, tenantUser)

	fixture.Org = tenantOrg
	fixture.User = tenantUser
}
