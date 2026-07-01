// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

func TestListMachineHealthReportHandlerProxiesRequest(t *testing.T) {
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
	handler := NewListMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)

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

func TestInsertMachineHealthReportHandlerProxiesRequest(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewInsertMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)
	req := model.APIMachineHealthReportEntry{
		Source: "overrides.sre",
		Mode:   model.MachineHealthReportModeMerge,
		Alerts: []model.APIMachineHealthProbeAlert{{ID: "probe.alert", Message: "forced unhealthy"}},
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

func TestInsertMachineHealthReportHandlerRejectsInvalidRequest(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewInsertMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)

	rec := fixture.Request(t, handler.Handle, http.MethodPut, "/", model.APIMachineHealthReportEntry{Mode: model.MachineHealthReportModeMerge}, "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, fixture.ProxiedReq.FullMethod)
}

func TestRemoveMachineHealthReportHandlerProxiesRequest(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewRemoveMachineHealthReportHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)

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
