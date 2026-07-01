// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

func TestBmcResetHandlerProxiesRequest(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, &cwssaws.AdminBmcResetResponse{})
	handler := NewBmcResetHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)

	rec := fixture.Request(t, handler.Handle, http.MethodPost, "/", model.APIBmcResetRequest{UseIpmiTool: cutil.GetPtr(true)}, "")
	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, cwssaws.Forge_AdminBmcReset_FullMethodName, fixture.ProxiedReq.FullMethod)
	assert.Empty(t, fixture.ProxiedReq.EncryptedSecrets)

	var coreReq cwssaws.AdminBmcResetRequest
	require.NoError(t, protojson.Unmarshal(fixture.ProxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, fixture.MachineID, coreReq.GetMachineId())
	assert.True(t, coreReq.GetUseIpmitool())
	var resp model.APIMessageResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "Machine BMC reset request was accepted", resp.Message)
	assert.NotContains(t, rec.Body.String(), "password")
}

func TestBmcResetHandlerRequiresRequestBody(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewBmcResetHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)

	rec := fixture.Request(t, handler.Handle, http.MethodPost, "/", nil, "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, fixture.ProxiedReq.FullMethod)
}
