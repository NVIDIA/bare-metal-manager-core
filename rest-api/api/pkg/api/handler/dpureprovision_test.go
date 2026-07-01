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
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

func TestDpuReprovisionHandlerProxiesRequest(t *testing.T) {
	fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
	handler := NewDpuReprovisionHandler(fixture.DBSession, fixture.SiteClientPool, fixture.Config)

	rec := fixture.Request(t, handler.Handle, http.MethodPatch, "/", model.APIDpuReprovisionRequest{Mode: model.DpuReprovisionModeRestart, UpdateFirmware: true}, "")
	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, cwssaws.Forge_TriggerDpuReprovisioning_FullMethodName, fixture.ProxiedReq.FullMethod)
	assert.Empty(t, fixture.ProxiedReq.EncryptedSecrets)

	var coreReq cwssaws.DpuReprovisioningRequest
	require.NoError(t, protojson.Unmarshal(fixture.ProxiedReq.RequestJSON, &coreReq))
	assert.Equal(t, fixture.MachineID, coreReq.GetMachineId().GetId())
	assert.Equal(t, cwssaws.DpuReprovisioningRequest_Restart, coreReq.GetMode())
	assert.Equal(t, cwssaws.UpdateInitiator_AdminCli, coreReq.GetInitiator())
	assert.True(t, coreReq.GetUpdateFirmware())
	var resp model.APIMessageResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "DPU reprovisioning request was accepted", resp.Message)
}
