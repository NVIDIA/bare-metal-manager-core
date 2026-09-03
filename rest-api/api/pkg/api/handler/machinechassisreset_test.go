// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

func TestResetMachineChassisHandler_Handle(t *testing.T) {
	tests := []struct {
		name       string
		chassisID  string
		setup      func(*testing.T, *common.TestSetupProviderMachineHandlerFixture)
		wantStatus int
	}{
		{
			name:       "queues reset",
			chassisID:  "Chassis_0",
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "rejects missing chassis ID",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejects invalid chassis ID",
			chassisID:  "../Chassis 0",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:      "requires Provider Admin",
			chassisID: "Chassis_0",
			setup: func(_ *testing.T, fixture *common.TestSetupProviderMachineHandlerFixture) {
				fixture.User = &cdbm.User{OrgData: cdbm.OrgData{fixture.Org: cdbm.Org{
					Name:  fixture.Org,
					Roles: []string{authz.ProviderViewerRole},
				}}}
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:      "rejects assigned Machine",
			chassisID: "Chassis_0",
			setup: func(t *testing.T, fixture *common.TestSetupProviderMachineHandlerFixture) {
				isAssigned := true
				_, err := cdbm.NewMachineDAO(fixture.DBSession).Update(context.Background(), nil, cdbm.MachineUpdateInput{
					MachineID:  fixture.MachineID,
					IsAssigned: &isAssigned,
				})
				require.NoError(t, err)
			},
			wantStatus: http.StatusPreconditionFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := common.NewTestSetupProviderMachineHandlerFixture(t, nil)
			handler := NewResetMachineChassisHandler(fixture.DBSession, fixture.SiteClientPool)
			if tt.setup != nil {
				tt.setup(t, &fixture)
			}

			rec := fixture.Request(t, handler.Handle, http.MethodPatch, "/?chassisId="+url.QueryEscape(tt.chassisID), nil, "")
			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantStatus != http.StatusAccepted {
				assert.Empty(t, fixture.ProxiedReq.FullMethod)
				return
			}

			assert.Equal(t, corev1.Forge_AdminChassisReset_FullMethodName, fixture.ProxiedReq.FullMethod)
			assert.Empty(t, fixture.ProxiedReq.EncryptedSecrets)
			var coreRequest corev1.AdminChassisResetRequest
			require.NoError(t, protojson.Unmarshal(fixture.ProxiedReq.RequestJSON, &coreRequest))
			assert.Equal(t, fixture.MachineID, coreRequest.GetMachineId().GetId())
			assert.Equal(t, tt.chassisID, coreRequest.GetChassisId())

			var response model.APIMessageResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
			assert.Equal(t, "Machine chassis reset request was accepted", response.Message)
		})
	}
}
