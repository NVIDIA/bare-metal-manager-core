// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	authz "github.com/NVIDIA/infra-controller-rest/auth/pkg/authorization"
	cauth "github.com/NVIDIA/infra-controller-rest/auth/pkg/config"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountHandler_GetCurrent(t *testing.T) {
	ctx := context.Background()

	// Initialize test database
	dbSession := common.TestInitDB(t)
	defer dbSession.Close()

	common.TestSetupSchema(t, dbSession)

	org1 := "test-org"
	user1 := common.TestBuildUser(t, dbSession, uuid.NewString(), org1, []string{authz.ProviderAdminRole, authz.TenantAdminRole})

	org2 := "test-org-2"
	user2 := common.TestBuildUser(t, dbSession, uuid.NewString(), org2, []string{authz.ProviderAdminRole, authz.TenantAdminRole})

	ip2 := common.TestBuildInfrastructureProvider(t, dbSession, "test-provider-2", org2, user2)
	tn2 := common.TestBuildTenant(t, dbSession, "test-tenant-2", org2, user2)
	_ = common.TestBuildTenantAccount(t, dbSession, ip2, &tn2.ID, org2, cdbm.TenantAccountStatusReady, user2)

	org3 := "test-org-3"
	user3 := common.TestBuildUser(t, dbSession, uuid.NewString(), org3, []string{authz.TenantAdminRole})

	tests := []struct {
		name                  string
		org                   string
		user                  *cdbm.User
		serviceAccountEnabled bool
	}{
		{
			name:                  "test get current ServiceAccount when service account is enabled and org doesn't have Provider/Tenant/TenantAccount",
			org:                   org1,
			user:                  user1,
			serviceAccountEnabled: true,
		},
		{
			name:                  "test get current ServiceAccount when service account is enabled and org has Provider/Tenant/TenantAccount",
			org:                   org2,
			user:                  user2,
			serviceAccountEnabled: true,
		},
		{
			name:                  "test get current ServiceAccount when service account is disabled",
			org:                   org3,
			user:                  user3,
			serviceAccountEnabled: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Setup echo server/context
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/service-account/current", nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(test.org)
			ec.Set("user", test.user)

			ec.SetRequest(ec.Request().WithContext(ctx))

			// Normally, the auth processor records the service-account flag on the request
			// context based on the type of issuer/Origin/claimMappings, but in this test we
			// set it manually for testing purposes.
			cauth.SetIsServiceAccountInContext(ec, test.serviceAccountEnabled)

			handler := GetCurrentServiceAccountHandler{
				dbSession: dbSession,
			}

			err := handler.Handle(ec)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, rec.Code)

			sa := &model.APIServiceAccount{}
			err = json.Unmarshal(rec.Body.Bytes(), sa)
			require.NoError(t, err)

			assert.Equal(t, test.serviceAccountEnabled, sa.Enabled)

			if test.serviceAccountEnabled {
				assert.NotNil(t, sa.InfrastructureProviderID)
				assert.NotNil(t, sa.TenantID)
			} else {
				assert.Nil(t, sa.InfrastructureProviderID)
				assert.Nil(t, sa.TenantID)
			}
		})
	}
}
