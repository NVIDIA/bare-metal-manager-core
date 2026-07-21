// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTemplatedOsEchoContext returns a bare echo.Context whose request carries a
// background context, which is all the buildInstance*OsConfig helpers require.
func newTemplatedOsEchoContext(t *testing.T) echo.Context {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = req.WithContext(context.Background())
	return e.NewContext(req, httptest.NewRecorder())
}

// assertTemplatedOsConfig asserts that a built InstanceOperatingSystemConfig
// references the Operating System by ID (the Templated iPXE variant) rather than
// carrying an inline iPXE script or an OS image reference.
func assertTemplatedOsConfig(t *testing.T, osConfig *corev1.InstanceOperatingSystemConfig, osID uuid.UUID) {
	t.Helper()
	require.NotNil(t, osConfig)
	variant, ok := osConfig.Variant.(*corev1.InstanceOperatingSystemConfig_OperatingSystemId)
	require.Truef(t, ok, "expected OperatingSystemId variant for Templated iPXE OS, got %T", osConfig.Variant)
	require.NotNil(t, variant.OperatingSystemId)
	assert.Equal(t, osID.String(), variant.OperatingSystemId.Value)
}

// TestBuildInstanceOsConfig_TemplatedIPXE verifies that a Templated iPXE
// Operating System is translated into an InstanceOperatingSystemConfig that
// references the OS by ID (corev1.InstanceOperatingSystemConfig_OperatingSystemId)
// across the create, update and batch-create instance paths, and that the shared
// templated-OS site validator rejects OSes that are not usable at the Site.
//
// Unlike raw iPXE (inline script) and Image (OS image ID) types, a Templated
// iPXE OS is rendered on the Site from its template, so only the OS ID is
// propagated to Core, and only once the definition is synchronized to that Site.
func TestBuildInstanceOsConfig_TemplatedIPXE(t *testing.T) {
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()

	common.TestSetupSchema(t, dbSession)

	cfg := common.GetTestConfig()
	logger := zerolog.Nop()

	org := "tmpl-os-instance-org"
	user := testInstanceBuildUser(t, dbSession, uuid.NewString(), org, []string{"tenant_admin"})
	tenant := testInstanceBuildTenant(t, dbSession, "tmpl-os-instance-tenant", org, user)

	ip := testMachineBuildInfrastructureProvider(t, dbSession, "tmpl-os-instance-ip-org", "tmpl-os-instance-provider")
	site := testMachineBuildSite(t, dbSession, ip, "tmpl-os-instance-site", cdbm.SiteStatusRegistered)

	// buildOS builds a tenant-owned Templated iPXE OS.
	buildOS := func(name string) *cdbm.OperatingSystem {
		return testInstanceBuildOperatingSystem(t, dbSession, name, tenant,
			cdbm.OperatingSystemTypeTemplatedIPXE, false, nil, false, cdbm.OperatingSystemStatusReady, user)
	}

	// An OS synchronized (Synced association) to the Site: the happy path.
	osSynced := buildOS("tmpl-os-instance-os-synced")
	testInstanceBuildOperatingSystemSiteAssociation(t, dbSession, site.ID, osSynced.ID)

	t.Run("create", func(t *testing.T) {
		ec := newTemplatedOsEchoContext(t)
		h := CreateInstanceHandler{dbSession: dbSession, cfg: cfg}
		apiReq := &model.APIInstanceCreateRequest{
			TenantID:          tenant.ID.String(),
			OperatingSystemID: cutil.GetPtr(osSynced.ID.String()),
		}

		osConfig, osID, apiErr := h.buildInstanceCreateRequestOsConfig(ec, &logger, apiReq, site)
		require.Nil(t, apiErr)
		require.NotNil(t, osID)
		assert.Equal(t, osSynced.ID, *osID)
		assertTemplatedOsConfig(t, osConfig, osSynced.ID)
	})

	t.Run("update", func(t *testing.T) {
		ec := newTemplatedOsEchoContext(t)
		h := UpdateInstanceHandler{dbSession: dbSession, cfg: cfg}
		// The instance is passed directly (not loaded from the DB) and only needs
		// its Tenant populated for the ownership check.
		instance := &cdbm.Instance{
			ID:       uuid.New(),
			TenantID: tenant.ID,
			Tenant:   tenant,
		}
		apiReq := &model.APIInstanceUpdateRequest{
			OperatingSystemID: cutil.GetPtr(osSynced.ID.String()),
		}

		osConfig, osID, apiErr := h.buildInstanceUpdateRequestOsConfig(ec, &logger, apiReq, instance, site)
		require.Nil(t, apiErr)
		require.NotNil(t, osID)
		assert.Equal(t, osSynced.ID, *osID)
		assertTemplatedOsConfig(t, osConfig, osSynced.ID)
	})

	t.Run("batch create", func(t *testing.T) {
		ec := newTemplatedOsEchoContext(t)
		h := BatchCreateInstanceHandler{dbSession: dbSession, cfg: cfg}
		apiReq := &model.APIBatchInstanceCreateRequest{
			TenantID:          tenant.ID.String(),
			OperatingSystemID: cutil.GetPtr(osSynced.ID.String()),
		}

		osConfig, osID, apiErr := h.buildBatchInstanceCreateRequestOsConfig(ec, &logger, apiReq, site)
		require.Nil(t, apiErr)
		require.NotNil(t, osID)
		assert.Equal(t, osSynced.ID, *osID)
		assertTemplatedOsConfig(t, osConfig, osSynced.ID)
	})

	// The following cases exercise the shared validator through the create path;
	// the same validator gates the update and batch paths.

	// Selection is gated on site availability, not on ownership: any Templated iPXE
	// OS that is present (Synced association) at its Site is a usable definition.
	t.Run("allows any templated OS synchronized to Site", func(t *testing.T) {
		osOther := buildOS("tmpl-os-instance-os-other")
		testInstanceBuildOperatingSystemSiteAssociation(t, dbSession, site.ID, osOther.ID)

		ec := newTemplatedOsEchoContext(t)
		h := CreateInstanceHandler{dbSession: dbSession, cfg: cfg}
		apiReq := &model.APIInstanceCreateRequest{
			TenantID:          tenant.ID.String(),
			OperatingSystemID: cutil.GetPtr(osOther.ID.String()),
		}

		osConfig, osID, apiErr := h.buildInstanceCreateRequestOsConfig(ec, &logger, apiReq, site)
		require.Nil(t, apiErr)
		require.NotNil(t, osID)
		assert.Equal(t, osOther.ID, *osID)
		assertTemplatedOsConfig(t, osConfig, osOther.ID)
	})

	// Only a Synced association marks a definition as available at the Site. An
	// OS with no association, or one whose association is still Syncing or has
	// Errored, must be rejected with BadRequest and no osConfig/osID.
	rejectCases := []struct {
		name   string
		status *string // nil => no association at all
	}{
		{name: "rejects templated OS not synchronized to Site", status: nil},
		{name: "rejects templated OS with Syncing association", status: cutil.GetPtr(cdbm.OperatingSystemSiteAssociationStatusSyncing)},
		{name: "rejects templated OS with Error association", status: cutil.GetPtr(cdbm.OperatingSystemSiteAssociationStatusError)},
	}
	for i, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			os := buildOS(fmt.Sprintf("tmpl-os-instance-os-reject-%d", i))
			if tc.status != nil {
				buildOperatingSystemSiteAssociationWithStatus(t, dbSession, site.ID, os.ID, *tc.status)
			}

			ec := newTemplatedOsEchoContext(t)
			h := CreateInstanceHandler{dbSession: dbSession, cfg: cfg}
			apiReq := &model.APIInstanceCreateRequest{
				TenantID:          tenant.ID.String(),
				OperatingSystemID: cutil.GetPtr(os.ID.String()),
			}

			osConfig, osID, apiErr := h.buildInstanceCreateRequestOsConfig(ec, &logger, apiReq, site)
			require.NotNil(t, apiErr)
			assert.Equal(t, http.StatusBadRequest, apiErr.Code)
			assert.Nil(t, osConfig)
			assert.Nil(t, osID)
		})
	}
}

// buildOperatingSystemSiteAssociationWithStatus inserts an
// OperatingSystemSiteAssociation with an explicit status, so tests can exercise
// non-Synced states (Syncing / Error) that the templated-OS site validator must
// reject.
func buildOperatingSystemSiteAssociationWithStatus(t *testing.T, dbSession *cdb.Session, siteID, osID uuid.UUID, status string) {
	t.Helper()
	ossa := &cdbm.OperatingSystemSiteAssociation{
		ID:                uuid.New(),
		OperatingSystemID: osID,
		SiteID:            siteID,
		Version:           cutil.GetPtr("1234"),
		Status:            status,
		Created:           cdb.GetCurTime(),
		Updated:           cdb.GetCurTime(),
	}
	_, err := dbSession.DB.NewInsert().Model(ossa).Exec(context.Background())
	require.NoError(t, err)
}
