/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handler

import (
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbu "github.com/NVIDIA/infra-controller/rest-api/db/pkg/util"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun/extra/bundebug"
)

func testIpxeTemplateInitDB(t *testing.T) *cdb.Session {
	dbSession := cdbu.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("BUNDEBUG"),
	))
	return dbSession
}

func testIpxeTemplateHandlerSetupSchema(t *testing.T, dbSession *cdb.Session) {
	ctx := context.Background()

	// Reset parent tables before any table whose CREATE references them via
	// foreign keys. Order: providers first, then sites/tenants, then the
	// global ipxe_template table, then the association tables that reference
	// ipxe_template/site/tenant.
	assert.Nil(t, dbSession.DB.ResetModel(ctx, (*cdbm.InfrastructureProvider)(nil)))
	assert.Nil(t, dbSession.DB.ResetModel(ctx, (*cdbm.Site)(nil)))
	assert.Nil(t, dbSession.DB.ResetModel(ctx, (*cdbm.Tenant)(nil)))
	assert.Nil(t, dbSession.DB.ResetModel(ctx, (*cdbm.IpxeTemplate)(nil)))
	assert.Nil(t, dbSession.DB.ResetModel(ctx, (*cdbm.IpxeTemplateSiteAssociation)(nil)))
	assert.Nil(t, dbSession.DB.ResetModel(ctx, (*cdbm.TenantSite)(nil)))
}

type ipxeTemplateTestFixture struct {
	ip    *cdbm.InfrastructureProvider
	site  *cdbm.Site
	tmpl1 *cdbm.IpxeTemplate
	tmpl2 *cdbm.IpxeTemplate
}

// associateTemplate creates an IpxeTemplateSiteAssociation row linking the
// global template to the given site.
func associateTemplate(t *testing.T, dbSession *cdb.Session, templateID, siteID uuid.UUID) {
	itsaDAO := cdbm.NewIpxeTemplateSiteAssociationDAO(dbSession)
	_, err := itsaDAO.Create(context.Background(), nil, cdbm.IpxeTemplateSiteAssociationCreateInput{
		IpxeTemplateID: templateID,
		SiteID:         siteID,
	})
	assert.Nil(t, err)
}

func testIpxeTemplateSetupTestData(t *testing.T, dbSession *cdb.Session, org string) *ipxeTemplateTestFixture {
	ctx := context.Background()

	ip := &cdbm.InfrastructureProvider{
		ID:   uuid.New(),
		Name: "test-provider",
		Org:  org,
	}
	_, err := dbSession.DB.NewInsert().Model(ip).Exec(ctx)
	assert.Nil(t, err)

	site := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-site",
		Org:                      org,
		InfrastructureProviderID: ip.ID,
		Status:                   cdbm.SiteStatusRegistered,
	}
	_, err = dbSession.DB.NewInsert().Model(site).Exec(ctx)
	assert.Nil(t, err)

	dao := cdbm.NewIpxeTemplateDAO(dbSession)

	tmpl1, err := dao.Create(ctx, nil, cdbm.IpxeTemplateCreateInput{
		ID: uuid.New(), Name: "kernel-initrd", Scope: cdbm.IpxeTemplateScopePublic,
		RequiredParams: []string{"kernel_params"}, ReservedParams: []string{"base_url"}, RequiredArtifacts: []string{"kernel"},
	})
	assert.Nil(t, err)
	associateTemplate(t, dbSession, tmpl1.ID, site.ID)

	tmpl2, err := dao.Create(ctx, nil, cdbm.IpxeTemplateCreateInput{
		ID: uuid.New(), Name: "ubuntu-autoinstall", Scope: cdbm.IpxeTemplateScopePublic,
		RequiredParams: []string{}, ReservedParams: []string{}, RequiredArtifacts: []string{"iso"},
	})
	assert.Nil(t, err)
	associateTemplate(t, dbSession, tmpl2.ID, site.ID)

	return &ipxeTemplateTestFixture{ip: ip, site: site, tmpl1: tmpl1, tmpl2: tmpl2}
}

func createIpxeTemplateMockUser(org string) *cdbm.User {
	return &cdbm.User{
		StarfleetID: cutil.GetPtr("test-user"),
		OrgData: cdbm.OrgData{
			org: cdbm.Org{
				ID:          123,
				Name:        org,
				DisplayName: org,
				OrgType:     "ENTERPRISE",
				Roles:       []string{"FORGE_PROVIDER_VIEWER"},
			},
		},
	}
}

func createIpxeTemplateTenantMockUser(org string) *cdbm.User {
	return &cdbm.User{
		StarfleetID: cutil.GetPtr("test-tenant-user"),
		OrgData: cdbm.OrgData{
			org: cdbm.Org{
				ID:          456,
				Name:        org,
				DisplayName: org,
				OrgType:     "ENTERPRISE",
				Roles:       []string{"FORGE_TENANT_ADMIN"},
			},
		},
	}
}

func createIpxeTemplateMixedRoleMockUser(org string) *cdbm.User {
	return &cdbm.User{
		StarfleetID: cutil.GetPtr("test-mixed-user"),
		OrgData: cdbm.OrgData{
			org: cdbm.Org{
				ID:          789,
				Name:        org,
				DisplayName: org,
				OrgType:     "ENTERPRISE",
				Roles:       []string{"FORGE_PROVIDER_VIEWER", "FORGE_TENANT_ADMIN"},
			},
		},
	}
}

func TestGetAllIpxeTemplateHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testIpxeTemplateInitDB(t)
	defer dbSession.Close()

	testIpxeTemplateHandlerSetupSchema(t, dbSession)

	ctx := context.Background()
	cfg := &config.Config{}
	handler := NewGetAllIpxeTemplateHandler(dbSession, nil, cfg)

	org := "test-org"
	fix := testIpxeTemplateSetupTestData(t, dbSession, org)

	// Unmanaged site in a different org
	unmanagedIP := &cdbm.InfrastructureProvider{ID: uuid.New(), Name: "unmanaged-provider", Org: "other-org"}
	_, err := dbSession.DB.NewInsert().Model(unmanagedIP).Exec(ctx)
	assert.Nil(t, err)

	unmanagedSite := &cdbm.Site{ID: uuid.New(), Name: "unmanaged-site", Org: "other-org", InfrastructureProviderID: unmanagedIP.ID, Status: cdbm.SiteStatusRegistered}
	_, err = dbSession.DB.NewInsert().Model(unmanagedSite).Exec(ctx)
	assert.Nil(t, err)

	// Second provider-owned site with its own template, to exercise the
	// "omitted siteId", multi-siteId, and per-site tenant-association paths.
	site2 := &cdbm.Site{ID: uuid.New(), Name: "test-site-2", Org: org, InfrastructureProviderID: fix.ip.ID, Status: cdbm.SiteStatusRegistered}
	_, err = dbSession.DB.NewInsert().Model(site2).Exec(ctx)
	assert.Nil(t, err)

	tmpl3, err := cdbm.NewIpxeTemplateDAO(dbSession).Create(ctx, nil, cdbm.IpxeTemplateCreateInput{
		ID: uuid.New(), Name: "site2-public", Scope: cdbm.IpxeTemplateScopePublic,
	})
	assert.Nil(t, err)
	associateTemplate(t, dbSession, tmpl3.ID, site2.ID)

	// Tenant with a TenantSite association to fix.site only (not site2).
	tenantOrg := "test-tenant-org"
	tenantWithCapability := &cdbm.Tenant{ID: uuid.New(), Name: "test-tenant", Org: tenantOrg, Config: &cdbm.TenantConfig{TargetedInstanceCreation: true}}
	_, err = dbSession.DB.NewInsert().Model(tenantWithCapability).Exec(ctx)
	assert.Nil(t, err)

	tenantSite := &cdbm.TenantSite{ID: uuid.New(), TenantID: tenantWithCapability.ID, TenantOrg: tenantOrg, SiteID: fix.site.ID}
	_, err = dbSession.DB.NewInsert().Model(tenantSite).Exec(ctx)
	assert.Nil(t, err)

	// Non-privileged tenant WITH a TenantSite association — should still succeed.
	tenantOrgNonPriv := "test-tenant-non-priv"
	tenantNonPriv := &cdbm.Tenant{ID: uuid.New(), Name: "non-priv-tenant", Org: tenantOrgNonPriv, Config: &cdbm.TenantConfig{TargetedInstanceCreation: false}}
	_, err = dbSession.DB.NewInsert().Model(tenantNonPriv).Exec(ctx)
	assert.Nil(t, err)

	tenantSiteNonPriv := &cdbm.TenantSite{ID: uuid.New(), TenantID: tenantNonPriv.ID, TenantOrg: tenantOrgNonPriv, SiteID: fix.site.ID}
	_, err = dbSession.DB.NewInsert().Model(tenantSiteNonPriv).Exec(ctx)
	assert.Nil(t, err)

	// Tenant with TenantSite to fix.site AND site2.
	tenantOrgTwoSites := "test-tenant-two-sites"
	tenantTwoSites := &cdbm.Tenant{ID: uuid.New(), Name: "two-sites-tenant", Org: tenantOrgTwoSites, Config: &cdbm.TenantConfig{}}
	_, err = dbSession.DB.NewInsert().Model(tenantTwoSites).Exec(ctx)
	assert.Nil(t, err)

	tenantSiteTwoA := &cdbm.TenantSite{ID: uuid.New(), TenantID: tenantTwoSites.ID, TenantOrg: tenantOrgTwoSites, SiteID: fix.site.ID}
	_, err = dbSession.DB.NewInsert().Model(tenantSiteTwoA).Exec(ctx)
	assert.Nil(t, err)

	tenantSiteTwoB := &cdbm.TenantSite{ID: uuid.New(), TenantID: tenantTwoSites.ID, TenantOrg: tenantOrgTwoSites, SiteID: site2.ID}
	_, err = dbSession.DB.NewInsert().Model(tenantSiteTwoB).Exec(ctx)
	assert.Nil(t, err)

	// Tenant without any TenantSite association.
	tenantOrgNoCapability := "test-tenant-no-capability"
	tenantWithoutCapability := &cdbm.Tenant{ID: uuid.New(), Name: "no-cap-tenant", Org: tenantOrgNoCapability, Config: &cdbm.TenantConfig{TargetedInstanceCreation: false}}
	_, err = dbSession.DB.NewInsert().Model(tenantWithoutCapability).Exec(ctx)
	assert.Nil(t, err)

	tenantOrgNoAccount := "test-tenant-no-site"
	tenantWithoutAccount := &cdbm.Tenant{ID: uuid.New(), Name: "no-site-tenant", Org: tenantOrgNoAccount, Config: &cdbm.TenantConfig{TargetedInstanceCreation: true}}
	_, err = dbSession.DB.NewInsert().Model(tenantWithoutAccount).Exec(ctx)
	assert.Nil(t, err)

	// Mixed-role org.
	mixedOrg := "mixed-role-org"
	mixedIP := &cdbm.InfrastructureProvider{ID: uuid.New(), Name: "mixed-provider", Org: mixedOrg}
	_, err = dbSession.DB.NewInsert().Model(mixedIP).Exec(ctx)
	assert.Nil(t, err)

	mixedTenant := &cdbm.Tenant{ID: uuid.New(), Name: "mixed-tenant", Org: mixedOrg, Config: &cdbm.TenantConfig{}}
	_, err = dbSession.DB.NewInsert().Model(mixedTenant).Exec(ctx)
	assert.Nil(t, err)

	mixedTenantSite := &cdbm.TenantSite{ID: uuid.New(), TenantID: mixedTenant.ID, TenantOrg: mixedOrg, SiteID: fix.site.ID}
	_, err = dbSession.DB.NewInsert().Model(mixedTenantSite).Exec(ctx)
	assert.Nil(t, err)

	_ = fix.tmpl1
	_ = fix.tmpl2
	_ = tmpl3
	_ = tenantSite
	_ = tenantSiteNonPriv
	_ = tenantWithoutCapability
	_ = tenantWithoutAccount

	tests := []struct {
		name                 string
		siteIDs              []string
		setupContext         func(c echo.Context)
		expectedStatus       int
		checkResponseContent func(t *testing.T, body []byte)
	}{
		{
			name:    "omitted siteId returns all templates available at provider's sites",
			siteIDs: nil,
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []*model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				// tmpl1, tmpl2 on fix.site + tmpl3 on site2.
				assert.Len(t, response, 3)
			},
		},
		{
			name:    "omitted siteId for tenant returns templates for tenant-accessible sites",
			siteIDs: nil,
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrg))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrg)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []*model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				// tenantOrg has a TenantSite on fix.site only, so only tmpl1 and
				// tmpl2 are visible.
				assert.Len(t, response, 2)
			},
		},
		{
			name:    "multiple siteIds filters by the union",
			siteIDs: []string{fix.site.ID.String(), site2.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []*model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				assert.Len(t, response, 3)
			},
		},
		{
			name:    "multiple siteIds with one unauthorized returns 403",
			siteIDs: []string{fix.site.ID.String(), unmanagedSite.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:    "invalid siteId returns 400",
			siteIDs: []string{"not-a-uuid"},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "successful GetAll with valid siteId",
			siteIDs: []string{fix.site.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []*model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				assert.Len(t, response, 2)
				ids := map[string]bool{}
				for _, tmpl := range response {
					ids[tmpl.ID] = true
				}
				assert.True(t, ids[fix.tmpl1.ID.String()])
				assert.True(t, ids[fix.tmpl2.ID.String()])
			},
		},
		{
			name:    "cannot retrieve from unmanaged site",
			siteIDs: []string{unmanagedSite.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:    "missing user context returns 500",
			siteIDs: nil,
			setupContext: func(c echo.Context) {
				c.SetParamNames("orgName")
				c.SetParamValues(org)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:    "tenant with TenantSite can retrieve templates for that site",
			siteIDs: []string{fix.site.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrg))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrg)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []*model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				assert.Len(t, response, 2)
			},
		},
		{
			name:    "non-privileged tenant with TenantSite can retrieve templates",
			siteIDs: []string{fix.site.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrgNonPriv))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrgNonPriv)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []*model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				assert.Len(t, response, 2)
			},
		},
		{
			name:    "tenant without TenantSite is denied",
			siteIDs: []string{fix.site.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrgNoCapability))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrgNoCapability)
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:    "tenant without TenantSite cannot access provider site",
			siteIDs: []string{fix.site.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrgNoAccount))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrgNoAccount)
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:    "mixed-role user fails provider check but passes tenant authorization",
			siteIDs: []string{fix.site.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMixedRoleMockUser(mixedOrg))
				c.SetParamNames("orgName")
				c.SetParamValues(mixedOrg)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []*model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				assert.Len(t, response, 2)
			},
		},
		{
			name:    "tenant associated with one site cannot access sibling site on same provider",
			siteIDs: []string{site2.ID.String()},
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrg))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrg)
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:    "tenant with TenantSite on multiple sites sees templates on each",
			siteIDs: nil,
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrgTwoSites))
				c.SetParamNames("orgName")
				c.SetParamValues(tenantOrgTwoSites)
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response []*model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				// tmpl1 and tmpl2 on fix.site + tmpl3 on site2 = 3 templates.
				assert.Len(t, response, 3)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/v2/org/" + org + "/nico/ipxe-template"
			params := []string{}
			for _, sid := range tt.siteIDs {
				params = append(params, "siteId="+sid)
			}
			if len(params) > 0 {
				url += "?" + params[0]
				for _, p := range params[1:] {
					url += "&" + p
				}
			}

			req := httptest.NewRequest(http.MethodGet, url, nil)
			req = req.WithContext(context.Background())
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			tt.setupContext(c)

			err := handler.Handle(c)
			assert.Nil(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != rec.Code {
				t.Errorf("Response: %v", rec.Body.String())
			}
			if tt.checkResponseContent != nil && rec.Code == http.StatusOK {
				tt.checkResponseContent(t, rec.Body.Bytes())
			}
		})
	}
}

func TestGetIpxeTemplateHandler_Handle(t *testing.T) {
	e := echo.New()
	dbSession := testIpxeTemplateInitDB(t)
	defer dbSession.Close()

	testIpxeTemplateHandlerSetupSchema(t, dbSession)

	ctx := context.Background()
	cfg := &config.Config{}
	handler := NewGetIpxeTemplateHandler(dbSession, nil, cfg)

	org := "test-org"
	fix := testIpxeTemplateSetupTestData(t, dbSession, org)

	// Unmanaged site in a different org
	unmanagedIP := &cdbm.InfrastructureProvider{ID: uuid.New(), Name: "unmanaged-provider-get", Org: "other-org"}
	_, err := dbSession.DB.NewInsert().Model(unmanagedIP).Exec(ctx)
	assert.Nil(t, err)

	unmanagedSite := &cdbm.Site{ID: uuid.New(), Name: "unmanaged-site-get", Org: "other-org", InfrastructureProviderID: unmanagedIP.ID, Status: cdbm.SiteStatusRegistered}
	_, err = dbSession.DB.NewInsert().Model(unmanagedSite).Exec(ctx)
	assert.Nil(t, err)

	unmanagedTmpl, err := cdbm.NewIpxeTemplateDAO(dbSession).Create(ctx, nil, cdbm.IpxeTemplateCreateInput{
		ID: uuid.New(), Name: "unmanaged-tmpl", Scope: cdbm.IpxeTemplateScopePublic,
	})
	assert.Nil(t, err)
	associateTemplate(t, dbSession, unmanagedTmpl.ID, unmanagedSite.ID)

	// Tenant with a TenantSite association to fix.site.
	tenantOrg := "test-tenant-org"
	tenantWithCapability := &cdbm.Tenant{ID: uuid.New(), Name: "test-tenant", Org: tenantOrg, Config: &cdbm.TenantConfig{TargetedInstanceCreation: true}}
	_, err = dbSession.DB.NewInsert().Model(tenantWithCapability).Exec(ctx)
	assert.Nil(t, err)

	tenantSiteGet := &cdbm.TenantSite{ID: uuid.New(), TenantID: tenantWithCapability.ID, TenantOrg: tenantOrg, SiteID: fix.site.ID}
	_, err = dbSession.DB.NewInsert().Model(tenantSiteGet).Exec(ctx)
	assert.Nil(t, err)

	// Non-privileged tenant WITH a TenantSite — should succeed.
	tenantOrgNonPrivGet := "test-tenant-non-priv-get"
	tenantNonPrivGet := &cdbm.Tenant{ID: uuid.New(), Name: "non-priv-tenant-get", Org: tenantOrgNonPrivGet, Config: &cdbm.TenantConfig{TargetedInstanceCreation: false}}
	_, err = dbSession.DB.NewInsert().Model(tenantNonPrivGet).Exec(ctx)
	assert.Nil(t, err)

	tenantSiteNonPrivGet := &cdbm.TenantSite{ID: uuid.New(), TenantID: tenantNonPrivGet.ID, TenantOrg: tenantOrgNonPrivGet, SiteID: fix.site.ID}
	_, err = dbSession.DB.NewInsert().Model(tenantSiteNonPrivGet).Exec(ctx)
	assert.Nil(t, err)

	// Tenant without any TenantSite (no site access).
	tenantOrgNoCapability := "test-tenant-no-capability-get"
	tenantWithoutCapability := &cdbm.Tenant{ID: uuid.New(), Name: "no-cap-tenant-get", Org: tenantOrgNoCapability, Config: &cdbm.TenantConfig{TargetedInstanceCreation: false}}
	_, err = dbSession.DB.NewInsert().Model(tenantWithoutCapability).Exec(ctx)
	assert.Nil(t, err)

	tenantOrgNoAccount := "test-tenant-no-site-get"
	tenantWithoutAccount := &cdbm.Tenant{ID: uuid.New(), Name: "no-site-tenant-get", Org: tenantOrgNoAccount, Config: &cdbm.TenantConfig{TargetedInstanceCreation: true}}
	_, err = dbSession.DB.NewInsert().Model(tenantWithoutAccount).Exec(ctx)
	assert.Nil(t, err)

	// Mixed-role org: provider check fails (site belongs to fix.ip), tenant path
	// succeeds via TenantSite association.
	mixedOrg := "mixed-role-org-get"
	mixedIP := &cdbm.InfrastructureProvider{ID: uuid.New(), Name: "mixed-provider-get", Org: mixedOrg}
	_, err = dbSession.DB.NewInsert().Model(mixedIP).Exec(ctx)
	assert.Nil(t, err)

	mixedTenant := &cdbm.Tenant{ID: uuid.New(), Name: "mixed-tenant-get", Org: mixedOrg, Config: &cdbm.TenantConfig{}}
	_, err = dbSession.DB.NewInsert().Model(mixedTenant).Exec(ctx)
	assert.Nil(t, err)

	mixedTenantSiteGet := &cdbm.TenantSite{ID: uuid.New(), TenantID: mixedTenant.ID, TenantOrg: mixedOrg, SiteID: fix.site.ID}
	_, err = dbSession.DB.NewInsert().Model(mixedTenantSiteGet).Exec(ctx)
	assert.Nil(t, err)

	_ = tenantSiteGet
	_ = tenantSiteNonPrivGet
	_ = tenantWithoutCapability
	_ = tenantWithoutAccount

	tests := []struct {
		name                 string
		templateID           string
		setupContext         func(c echo.Context)
		expectedStatus       int
		checkResponseContent func(t *testing.T, body []byte)
	}{
		{
			name:       "successful retrieval",
			templateID: fix.tmpl1.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, fix.tmpl1.ID.String())
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				assert.Equal(t, fix.tmpl1.ID.String(), response.ID)
				assert.Equal(t, "kernel-initrd", response.Name)
			},
		},
		{
			name:       "template not found",
			templateID: uuid.New().String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, uuid.New().String())
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:       "invalid uuid returns bad request",
			templateID: "not-a-uuid",
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, "not-a-uuid")
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:       "cannot retrieve from unmanaged site",
			templateID: unmanagedTmpl.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMockUser(org))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, unmanagedTmpl.ID.String())
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:       "missing user context returns 500",
			templateID: fix.tmpl1.ID.String(),
			setupContext: func(c echo.Context) {
				c.SetParamNames("orgName", "id")
				c.SetParamValues(org, fix.tmpl1.ID.String())
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:       "tenant with TenantSite can retrieve template",
			templateID: fix.tmpl1.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrg))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(tenantOrg, fix.tmpl1.ID.String())
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				assert.Equal(t, fix.tmpl1.ID.String(), response.ID)
			},
		},
		{
			name:       "non-privileged tenant with TenantSite can retrieve template",
			templateID: fix.tmpl1.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrgNonPrivGet))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(tenantOrgNonPrivGet, fix.tmpl1.ID.String())
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				assert.Equal(t, fix.tmpl1.ID.String(), response.ID)
			},
		},
		{
			name:       "tenant without TenantSite is denied",
			templateID: fix.tmpl1.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrgNoCapability))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(tenantOrgNoCapability, fix.tmpl1.ID.String())
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:       "tenant without TenantSite on requested site is denied",
			templateID: fix.tmpl1.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateTenantMockUser(tenantOrgNoAccount))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(tenantOrgNoAccount, fix.tmpl1.ID.String())
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:       "mixed-role user fails provider check but passes tenant authorization",
			templateID: fix.tmpl1.ID.String(),
			setupContext: func(c echo.Context) {
				c.Set("user", createIpxeTemplateMixedRoleMockUser(mixedOrg))
				c.SetParamNames("orgName", "id")
				c.SetParamValues(mixedOrg, fix.tmpl1.ID.String())
			},
			expectedStatus: http.StatusOK,
			checkResponseContent: func(t *testing.T, body []byte) {
				var response model.APIIpxeTemplate
				assert.Nil(t, json.Unmarshal(body, &response))
				assert.Equal(t, fix.tmpl1.ID.String(), response.ID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/v2/org/" + org + "/nico/ipxe-template/" + tt.templateID
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req = req.WithContext(context.Background())
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			tt.setupContext(c)

			err := handler.Handle(c)
			assert.Nil(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus != rec.Code {
				t.Errorf("Response: %v", rec.Body.String())
			}
			if tt.checkResponseContent != nil && rec.Code == http.StatusOK {
				tt.checkResponseContent(t, rec.Body.Bytes())
			}
		})
	}
}
