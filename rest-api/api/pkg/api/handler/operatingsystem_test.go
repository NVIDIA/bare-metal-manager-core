// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	cdmu "github.com/NVIDIA/infra-controller-rest/api/pkg/api/model/util"
	sc "github.com/NVIDIA/infra-controller-rest/api/pkg/client/site"
	authz "github.com/NVIDIA/infra-controller-rest/auth/pkg/authorization"
	"github.com/NVIDIA/infra-controller-rest/common/pkg/otelecho"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/ipam"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	swe "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/error"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.temporal.io/api/enums/v1"
	tmocks "go.temporal.io/sdk/mocks"
	tp "go.temporal.io/sdk/temporal"
)

func TestOperatingSystemHandler_Create(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()

	common.TestSetupSchema(t, dbSession)

	// Add user entry
	ipOrg1 := "test-ip-org-1"
	ipOrg2 := "test-ip-org-2"
	ipOrg3 := "test-ip-org-3"
	ipRoles := []string{authz.ProviderAdminRole}

	testMachineBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg1, ipOrg2, ipOrg3}, ipRoles)

	tnOrg1 := "test-tn-org-1"
	tnOrg2 := "test-tn-org-2"
	tnOrg3 := "test-tn-org-3"
	tnRoles := []string{authz.TenantAdminRole}

	ip := testMachineBuildInfrastructureProvider(t, dbSession, ipOrg1, "infra-provider-1")
	assert.NotNil(t, ip)

	site := testMachineBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusRegistered)
	assert.NotNil(t, site)

	site1 := testMachineBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered)
	assert.NotNil(t, site1)

	tnu := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{tnOrg1, tnOrg2, tnOrg3}, tnRoles)

	tenant1 := testMachineBuildTenant(t, dbSession, tnOrg1, "test-tenant-1")
	testMachineBuildTenant(t, dbSession, tnOrg1, "test-tenant-3")

	ts1 := testBuildTenantSiteAssociation(t, dbSession, tnOrg1, tenant1.ID, site.ID, tnu.ID)
	assert.NotNil(t, ts1)

	tenant2 := testMachineBuildTenant(t, dbSession, tnOrg2, "test-tenant-2")
	testMachineBuildTenant(t, dbSession, tnOrg2, "test-tenant-4")

	ts2 := testBuildTenantSiteAssociation(t, dbSession, tnOrg1, tenant2.ID, site.ID, tnu.ID)
	assert.NotNil(t, ts2)

	ts3 := testBuildTenantSiteAssociation(t, dbSession, tnOrg1, tenant2.ID, site1.ID, tnu.ID)
	assert.NotNil(t, ts3)

	cfg := common.GetTestConfig()
	tempClient := &tmocks.Client{}

	osObj := model.APIOperatingSystemCreateRequest{Name: "test-operating-system-1", Description: cdb.GetStrPtr("test"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(tenant1.ID.String()), IpxeScript: cdb.GetStrPtr("ipxe"), ImageDisk: cdb.GetStrPtr("/dev/sda"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit), IsCloudInit: true, AllowOverride: false}
	okBody, err := json.Marshal(osObj)
	assert.Nil(t, err)

	osImageURLObj1 := model.APIOperatingSystemCreateRequest{Name: "test-operating-system-2", Description: cdb.GetStrPtr("test"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(tenant1.ID.String()), SiteIDs: []string{site.ID.String()}, ImageURL: cdb.GetStrPtr("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit), ImageSHA: nil}
	errImageURLBody, err := json.Marshal(osImageURLObj1)
	assert.Nil(t, err)

	osImageURLObj2 := model.APIOperatingSystemCreateRequest{Name: "test-operating-system-3", Description: cdb.GetStrPtr("test"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(tenant1.ID.String()), SiteIDs: []string{site.ID.String()}, ImageURL: cdb.GetStrPtr("//cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit)}
	badImageURLBody, err := json.Marshal(osImageURLObj2)
	assert.Nil(t, err)

	osImageURLObj3 := model.APIOperatingSystemCreateRequest{Name: "test-operating-system-4", Description: cdb.GetStrPtr("test"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(tenant2.ID.String()), SiteIDs: []string{site.ID.String()}, ImageURL: cdb.GetStrPtr("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), ImageAuthType: cdb.GetStrPtr("Basic"), ImageAuthToken: cdb.GetStrPtr("rsa"), ImageDisk: cdb.GetStrPtr("/dev/nvme1n3"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit), IsCloudInit: false, AllowOverride: true}
	validImageURLBody, err := json.Marshal(osImageURLObj3)
	assert.Nil(t, err)

	osImageURLObj4 := model.APIOperatingSystemCreateRequest{Name: "test-operating-system-5", Description: cdb.GetStrPtr("test"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(tenant1.ID.String()), SiteIDs: []string{site.ID.String()}, IpxeScript: cdb.GetStrPtr("ipxe"), ImageURL: cdb.GetStrPtr("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"), RootFsLabel: cdb.GetStrPtr("test-label"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit)}
	errIpxeImageUrlBody, err := json.Marshal(osImageURLObj4)
	assert.Nil(t, err)

	osImageURLObj5 := model.APIOperatingSystemCreateRequest{Name: "test-operating-system-6", Description: cdb.GetStrPtr("test"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(tenant1.ID.String()), SiteIDs: []string{site.ID.String()}, ImageURL: cdb.GetStrPtr("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"), RootFsID: cdb.GetStrPtr("abc123"), RootFsLabel: cdb.GetStrPtr("test-label"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit)}
	errRootFsBody, err := json.Marshal(osImageURLObj5)
	assert.Nil(t, err)

	osImageURLObj6 := model.APIOperatingSystemCreateRequest{Name: "test-operating-system-7", Description: cdb.GetStrPtr("test"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(tenant1.ID.String()), SiteIDs: []string{site.ID.String()}, ImageURL: cdb.GetStrPtr("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"), RootFsID: cdb.GetStrPtr("abc123"), ImageDisk: cdb.GetStrPtr("/dev/junk"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit)}
	errDiskImageBody, err := json.Marshal(osImageURLObj6)
	assert.Nil(t, err)

	osImageURLObj7 := model.APIOperatingSystemCreateRequest{Name: "terminate-workflow-operating-system", Description: cdb.GetStrPtr("test termination"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(tenant2.ID.String()), SiteIDs: []string{site1.ID.String()}, ImageURL: cdb.GetStrPtr("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), ImageAuthType: cdb.GetStrPtr("Basic"), ImageAuthToken: cdb.GetStrPtr("rsa"), ImageDisk: cdb.GetStrPtr("/dev/nvme1n3"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit), IsCloudInit: false, AllowOverride: true}
	terminateCreationImageURLBody, err := json.Marshal(osImageURLObj7)
	assert.Nil(t, err)

	errBodyNameClash, err := json.Marshal(osObj)
	assert.Nil(t, err)

	errBodyDoesntValidate, err := json.Marshal(struct{ Name string }{Name: "test"})
	assert.Nil(t, err)

	// OTEL Spanner configuration
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	// Mock per-Site client for st1
	tsc := &tmocks.Client{}

	// Prepare client pool for sync calls
	// to site(s).
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)
	scp.IDClientMap[site.ID.String()] = tsc

	wid := "test-workflow-id"
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return(wid)

	wrun.Mock.On("Get", mock.Anything, mock.Anything).Return(nil)

	tempClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		mock.AnythingOfType("func(internal.Context, uuid.UUID, uuid.UUID) error"), mock.AnythingOfType("uuid.UUID"),
		mock.AnythingOfType("uuid.UUID")).Return(wrun, nil)

	tsc.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		"CreateOsImage", mock.Anything).Return(wrun, nil)

	// Mock timeout error
	tsc1 := &tmocks.Client{}
	scp.IDClientMap[site1.ID.String()] = tsc1

	wruntimeout := &tmocks.WorkflowRun{}
	wruntimeout.On("GetID").Return("test-workflow-timeout-id")

	wruntimeout.Mock.On("Get", mock.Anything, mock.Anything).Return(tp.NewTimeoutError(enums.TIMEOUT_TYPE_UNSPECIFIED, nil, nil))

	tsc1.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		"CreateOsImage", mock.Anything).Return(wruntimeout, nil)

	tsc1.Mock.On("TerminateWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	tests := []struct {
		name                          string
		reqOrgName                    string
		reqBody                       string
		reqBodyModel                  *model.APIOperatingSystemCreateRequest
		user                          *cdbm.User
		expectedErr                   bool
		expectedStatus                int
		expectedOperatingSystemStatus string
		expectedStatusHistoryCount    int
		expectedImageURL              bool
		verifyChildSpanner            bool
	}{
		{
			name:           "error when user not found in request context",
			reqOrgName:     tnOrg1,
			reqBody:        string(okBody),
			reqBodyModel:   &osObj,
			user:           nil,
			expectedErr:    true,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "error when user not found in org",
			reqOrgName:     "SomeOrg",
			reqBody:        string(okBody),
			reqBodyModel:   &osObj,
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "error when request body doesnt bind",
			reqOrgName:     tnOrg1,
			reqBody:        "SomeNonJsonBody",
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when request doesnt validate",
			reqOrgName:     tnOrg1,
			reqBody:        string(errBodyDoesntValidate),
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when org does not have a tenant",
			reqOrgName:     tnOrg3,
			reqBody:        string(okBody),
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when both imageURL and idxScrip specified in request",
			reqOrgName:     tnOrg1,
			reqBody:        string(errIpxeImageUrlBody),
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when bad disk path specified in request",
			reqOrgName:     tnOrg1,
			user:           tnu,
			reqBody:        string(errDiskImageBody),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when bad imageURL specified in request",
			reqOrgName:     tnOrg1,
			reqBody:        string(badImageURLBody),
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when imageURL specified in request but imageSHA is nil",
			reqOrgName:     tnOrg1,
			reqBody:        string(errImageURLBody),
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when both rootFsID and rootFsLabel specified in request",
			reqOrgName:     tnOrg1,
			reqBody:        string(errRootFsBody),
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:               "imageURL specified in request (temporarily expect StatusBadRequest - Image based OS creation not allowed)",
			reqOrgName:         tnOrg2,
			reqBody:            string(validImageURLBody),
			reqBodyModel:       &osImageURLObj3,
			user:               tnu,
			expectedErr:        true,
			expectedStatus:     http.StatusBadRequest,
			verifyChildSpanner: false,
		},
		{
			name:           "imageURL specified in request, context deadline timeout (temporarily expect StatusBadRequest - Image based OS creation not allowed)",
			reqOrgName:     tnOrg2,
			reqBody:        string(terminateCreationImageURLBody),
			reqBodyModel:   &osImageURLObj7,
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:                          "success case",
			reqOrgName:                    tnOrg1,
			reqBody:                       string(okBody),
			reqBodyModel:                  &osObj,
			user:                          tnu,
			expectedErr:                   false,
			expectedStatus:                http.StatusCreated,
			expectedOperatingSystemStatus: cdbm.OperatingSystemStatusReady,
			expectedStatusHistoryCount:    1,
			verifyChildSpanner:            true,
		},
		{
			name:           "error due to name clash",
			reqOrgName:     tnOrg1,
			reqBody:        string(errBodyNameClash),
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusConflict,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, tc.name, "")
			// Setup echo server/context
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(tc.reqOrgName)
			if tc.user != nil {
				ec.Set("user", tc.user)
			}

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			cosh := CreateOperatingSystemHandler{
				dbSession: dbSession,
				tc:        tempClient,
				cfg:       cfg,
				scp:       scp,
			}

			err := cosh.Handle(ec)
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedErr, rec.Code != http.StatusCreated)
			assert.Equal(t, tc.expectedStatus, rec.Code)
			if !tc.expectedErr {
				rsp := &model.APIOperatingSystem{}
				err := json.Unmarshal(rec.Body.Bytes(), rsp)
				assert.Nil(t, err)
				// validate response fields
				assert.Equal(t, len(rsp.StatusHistory), tc.expectedStatusHistoryCount)
				assert.Equal(t, tenant1.ID.String(), *rsp.TenantID)
				if !tc.expectedImageURL {
					assert.Equal(t, *rsp.IpxeScript, *tc.reqBodyModel.IpxeScript)
					assert.Equal(t, *rsp.Type, "iPXE")
				} else {
					assert.Equal(t, *rsp.ImageURL, *tc.reqBodyModel.ImageURL)
					assert.Equal(t, *rsp.Type, "Image")
					if tc.reqBodyModel.ImageSHA != nil {
						assert.Equal(t, *rsp.ImageSHA, *tc.reqBodyModel.ImageSHA)
					}
					if tc.reqBodyModel.ImageAuthType != nil {
						assert.Equal(t, *rsp.ImageAuthType, *tc.reqBodyModel.ImageAuthType)
					}
					if tc.reqBodyModel.ImageAuthToken != nil {
						assert.Equal(t, *rsp.ImageAuthToken, *tc.reqBodyModel.ImageAuthToken)
					}
					if tc.reqBodyModel.ImageDisk != nil {
						assert.Equal(t, *rsp.ImageDisk, *tc.reqBodyModel.ImageDisk)
					}
					if tc.reqBodyModel.RootFsID != nil {
						assert.Equal(t, *rsp.RootFsID, *tc.reqBodyModel.RootFsID)
					}
					if tc.reqBodyModel.RootFsLabel != nil {
						assert.Equal(t, *rsp.RootFsLabel, *tc.reqBodyModel.RootFsLabel)
					}
				}

				assert.Equal(t, *rsp.UserData, *tc.reqBodyModel.UserData)
				assert.Equal(t, rsp.Name, tc.reqBodyModel.Name)
				assert.Equal(t, rsp.Status, tc.expectedOperatingSystemStatus)
				if tc.reqBodyModel.PhoneHomeEnabled != nil {
					assert.Equal(t, rsp.PhoneHomeEnabled, *tc.reqBodyModel.PhoneHomeEnabled)
				}
			}

			if tc.verifyChildSpanner {
				span := oteltrace.SpanFromContext(ec.Request().Context())
				assert.True(t, span.SpanContext().IsValid())
			}
		})
	}
}

func TestOperatingSystemHandler_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()

	common.TestSetupSchema(t, dbSession)

	// Add user entry
	ipOrg1 := "test-ip-org-1"
	ipOrg2 := "test-ip-org-2"
	ipOrg3 := "test-ip-org-3"
	ipRoles := []string{authz.ProviderAdminRole}

	ip := testMachineBuildInfrastructureProvider(t, dbSession, ipOrg1, "infra-provider-1")
	assert.NotNil(t, ip)

	site := testMachineBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusRegistered)
	assert.NotNil(t, site)

	testMachineBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg1, ipOrg2, ipOrg3}, ipRoles)

	tnOrg1 := "test-tn-org-1"
	tnOrg2 := "test-tn-org-2"
	tnOrg3 := "test-tn-org-3"
	tnOrg4 := "test-tn-org-4"
	tnRoles := []string{authz.TenantAdminRole}

	tnu := testMachineBuildUser(t, dbSession, uuid.NewString(), []string{tnOrg1, tnOrg2, tnOrg3, tnOrg4}, tnRoles)

	tenant1 := testMachineBuildTenant(t, dbSession, tnOrg1, "test-tenant-1")
	testMachineBuildTenant(t, dbSession, tnOrg2, "test-tenant-2")

	ts1 := testBuildTenantSiteAssociation(t, dbSession, tnOrg1, tenant1.ID, site.ID, tnu.ID)
	assert.NotNil(t, ts1)

	cfg := common.GetTestConfig()
	tempClient := &tmocks.Client{}

	osDAO := cdbm.NewOperatingSystemDAO(dbSession)

	totalCount := 30

	oss := []cdbm.OperatingSystem{}

	for i := 0; i < totalCount; i++ {
		os := &cdbm.OperatingSystem{}
		if i == 0 || i == 1 {
			os, err := osDAO.Create(
				ctx,
				nil,
				cdbm.OperatingSystemCreateInput{
					Name:               fmt.Sprintf("test-os-%02d", i),
					Description:        cdb.GetStrPtr("test"),
					Org:                tnOrg1,
					TenantID:           &tenant1.ID,
					OsType:             cdbm.OperatingSystemTypeImage,
					ImageURL:           cdb.GetStrPtr("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"),
					ImageSHA:           cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"),
					ImageAuthType:      cdb.GetStrPtr("Basic"),
					ImageAuthToken:     cdb.GetStrPtr("rsa"),
					ImageDisk:          cdb.GetStrPtr("/dev/nvme1n3"),
					RootFsId:           cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"),
					UserData:           cdb.GetStrPtr(cdmu.TestCommonCloudInit),
					IsCloudInit:        true,
					AllowOverride:      false,
					EnableBlockStorage: false,
					PhoneHomeEnabled:   false,
					Status:             cdbm.OperatingSystemStatusSyncing,
					CreatedBy:          tnu.ID,
				},
			)
			assert.Nil(t, err)
			common.TestBuildOperatingSystemSiteAssociation(t, dbSession, os.ID, site.ID, db.GetStrPtr("test"), cdbm.OperatingSystemSiteAssociationStatusSyncing, tnu)
			common.TestBuildStatusDetail(t, dbSession, os.ID.String(), cdbm.OperatingSystemStatusSyncing, cdb.GetStrPtr("received Operating System creation request, syncing"))
			common.TestBuildStatusDetail(t, dbSession, os.ID.String(), cdbm.OperatingSystemStatusReady, cdb.GetStrPtr("Operating System is now ready for use"))
		} else {
			os, err := osDAO.Create(
				ctx,
				nil,
				cdbm.OperatingSystemCreateInput{
					Name:               fmt.Sprintf("test-os-%02d", i),
					Description:        cdb.GetStrPtr("test"),
					Org:                tnOrg1,
					TenantID:           &tenant1.ID,
					OsType:             cdbm.OperatingSystemTypeIPXE,
					IpxeScript:         cdb.GetStrPtr("ipxe"),
					IsCloudInit:        true,
					AllowOverride:      false,
					EnableBlockStorage: false,
					PhoneHomeEnabled:   false,
					Status:             cdbm.OperatingSystemStatusPending,
					CreatedBy:          tnu.ID,
				},
			)
			assert.Nil(t, err)
			common.TestBuildStatusDetail(t, dbSession, os.ID.String(), cdbm.OperatingSystemStatusPending, cdb.GetStrPtr("request received, pending processing"))
			common.TestBuildStatusDetail(t, dbSession, os.ID.String(), cdbm.OperatingSystemStatusReady, cdb.GetStrPtr("OPerating System is now ready for use"))
		}
		oss = append(oss, *os)
	}

	site2 := testMachineBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered)
	assert.NotNil(t, site2)

	tenant4 := testMachineBuildTenant(t, dbSession, tnOrg4, "test-tenant-4")
	testMachineBuildTenant(t, dbSession, tnOrg4, "test-tenant-4")

	ts4 := testBuildTenantSiteAssociation(t, dbSession, tnOrg4, tenant4.ID, site2.ID, tnu.ID)
	assert.NotNil(t, ts4)

	imageoss := []cdbm.OperatingSystem{}
	imageossa := []cdbm.OperatingSystemSiteAssociation{}
	ipxeoss := []cdbm.OperatingSystem{}
	totalCount2 := 18

	for i := 0; i < totalCount2; i++ {
		if i%2 == 0 {
			os, err := osDAO.Create(
				ctx,
				nil,
				cdbm.OperatingSystemCreateInput{
					Name:               fmt.Sprintf("site-test-os-%02d", i),
					Description:        cdb.GetStrPtr("test"),
					Org:                tnOrg4,
					TenantID:           &tenant4.ID,
					OsType:             cdbm.OperatingSystemTypeImage,
					ImageURL:           cdb.GetStrPtr("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"),
					ImageSHA:           cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"),
					ImageAuthType:      cdb.GetStrPtr("Basic"),
					ImageAuthToken:     cdb.GetStrPtr("rsa"),
					ImageDisk:          cdb.GetStrPtr("/dev/nvme1n3"),
					RootFsId:           cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"),
					UserData:           cdb.GetStrPtr(cdmu.TestCommonCloudInit),
					IsCloudInit:        true,
					AllowOverride:      false,
					EnableBlockStorage: false,
					PhoneHomeEnabled:   false,
					Status:             cdbm.OperatingSystemStatusSyncing,
					CreatedBy:          tnu.ID,
				},
			)
			assert.Nil(t, err)

			ossa := common.TestBuildOperatingSystemSiteAssociation(t, dbSession, os.ID, site2.ID, db.GetStrPtr("test"), cdbm.OperatingSystemSiteAssociationStatusSyncing, tnu)
			common.TestBuildStatusDetail(t, dbSession, os.ID.String(), cdbm.OperatingSystemStatusSyncing, cdb.GetStrPtr("received Operating System creation request, syncing"))
			common.TestBuildStatusDetail(t, dbSession, os.ID.String(), cdbm.OperatingSystemStatusReady, cdb.GetStrPtr("Operating System is now ready for use"))

			assert.Nil(t, err)
			imageoss = append(imageoss, *os)
			imageossa = append(imageossa, *ossa)

		} else {
			os, err := osDAO.Create(
				ctx,
				nil,
				cdbm.OperatingSystemCreateInput{
					Name:               fmt.Sprintf("site-test-os-%02d", i),
					Description:        cdb.GetStrPtr("test"),
					Org:                tnOrg4,
					TenantID:           &tenant4.ID,
					OsType:             cdbm.OperatingSystemTypeIPXE,
					IpxeScript:         cdb.GetStrPtr("ipxe"),
					IsCloudInit:        true,
					AllowOverride:      false,
					EnableBlockStorage: false,
					PhoneHomeEnabled:   false,
					Status:             cdbm.OperatingSystemStatusPending,
					CreatedBy:          tnu.ID,
				},
			)
			assert.Nil(t, err)

			common.TestBuildStatusDetail(t, dbSession, os.ID.String(), cdbm.OperatingSystemStatusPending, cdb.GetStrPtr("request received, pending processing"))
			common.TestBuildStatusDetail(t, dbSession, os.ID.String(), cdbm.OperatingSystemStatusReady, cdb.GetStrPtr("OPerating System is now ready for use"))

			ipxeoss = append(ipxeoss, *os)
		}
	}

	// OTEL Spanner configuration
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		name                              string
		reqOrgName                        string
		user                              *cdbm.User
		siteID                            *uuid.UUID
		osType                            *string
		querySearch                       *string
		queryStatus                       *string
		queryIncludeRelations1            *string
		queryIncludeRelations2            *string
		pageNumber                        *int
		pageSize                          *int
		orderBy                           *string
		expectedErr                       bool
		expectedStatus                    int
		expectedCnt                       int
		expectedTotal                     *int
		expectedFirstEntry                *cdbm.OperatingSystem
		expectedTenantOrg                 *string
		expectedInfrastructureProviderOrg *string
		verifyChildSpanner                bool
	}{
		{
			name:           "error when user not found in request context",
			reqOrgName:     ipOrg1,
			user:           nil,
			expectedErr:    true,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "error when user is not a member of org",
			reqOrgName:     "SomeOrg",
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "error when tenant doesnt exist for org",
			reqOrgName:     tnOrg3,
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:               "success case when objects returned",
			reqOrgName:         tnOrg1,
			user:               tnu,
			expectedErr:        false,
			expectedStatus:     http.StatusOK,
			expectedCnt:        paginator.DefaultLimit,
			expectedTotal:      &totalCount,
			verifyChildSpanner: true,
		},
		{
			name:                   "success when tenant relation are specified",
			reqOrgName:             tnOrg1,
			user:                   tnu,
			queryIncludeRelations1: cdb.GetStrPtr(cdbm.TenantRelationName),
			expectedErr:            false,
			expectedStatus:         http.StatusOK,
			expectedCnt:            paginator.DefaultLimit,
			expectedTotal:          &totalCount,
			expectedTenantOrg:      cdb.GetStrPtr(tenant1.Org),
		},
		{
			name:           "success case when no objects returned",
			reqOrgName:     tnOrg2,
			user:           tnu,
			expectedErr:    false,
			expectedStatus: http.StatusOK,
			expectedCnt:    0,
		},
		{
			name:               "success when pagination params are specified",
			reqOrgName:         tnOrg1,
			user:               tnu,
			pageNumber:         cdb.GetIntPtr(1),
			pageSize:           cdb.GetIntPtr(10),
			orderBy:            cdb.GetStrPtr("NAME_DESC"),
			expectedErr:        false,
			expectedStatus:     http.StatusOK,
			expectedCnt:        10,
			expectedTotal:      cdb.GetIntPtr(totalCount / 2),
			expectedFirstEntry: &oss[29],
		},
		{
			name:           "failure when invalid pagination params are specified",
			reqOrgName:     tnOrg1,
			user:           tnu,
			pageNumber:     cdb.GetIntPtr(1),
			pageSize:       cdb.GetIntPtr(10),
			orderBy:        cdb.GetStrPtr("TEST_ASC"),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
			expectedCnt:    0,
		},
		{
			name:           "success when name query search specified",
			reqOrgName:     tnOrg1,
			user:           tnu,
			querySearch:    cdb.GetStrPtr("test"),
			expectedErr:    false,
			expectedStatus: http.StatusOK,
			expectedCnt:    paginator.DefaultLimit,
			expectedTotal:  &totalCount,
		},
		{
			name:           "success when unexisted status query search specified",
			reqOrgName:     tnOrg1,
			user:           tnu,
			querySearch:    cdb.GetStrPtr("ready"),
			expectedErr:    false,
			expectedStatus: http.StatusOK,
			expectedCnt:    0,
			expectedTotal:  cdb.GetIntPtr(0),
		},
		{
			name:           "success when name and status query search specified",
			reqOrgName:     tnOrg1,
			user:           tnu,
			querySearch:    cdb.GetStrPtr("test ready"),
			expectedErr:    false,
			expectedStatus: http.StatusOK,
			expectedCnt:    paginator.DefaultLimit,
			expectedTotal:  &totalCount,
		},
		{
			name:           "success when OperatingSystemStatusPending status is specified",
			reqOrgName:     tnOrg1,
			user:           tnu,
			queryStatus:    cdb.GetStrPtr(cdbm.OperatingSystemStatusPending),
			expectedErr:    false,
			expectedStatus: http.StatusOK,
			expectedCnt:    paginator.DefaultLimit,
			expectedTotal:  cdb.GetIntPtr(totalCount),
		},
		{
			name:           "success when BadStatus status is specified",
			reqOrgName:     tnOrg1,
			user:           tnu,
			queryStatus:    cdb.GetStrPtr("BadRequest"),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
			expectedCnt:    0,
			expectedTotal:  cdb.GetIntPtr(0),
		},
		{
			name:           "success when site and type filter specified",
			reqOrgName:     tnOrg1,
			user:           tnu,
			siteID:         &site.ID,
			osType:         cdb.GetStrPtr(cdbm.OperatingSystemTypeImage),
			querySearch:    cdb.GetStrPtr("test"),
			expectedErr:    false,
			expectedStatus: http.StatusOK,
			expectedCnt:    2,
			expectedTotal:  cdb.GetIntPtr(2),
		},
		{
			name:           "success when only site filter specified",
			reqOrgName:     tnOrg4,
			user:           tnu,
			siteID:         &site2.ID,
			osType:         nil,
			expectedErr:    false,
			expectedStatus: http.StatusOK,
			expectedCnt:    len(imageoss) + len(ipxeoss),
			expectedTotal:  cdb.GetIntPtr(len(imageoss) + len(ipxeoss)),
		},
		{
			name:           "success when only image type filter specified",
			reqOrgName:     tnOrg4,
			user:           tnu,
			osType:         cdb.GetStrPtr(cdbm.OperatingSystemTypeImage),
			expectedErr:    false,
			expectedStatus: http.StatusOK,
			expectedCnt:    len(imageoss),
			expectedTotal:  cdb.GetIntPtr(len(imageoss)),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, tc.name, "")
			// Setup echo server/context
			e := echo.New()

			q := url.Values{}
			if tc.siteID != nil {
				q.Add("siteId", tc.siteID.String())
			}
			if tc.osType != nil {
				q.Add("type", *tc.osType)
			}
			if tc.querySearch != nil {
				q.Add("query", *tc.querySearch)
			}
			if tc.queryStatus != nil {
				q.Add("status", *tc.queryStatus)
			}
			if tc.queryIncludeRelations1 != nil {
				q.Add("includeRelation", *tc.queryIncludeRelations1)
			}
			if tc.queryIncludeRelations2 != nil {
				q.Add("includeRelation", *tc.queryIncludeRelations2)
			}
			if tc.pageNumber != nil {
				q.Set("pageNumber", fmt.Sprintf("%v", *tc.pageNumber))
			}
			if tc.pageSize != nil {
				q.Set("pageSize", fmt.Sprintf("%v", *tc.pageSize))
			}
			if tc.orderBy != nil {
				q.Set("orderBy", *tc.orderBy)
			}

			path := fmt.Sprintf("/v2/org/%s/nico/operating-system?%s", tc.reqOrgName, q.Encode())

			req := httptest.NewRequest(http.MethodGet, path, nil)

			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName")
			ec.SetParamValues(tc.reqOrgName)
			if tc.user != nil {
				ec.Set("user", tc.user)
			}

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			mh := GetAllOperatingSystemHandler{
				dbSession: dbSession,
				tc:        tempClient,
				cfg:       cfg,
			}
			err := mh.Handle(ec)
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedErr, rec.Code != http.StatusOK)
			require.Equal(t, tc.expectedStatus, rec.Code)

			if !tc.expectedErr {
				rsp := []model.APIOperatingSystem{}
				err := json.Unmarshal(rec.Body.Bytes(), &rsp)
				assert.Nil(t, err)
				assert.Equal(t, tc.expectedCnt, len(rsp))

				if tc.queryIncludeRelations1 != nil || tc.queryIncludeRelations2 != nil {
					if tc.expectedInfrastructureProviderOrg != nil {
						assert.Equal(t, *tc.expectedInfrastructureProviderOrg, rsp[0].InfrastructureProvider.Org)
					}

					if tc.expectedTenantOrg != nil {
						assert.Equal(t, *tc.expectedTenantOrg, rsp[0].Tenant.Org)
					}
				} else {
					if len(rsp) > 0 {
						assert.Nil(t, rsp[0].Tenant)
						assert.Nil(t, rsp[0].InfrastructureProvider)
					}
				}

				for _, apios := range rsp {
					assert.Equal(t, 2, len(apios.StatusHistory))
					assert.True(t, apios.IsActive, "Operating System should be active by default")
				}

				if tc.osType != nil && *tc.osType == cdbm.OperatingSystemTypeImage {
					for _, apios := range rsp {
						assert.Greater(t, len(apios.SiteAssociations), 0)
					}
				}
			}

			if tc.verifyChildSpanner {
				span := oteltrace.SpanFromContext(ec.Request().Context())
				assert.True(t, span.SpanContext().IsValid())
			}
		})
	}
}

func TestOperatingSystemHandler_GetByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()

	common.TestSetupSchema(t, dbSession)

	// Add user entry
	ipOrg1 := "test-ip-org-1"
	ipOrg2 := "test-ip-org-2"
	ipOrg3 := "test-ip-org-3"

	ip := testMachineBuildInfrastructureProvider(t, dbSession, ipOrg1, "infra-provider-1")
	assert.NotNil(t, ip)

	site := testMachineBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusRegistered)
	assert.NotNil(t, site)

	tnOrg1 := "test-tn-org-1"
	tnOrg2 := "test-tn-org-2"
	orgRoles := []string{authz.TenantAdminRole}

	user := testMachineBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg1, ipOrg2, ipOrg3, tnOrg1, tnOrg2}, orgRoles)

	tenant1 := testMachineBuildTenant(t, dbSession, tnOrg1, "t1")
	assert.NotNil(t, tenant1)

	tenant2 := testMachineBuildTenant(t, dbSession, tnOrg2, "t2")
	assert.NotNil(t, tenant2)

	ts1 := testBuildTenantSiteAssociation(t, dbSession, tnOrg1, tenant1.ID, site.ID, user.ID)
	assert.NotNil(t, ts1)

	ts2 := testBuildTenantSiteAssociation(t, dbSession, tnOrg2, tenant2.ID, site.ID, user.ID)
	assert.NotNil(t, ts2)

	cfg := common.GetTestConfig()
	tempClient := &tmocks.Client{}

	osDAO := cdbm.NewOperatingSystemDAO(dbSession)
	os1, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test1",
			Description:        cdb.GetStrPtr("test"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeIPXE,
			IpxeScript:         cdb.GetStrPtr("ipxe"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusPending,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os1)

	os2, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test2",
			Description:        cdb.GetStrPtr("test"),
			Org:                ipOrg2,
			TenantID:           &tenant2.ID,
			OsType:             cdbm.OperatingSystemTypeIPXE,
			IpxeScript:         cdb.GetStrPtr("ipxe"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusPending,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os2)

	os3, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test3",
			Description:        cdb.GetStrPtr("test"),
			Org:                ipOrg2,
			TenantID:           &tenant2.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os3)

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dbSession)
	ossaDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: os3.ID,
			SiteID:            site.ID,
			Status:            cdbm.OperatingSystemSiteAssociationStatusSynced,
			CreatedBy:         user.ID,
		},
	)

	// OTEL Spanner configuration
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		name                              string
		reqOrgName                        string
		user                              *cdbm.User
		os                                *cdbm.OperatingSystem
		queryIncludeRelations1            *string
		queryIncludeRelations2            *string
		expectedErr                       bool
		expectedStatus                    int
		expectedTenantOrg                 *string
		expectedInfrastructureProviderOrg *string
		verifyChildSpanner                bool
	}{
		{
			name:           "error when user not found in request context",
			reqOrgName:     tnOrg1,
			user:           nil,
			os:             os1,
			expectedErr:    true,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "error when user not found in org",
			reqOrgName:     "SomeOrg",
			user:           user,
			os:             os1,
			expectedErr:    true,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "error when tenant doesnt exist for org",
			reqOrgName:     ipOrg3,
			user:           user,
			os:             os1,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:       "error when os id doesnt exist",
			reqOrgName: tnOrg1,
			user:       user,
			os: &cdbm.OperatingSystem{
				ID: uuid.New(),
			},
			expectedErr:    true,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "error when os tenant doesnt match tenant in org",
			reqOrgName:     ipOrg1,
			user:           user,
			os:             os2,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:               "success case",
			reqOrgName:         tnOrg1,
			user:               user,
			os:                 os1,
			expectedErr:        false,
			expectedStatus:     http.StatusOK,
			verifyChildSpanner: true,
		},
		{
			name:                   "success when both infrastructure and tenant relations are specified",
			reqOrgName:             tnOrg1,
			user:                   user,
			os:                     os1,
			expectedErr:            false,
			expectedStatus:         http.StatusOK,
			queryIncludeRelations1: cdb.GetStrPtr(cdbm.InfrastructureProviderRelationName),
			queryIncludeRelations2: cdb.GetStrPtr(cdbm.TenantRelationName),
			expectedTenantOrg:      cdb.GetStrPtr(tenant1.Org),
		},
		{
			name:               "success case with image based os",
			reqOrgName:         tnOrg2,
			user:               user,
			os:                 os3,
			expectedErr:        false,
			expectedStatus:     http.StatusOK,
			verifyChildSpanner: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, tc.name, "")

			// Setup echo server/context
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/", nil)

			q := req.URL.Query()
			if tc.queryIncludeRelations1 != nil {
				q.Add("includeRelation", *tc.queryIncludeRelations1)
			}

			if tc.queryIncludeRelations2 != nil {
				q.Add("includeRelation", *tc.queryIncludeRelations2)
			}

			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			req.URL.RawQuery = q.Encode()

			ec := e.NewContext(req, rec)
			names := []string{"orgName", "id"}
			ec.SetParamNames(names...)
			values := []string{tc.reqOrgName, tc.os.ID.String()}
			ec.SetParamValues(values...)
			if tc.user != nil {
				ec.Set("user", tc.user)
			}

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			tah := GetOperatingSystemHandler{
				dbSession: dbSession,
				tc:        tempClient,
				cfg:       cfg,
			}
			err := tah.Handle(ec)
			assert.Nil(t, err)

			if tc.expectedStatus != rec.Code {
				t.Errorf("response: %v\n", rec.Body.String())
			}

			assert.Equal(t, tc.expectedStatus, rec.Code)
			assert.Equal(t, tc.expectedErr, rec.Code != http.StatusOK)

			if !tc.expectedErr {
				rsp := &model.APIOperatingSystem{}
				err := json.Unmarshal(rec.Body.Bytes(), rsp)
				assert.Nil(t, err)
				assert.Equal(t, tc.os.Name, rsp.Name)
				assert.Equal(t, tc.os.TenantID.String(), *rsp.TenantID)

				if tc.queryIncludeRelations1 != nil || tc.queryIncludeRelations2 != nil {
					if tc.expectedInfrastructureProviderOrg != nil {
						assert.Equal(t, *tc.expectedInfrastructureProviderOrg, rsp.InfrastructureProvider.Org)
					}

					if tc.expectedTenantOrg != nil {
						assert.Equal(t, *tc.expectedTenantOrg, rsp.Tenant.Org)
					}
				} else {
					assert.Nil(t, rsp.Tenant)
					assert.Nil(t, rsp.InfrastructureProvider)
				}

				if len(rsp.SiteAssociations) > 0 {
					assert.Equal(t, *rsp.Type, cdbm.OperatingSystemTypeImage)
				} else {
					assert.Equal(t, *rsp.Type, cdbm.OperatingSystemTypeIPXE)
				}
			}

			if tc.verifyChildSpanner {
				span := oteltrace.SpanFromContext(ec.Request().Context())
				assert.True(t, span.SpanContext().IsValid())
			}
		})
	}
}

func TestOperatingSystemHandler_Update(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()

	common.TestSetupSchema(t, dbSession)

	// Add user entry
	ipOrg1 := "test-ip-org-1"
	ipOrg2 := "test-ip-org-2"
	ipOrg3 := "test-ip-org-3"
	tnOrg1 := "test-tn-org-1"
	tnOrg2 := "test-tn-org-2"
	orgRoles := []string{authz.TenantAdminRole}
	user := testMachineBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg1, ipOrg2, ipOrg3, tnOrg1, tnOrg2}, orgRoles)

	ip := testMachineBuildInfrastructureProvider(t, dbSession, ipOrg1, "infra-provider-1")
	assert.NotNil(t, ip)

	site := testMachineBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusRegistered)
	assert.NotNil(t, site)

	site1 := testMachineBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered)
	assert.NotNil(t, site1)

	tenant1 := testMachineBuildTenant(t, dbSession, ipOrg1, "t1")

	tenant2 := testMachineBuildTenant(t, dbSession, ipOrg2, "t2")

	assert.NotNil(t, tenant2)

	ts2 := testBuildTenantSiteAssociation(t, dbSession, tnOrg1, tenant1.ID, site.ID, user.ID)
	assert.NotNil(t, ts2)

	ts3 := testBuildTenantSiteAssociation(t, dbSession, tnOrg1, tenant2.ID, site1.ID, user.ID)
	assert.NotNil(t, ts3)

	cfg := common.GetTestConfig()
	tempClient := &tmocks.Client{}

	osDAO := cdbm.NewOperatingSystemDAO(dbSession)
	os1, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-1",
			Description:        cdb.GetStrPtr("Test Description 1"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeIPXE,
			IpxeScript:         cdb.GetStrPtr("ipxe"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusPending,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os1)

	os2, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-2",
			Description:        cdb.GetStrPtr("Test Description 2"),
			Org:                ipOrg2,
			TenantID:           &tenant2.ID,
			OsType:             cdbm.OperatingSystemTypeIPXE,
			IpxeScript:         cdb.GetStrPtr("ipxe"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusPending,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os2)

	os3, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-3",
			Description:        cdb.GetStrPtr("Test Description 3"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeIPXE,
			IpxeScript:         cdb.GetStrPtr("ipxe"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusPending,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os3)

	os4, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-4",
			Description:        cdb.GetStrPtr("Test Description 4"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeIPXE,
			IpxeScript:         cdb.GetStrPtr("ipxe"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os4)

	os5, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-5",
			Description:        cdb.GetStrPtr("Test Description 5"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: true,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os5)

	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dbSession)
	ossaDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: os5.ID,
			SiteID:            site.ID,
			Status:            cdbm.OperatingSystemSiteAssociationStatusSynced,
			CreatedBy:         user.ID,
		},
	)

	os6, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-6",
			Description:        cdb.GetStrPtr("Test Description 6"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			RootFsId:           cdb.GetStrPtr("fsID"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: true,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os6)

	os7, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-7",
			Description:        cdb.GetStrPtr("Test Description 7"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			RootFsLabel:        cdb.GetStrPtr("fs-label"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os7)

	os8, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-8",
			Description:        cdb.GetStrPtr("Test Description 8"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			RootFsLabel:        cdb.GetStrPtr("fs-label"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os8)

	os9, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-9",
			Description:        cdb.GetStrPtr("Test Description 9"),
			Org:                ipOrg2,
			TenantID:           &tenant2.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: true,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os9)

	ossaDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: os9.ID,
			SiteID:            site1.ID,
			Status:            cdbm.OperatingSystemSiteAssociationStatusSyncing,
			CreatedBy:         user.ID,
		},
	)

	// OS to be deactivated (1)
	os10, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-10",
			Description:        cdb.GetStrPtr("Test Description 10"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			RootFsLabel:        cdb.GetStrPtr("fs-label"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os10)

	// OS to be deactivated (2)
	os11, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-11",
			Description:        cdb.GetStrPtr("Test Description 11"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			RootFsLabel:        cdb.GetStrPtr("fs-label"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os11)

	// deactivated OS (2)
	os12, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-12",
			Description:        cdb.GetStrPtr("Test Description 12"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			RootFsLabel:        cdb.GetStrPtr("fs-label"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os12)
	os12, err = osDAO.Update(ctx, nil, cdbm.OperatingSystemUpdateInput{OperatingSystemId: os12.ID, IsActive: cdb.GetBoolPtr(false)})
	assert.Nil(t, err)
	assert.NotNil(t, os12)

	// deactivated OS (2)
	os13, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-13",
			Description:        cdb.GetStrPtr("Test Description 13"),
			Org:                ipOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			RootFsLabel:        cdb.GetStrPtr("fs-label"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: false,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          user.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os13)
	os13, err = osDAO.Update(ctx, nil, cdbm.OperatingSystemUpdateInput{OperatingSystemId: os13.ID, IsActive: cdb.GetBoolPtr(false)})
	assert.Nil(t, err)
	assert.NotNil(t, os13)

	updReq := model.APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("test-os-updated"), Description: cdb.GetStrPtr("Updated Description"), IpxeScript: cdb.GetStrPtr("updatedIpxe"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit), IsCloudInit: cdb.GetBoolPtr(false), AllowOverride: cdb.GetBoolPtr(true), PhoneHomeEnabled: cdb.GetBoolPtr(false)}
	okBody, err := json.Marshal(updReq)
	assert.Nil(t, err)

	updReqNameClash := model.APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("test-operating-system-3")}
	errBodyNameClash, err := json.Marshal(updReqNameClash)
	assert.Nil(t, err)

	updReq2 := model.APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("test-operating-system-2")}
	okBody2, err := json.Marshal(updReq2)
	assert.Nil(t, err)

	updReqImageUrl := model.APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("test-os-updated-2"), Description: cdb.GetStrPtr("Updated Description"), ImageURL: cdb.GetStrPtr("http://imagepath.iso")}
	errBodyImageUrlIpxe, err := json.Marshal(updReqImageUrl)
	assert.Nil(t, err)

	updReqValidImageUrl := model.APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("test-os-updated-3"), Description: cdb.GetStrPtr("Updated Description"), ImageURL: cdb.GetStrPtr("http://newimagepath.iso"), ImageSHA: cdb.GetStrPtr("10886660c5b2746ff48224646c5094ebcf88c889"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), ImageDisk: cdb.GetStrPtr("/dev/nvme2n1")}
	okBodyImageUrl, err := json.Marshal(updReqValidImageUrl)
	assert.Nil(t, err)

	updReqDeactivate := model.APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("test-os-updated-deactivate"), Description: cdb.GetStrPtr("Updated Description for deactivation"), IsActive: cdb.GetBoolPtr(false), DeactivationNote: cdb.GetStrPtr("Deactivated for a valid reason")}
	okBodyDeactivate, err := json.Marshal(updReqDeactivate)
	assert.Nil(t, err)

	updReqDeactivateNoNote := model.APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("test-os-updated-deactivate-no-note"), Description: cdb.GetStrPtr("Updated Description for deactivation"), IsActive: cdb.GetBoolPtr(false)}
	okBodyDeactivateNoNote, err := json.Marshal(updReqDeactivateNoNote)
	assert.Nil(t, err)

	updReqChangeNote := model.APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("test-os-updated-change-note"), DeactivationNote: cdb.GetStrPtr("Changed Note")}
	okBodyChangeNote, err := json.Marshal(updReqChangeNote)
	assert.Nil(t, err)

	updReqActivate := model.APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("test-os-updated-activate"), Description: cdb.GetStrPtr("Updated Description for activation"), IsActive: cdb.GetBoolPtr(true)}
	okBodyActivate, err := json.Marshal(updReqActivate)
	assert.Nil(t, err)

	errBodyDoesntValidate, err := json.Marshal(struct{ Name string }{Name: "t"})
	assert.Nil(t, err)

	// OTEL Spanner configuration
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	// Mock per-Site client for st1
	tsc := &tmocks.Client{}

	// Prepare client pool for sync calls
	// to site(s).
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)
	scp.IDClientMap[site.ID.String()] = tsc

	wid := "test-workflow-id"
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return(wid)

	wrun.Mock.On("Get", mock.Anything, mock.Anything).Return(nil)

	tempClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		mock.AnythingOfType("func(internal.Context, uuid.UUID, uuid.UUID) error"), mock.AnythingOfType("uuid.UUID"),
		mock.AnythingOfType("uuid.UUID")).Return(wrun, nil)

	tsc.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		"UpdateOsImage", mock.Anything).Return(wrun, nil)

	// Mock timeout error
	tsc1 := &tmocks.Client{}
	scp.IDClientMap[site1.ID.String()] = tsc1

	wruntimeout := &tmocks.WorkflowRun{}
	wruntimeout.On("GetID").Return("test-workflow-timeout-id")

	wruntimeout.Mock.On("Get", mock.Anything, mock.Anything).Return(tp.NewTimeoutError(enums.TIMEOUT_TYPE_UNSPECIFIED, nil, nil))

	tsc1.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		"UpdateOsImage", mock.Anything).Return(wruntimeout, nil)

	tsc1.Mock.On("TerminateWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	tests := []struct {
		name           string
		reqOrgName     string
		user           *cdbm.User
		reqBody        string
		reqUpdateModel *model.APIOperatingSystemUpdateRequest
		osID           string
		expectedErr    bool
		expectedStatus int

		expectedName             *string
		expectedDesc             *string
		expectedIpxeScript       *string
		expectedImageURL         *string
		expectedUserData         *string
		expectedIsCloudInit      *bool
		expectedAllowOverride    *bool
		expectedPhoneHomeEnabled *bool
		expectedIsActive         *bool
		expectedDeactivationNote *string
		verifyChildSpanner       bool
	}{
		{
			name:           "error when user not found in request context",
			reqOrgName:     ipOrg1,
			user:           nil,
			expectedErr:    true,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "error when user not found in org",
			reqOrgName:     "SomeOrg",
			user:           user,
			expectedErr:    true,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "error when tenant doesnt exist for org",
			reqOrgName:     ipOrg3,
			user:           user,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when os id doesnt exist",
			reqOrgName:     ipOrg1,
			user:           user,
			osID:           uuid.New().String(),
			expectedErr:    true,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "error when os tenant doesnt match tenant in org",
			reqOrgName:     ipOrg1,
			user:           user,
			osID:           os2.ID.String(),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when req body doesnt bind",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        "bad-body",
			osID:           os1.ID.String(),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when req body doesnt validate",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        string(errBodyDoesntValidate),
			osID:           os1.ID.String(),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when updated name clashes",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        string(errBodyNameClash),
			osID:           os1.ID.String(),
			expectedErr:    true,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "error when os created with ipxe but request to update imageURL ",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        string(errBodyImageUrlIpxe),
			osID:           os4.ID.String(),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "success when updated with same name",
			reqOrgName:     ipOrg2,
			user:           user,
			reqBody:        string(okBody2),
			osID:           os2.ID.String(),
			expectedErr:    false,
			expectedStatus: http.StatusOK,

			expectedName: cdb.GetStrPtr("test-operating-system-2"),
		},
		{
			name:           "success case - can update all fields",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        string(okBody),
			osID:           os1.ID.String(),
			expectedErr:    false,
			expectedStatus: http.StatusOK,

			expectedName:             cdb.GetStrPtr("test-os-updated"),
			expectedDesc:             cdb.GetStrPtr("Updated Description"),
			expectedIpxeScript:       cdb.GetStrPtr("updatedIpxe"),
			expectedUserData:         cdb.GetStrPtr(cdmu.TestCommonPhoneHomeCloudInit),
			expectedIsCloudInit:      cdb.GetBoolPtr(false),
			expectedAllowOverride:    cdb.GetBoolPtr(true),
			expectedPhoneHomeEnabled: cdb.GetBoolPtr(true),
			verifyChildSpanner:       true,
		},
		{
			name:           "should succeed to deactivate active OS",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        string(okBodyDeactivate),
			osID:           os10.ID.String(),
			expectedErr:    false,
			expectedStatus: http.StatusOK,

			expectedName:             updReqDeactivate.Name,
			expectedDesc:             updReqDeactivate.Description,
			expectedIsActive:         cdb.GetBoolPtr(false),
			expectedDeactivationNote: updReqDeactivate.DeactivationNote,
		},
		{
			name:           "should succeed to deactivate active OS without Deactivation Note",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        string(okBodyDeactivateNoNote),
			osID:           os11.ID.String(),
			expectedErr:    false,
			expectedStatus: http.StatusOK,

			expectedName:             updReqDeactivateNoNote.Name,
			expectedDesc:             updReqDeactivateNoNote.Description,
			expectedIsActive:         cdb.GetBoolPtr(false),
			expectedDeactivationNote: updReqDeactivateNoNote.DeactivationNote,
		},
		{
			name:           "should fail to change Deactivation Note for an active OS",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        string(okBodyChangeNote),
			osID:           os1.ID.String(),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "should succeed to change Deactivation Note on deactivated OS",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        string(okBodyChangeNote),
			osID:           os12.ID.String(),
			expectedErr:    false,
			expectedStatus: http.StatusOK,

			expectedName:             updReqChangeNote.Name,
			expectedDesc:             updReqChangeNote.Description,
			expectedIsActive:         cdb.GetBoolPtr(false),
			expectedDeactivationNote: updReqChangeNote.DeactivationNote,
		},
		{
			name:           "should succeed to activate deactivated OS (3/4)",
			reqOrgName:     ipOrg1,
			user:           user,
			reqBody:        string(okBodyActivate),
			osID:           os13.ID.String(),
			expectedErr:    false,
			expectedStatus: http.StatusOK,

			expectedName:             updReqActivate.Name,
			expectedDesc:             updReqActivate.Description,
			expectedIsActive:         cdb.GetBoolPtr(false),
			expectedDeactivationNote: nil,
		},
		{
			name:             "success when updated with required valid imageURL attribute",
			reqOrgName:       ipOrg1,
			user:             user,
			reqBody:          string(okBodyImageUrl),
			reqUpdateModel:   &updReqImageUrl,
			osID:             os5.ID.String(),
			expectedErr:      false,
			expectedStatus:   http.StatusOK,
			expectedImageURL: cdb.GetStrPtr("http://newimagepath.iso"),
		},
		{
			name:           "error when updated with required valid imageURL attribute failed with context deadline error",
			reqOrgName:     ipOrg2,
			user:           user,
			reqBody:        string(okBodyImageUrl),
			reqUpdateModel: &updReqImageUrl,
			osID:           os9.ID.String(),
			expectedErr:    true,
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, tc.name, "")

			// Setup echo server/context
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.reqBody))

			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			names := []string{"orgName", "id"}
			ec.SetParamNames(names...)
			values := []string{tc.reqOrgName, tc.osID}
			ec.SetParamValues(values...)
			if tc.user != nil {
				ec.Set("user", tc.user)
			}

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			tah := UpdateOperatingSystemHandler{
				dbSession: dbSession,
				tc:        tempClient,
				cfg:       cfg,
				scp:       scp,
			}
			err := tah.Handle(ec)
			assert.Nil(t, err)

			assert.Equal(t, tc.expectedStatus, rec.Code)
			assert.Equal(t, tc.expectedErr, rec.Code != http.StatusOK)

			if !tc.expectedErr {
				rsp := &model.APIOperatingSystem{}
				err := json.Unmarshal(rec.Body.Bytes(), rsp)
				assert.Nil(t, err)

				if tc.expectedName != nil {
					assert.Equal(t, *tc.expectedName, rsp.Name)
				}

				if tc.expectedDesc != nil {
					assert.Equal(t, *tc.expectedDesc, *rsp.Description)
				}

				if tc.expectedIpxeScript != nil {
					assert.Equal(t, *tc.expectedIpxeScript, *rsp.IpxeScript)
					assert.Equal(t, "iPXE", *rsp.Type)
				}

				if tc.expectedUserData != nil && tc.expectedPhoneHomeEnabled != nil && !*tc.expectedPhoneHomeEnabled {
					assert.Equal(t, *tc.expectedUserData, *rsp.UserData)
				}

				if tc.expectedIsCloudInit != nil {
					assert.Equal(t, *tc.expectedIsCloudInit, rsp.IsCloudInit)
				}

				if tc.expectedAllowOverride != nil {
					assert.Equal(t, *tc.expectedAllowOverride, rsp.AllowOverride)
				}

				if tc.expectedImageURL != nil {
					assert.Equal(t, *tc.expectedImageURL, *rsp.ImageURL)
					assert.Equal(t, cdbm.OperatingSystemTypeImage, *rsp.Type)
					if tc.reqUpdateModel != nil {
						if tc.reqUpdateModel.ImageSHA != nil {
							assert.Equal(t, *tc.reqUpdateModel.ImageSHA, *rsp.ImageSHA)
						}
						if tc.reqUpdateModel.ImageAuthType != nil {
							assert.Equal(t, *tc.reqUpdateModel.ImageAuthType, *rsp.ImageAuthType)
						}
						if tc.reqUpdateModel.ImageAuthToken != nil {
							assert.Equal(t, *tc.reqUpdateModel.ImageAuthToken, *rsp.ImageAuthToken)
						}
						if tc.reqUpdateModel.ImageDisk != nil {
							assert.Equal(t, *tc.reqUpdateModel.ImageDisk, *rsp.ImageDisk)
						}
						if tc.reqUpdateModel.RootFsID != nil {
							assert.Equal(t, *tc.reqUpdateModel.RootFsID, *rsp.RootFsID)
						}
						if tc.reqUpdateModel.RootFsLabel != nil {
							assert.Equal(t, *tc.reqUpdateModel.RootFsLabel, *rsp.RootFsLabel)
						}

					}
				}
			}

			if tc.verifyChildSpanner {
				span := oteltrace.SpanFromContext(ec.Request().Context())
				assert.True(t, span.SpanContext().IsValid())
			}
		})
	}
}

func TestOperatingSystemHandler_Delete(t *testing.T) {
	ctx := context.Background()
	dbSession := testMachineInitDB(t)
	defer dbSession.Close()

	common.TestSetupSchema(t, dbSession)

	// Add user entry
	ipOrg1 := "test-ip-org-1"
	ipOrg2 := "test-ip-org-2"
	ipOrg3 := "test-ip-org-3"
	ipRoles := []string{authz.ProviderAdminRole}

	ipu := testMachineBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg1, ipOrg2, ipOrg3}, ipRoles)

	tnOrg1 := "test-tn-org-1"
	tnOrg2 := "test-tn-org-2"
	tnOrg3 := "test-tn-org-3"
	tnOrg4 := "test-tn-org-4"
	tnRoles := []string{authz.TenantAdminRole}

	tnu := testMachineBuildUser(t, dbSession, uuid.New().String(), []string{tnOrg1, tnOrg2, tnOrg3, tnOrg4}, tnRoles)

	ip3 := testIPBlockBuildInfrastructureProvider(t, dbSession, "TestIp", ipOrg3, ipu)
	site := testIPBlockBuildSite(t, dbSession, ip3, "testSite", cdbm.SiteStatusRegistered, true, ipu)
	assert.NotNil(t, site)

	site2 := testIPBlockBuildSite(t, dbSession, ip3, "testSite2", cdbm.SiteStatusRegistered, true, ipu)
	assert.NotNil(t, site2)

	tenant1 := testMachineBuildTenant(t, dbSession, tnOrg1, "t1")
	testMachineBuildTenant(t, dbSession, tnOrg2, "t2")
	tenant3 := testMachineBuildTenant(t, dbSession, tnOrg3, "t3")

	ts1 := testBuildTenantSiteAssociation(t, dbSession, tnOrg1, tenant1.ID, site.ID, tnu.ID)
	assert.NotNil(t, ts1)

	ts2 := testBuildTenantSiteAssociation(t, dbSession, tnOrg2, tenant3.ID, site2.ID, tnu.ID)
	assert.NotNil(t, ts2)

	vpc3 := testAllocationBuildVpc(t, dbSession, ip3, site, tenant3, ipOrg3, "testVPC")

	cfg := common.GetTestConfig()

	osDAO := cdbm.NewOperatingSystemDAO(dbSession)
	os1, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:               "test1",
		Description:        cdb.GetStrPtr("test"),
		Org:                ipOrg1,
		TenantID:           &tenant1.ID,
		OsType:             cdbm.OperatingSystemTypeIPXE,
		IpxeScript:         cdb.GetStrPtr("ipxe"),
		IsCloudInit:        true,
		AllowOverride:      false,
		EnableBlockStorage: false,
		PhoneHomeEnabled:   false,
		Status:             cdbm.OperatingSystemStatusPending,
		CreatedBy:          tnu.ID,
	})
	assert.Nil(t, err)
	assert.NotNil(t, os1)
	os3, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
		Name:               "test2",
		Description:        cdb.GetStrPtr("test"),
		Org:                ipOrg3,
		TenantID:           &tenant3.ID,
		OsType:             cdbm.OperatingSystemTypeIPXE,
		IpxeScript:         cdb.GetStrPtr("ipxe"),
		IsCloudInit:        true,
		AllowOverride:      false,
		EnableBlockStorage: false,
		PhoneHomeEnabled:   false,
		Status:             cdbm.OperatingSystemStatusPending,
		CreatedBy:          tnu.ID,
	})
	assert.Nil(t, err)
	assert.NotNil(t, os3)

	ipamStorage := ipam.NewIpamStorage(dbSession.DB, nil)
	it3 := testMachineBuildInstanceType(t, dbSession, ip3, site, "testIT")

	// build some machines, and map the machines to the instancetypes
	for i := 1; i <= 3; i++ {
		mc := testInstanceBuildMachine(t, dbSession, ip3.ID, site.ID, cdb.GetBoolPtr(false), nil)
		assert.NotNil(t, mc)
		mcinst1 := testInstanceBuildMachineInstanceType(t, dbSession, mc, it3)
		assert.NotNil(t, mcinst1)
	}

	acGoodIT := model.APIAllocationConstraintCreateRequest{ResourceType: cdbm.AllocationResourceTypeInstanceType, ResourceTypeID: it3.ID.String(), ConstraintType: cdbm.AllocationConstraintTypeReserved, ConstraintValue: 2}
	okBodyIT, err := json.Marshal(model.APIAllocationCreateRequest{Name: "ok1", Description: cdb.GetStrPtr(""), TenantID: tenant3.ID.String(), SiteID: site.ID.String(), AllocationConstraints: []model.APIAllocationConstraintCreateRequest{acGoodIT}})
	assert.Nil(t, err)
	testCreateAllocation(t, dbSession, ipamStorage, ipu, ipOrg3, string(okBodyIT))
	instanceDAO := cdbm.NewInstanceDAO(dbSession)
	instance, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "testInst",
			TenantID:                 tenant3.ID,
			InfrastructureProviderID: ip3.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &it3.ID,
			VpcID:                    vpc3.ID,
			OperatingSystemID:        &os3.ID,
			Status:                   cdbm.InstanceStatusReady,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, instance)

	os5, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-5",
			Description:        cdb.GetStrPtr("Test Description 5"),
			Org:                tnOrg1,
			TenantID:           &tenant1.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: true,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          tnu.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os5)

	// Add Operating System Site Association
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dbSession)
	ossaDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: os5.ID,
			SiteID:            site.ID,
			Version:           db.GetStrPtr("test"),
			Status:            cdbm.OperatingSystemSiteAssociationStatusSyncing,
			CreatedBy:         tnu.ID,
		},
	)

	os6, err := osDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemCreateInput{
			Name:               "test-operating-system-6",
			Description:        cdb.GetStrPtr("Test Description 6"),
			Org:                tnOrg3,
			TenantID:           &tenant3.ID,
			OsType:             cdbm.OperatingSystemTypeImage,
			ImageURL:           cdb.GetStrPtr("https://oldimagepath.iso"),
			IsCloudInit:        true,
			AllowOverride:      false,
			EnableBlockStorage: true,
			PhoneHomeEnabled:   false,
			Status:             cdbm.OperatingSystemStatusReady,
			CreatedBy:          tnu.ID,
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, os6)

	// Add Operating System Site Association
	ossaDAO.Create(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: os6.ID,
			SiteID:            site2.ID,
			Version:           db.GetStrPtr("test"),
			Status:            cdbm.OperatingSystemSiteAssociationStatusSyncing,
			CreatedBy:         tnu.ID,
		},
	)

	// OTEL Spanner configuration
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	// Prepare client pool for sync calls
	// to site(s).
	tcfg, _ := cfg.GetTemporalConfig()

	// Normal mocks
	tsc := &tmocks.Client{}
	tempClient := &tmocks.Client{}
	tempScp := sc.NewClientPool(tcfg)
	scp := sc.NewClientPool(tcfg)
	scp.IDClientMap[site.ID.String()] = tsc
	scp.IDClientMap[site2.ID.String()] = tsc

	wid := "test-workflow-id"
	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return(wid)

	wrun.Mock.On("Get", mock.Anything, mock.Anything).Return(nil)

	tempClient.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		mock.AnythingOfType("func(internal.Context, uuid.UUID, uuid.UUID) error"), mock.AnythingOfType("uuid.UUID"),
		mock.AnythingOfType("uuid.UUID")).Return(wrun, nil)

	tsc.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		"DeleteOsImage", mock.Anything).Return(wrun, nil)

	//
	// Timeout mocking
	//
	scpWithTimeout := sc.NewClientPool(tcfg)
	tscWithTimeout := &tmocks.Client{}

	scpWithTimeout.IDClientMap[site.ID.String()] = tscWithTimeout
	scpWithTimeout.IDClientMap[site2.ID.String()] = tscWithTimeout

	wrunTimeout := &tmocks.WorkflowRun{}
	wrunTimeout.On("GetID").Return("workflow-with-timeout")

	wrunTimeout.Mock.On("Get", mock.Anything, mock.Anything).Return(tp.NewTimeoutError(enums.TIMEOUT_TYPE_UNSPECIFIED, nil, nil))

	tscWithTimeout.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		"DeleteOsImage", mock.Anything).Return(wrunTimeout, nil)

	tscWithTimeout.Mock.On("TerminateWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	//
	// NICo not-found mocking
	//
	scpWithNICoNotFound := sc.NewClientPool(tcfg)
	tscWithNICoNotFound := &tmocks.Client{}

	scpWithNICoNotFound.IDClientMap[site.ID.String()] = tscWithNICoNotFound
	scpWithNICoNotFound.IDClientMap[site2.ID.String()] = tscWithNICoNotFound

	wrunWithNICoNotFound := &tmocks.WorkflowRun{}
	wrunWithNICoNotFound.On("GetID").Return("workflow-WithNICoNotFound")

	wrunWithNICoNotFound.Mock.On("Get", mock.Anything, mock.Anything).Return(tp.NewNonRetryableApplicationError("NICo went bananas", swe.ErrTypeNICoObjectNotFound, errors.New("NICo went bananas")))

	tscWithNICoNotFound.Mock.On("ExecuteWorkflow", mock.Anything, mock.AnythingOfType("internal.StartWorkflowOptions"),
		"DeleteOsImage", mock.Anything).Return(wrunWithNICoNotFound, nil)

	tscWithNICoNotFound.Mock.On("TerminateWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	tests := []struct {
		name               string
		reqOrgName         string
		user               *cdbm.User
		osID               string
		expectedErr        bool
		expectedStatus     int
		verifyChildSpanner bool
		tClient            *tmocks.Client
		clientPool         *sc.ClientPool
	}{
		{
			name:           "error when user not found in request context",
			reqOrgName:     tnOrg1,
			user:           nil,
			expectedErr:    true,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "error when user not found in org",
			reqOrgName:     "SomeOrg",
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "error when tenant doesnt exist for org",
			reqOrgName:     tnOrg4,
			user:           tnu,
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when os id doesnt exist",
			reqOrgName:     tnOrg1,
			user:           tnu,
			osID:           uuid.New().String(),
			expectedErr:    true,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "error when os tenant doesnt match tenant in org",
			reqOrgName:     tnOrg1,
			user:           tnu,
			osID:           os3.ID.String(),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "error when instance present for os",
			reqOrgName:     tnOrg3,
			user:           tnu,
			osID:           os3.ID.String(),
			expectedErr:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:               "success case",
			reqOrgName:         tnOrg1,
			user:               tnu,
			osID:               os1.ID.String(),
			expectedErr:        false,
			expectedStatus:     http.StatusAccepted,
			verifyChildSpanner: true,
		},
		{
			name:               "success case with OS image type",
			reqOrgName:         tnOrg1,
			user:               tnu,
			osID:               os5.ID.String(),
			expectedErr:        false,
			expectedStatus:     http.StatusAccepted,
			verifyChildSpanner: true,
			clientPool:         scp,
			tClient:            tsc,
		},
		{
			name:               "workflow timeout failure",
			reqOrgName:         tnOrg3,
			user:               tnu,
			osID:               os6.ID.String(),
			expectedErr:        true,
			expectedStatus:     http.StatusInternalServerError,
			verifyChildSpanner: true,
			clientPool:         scpWithTimeout,
			tClient:            tscWithTimeout,
		},
		{
			name:               "nico not-found success",
			reqOrgName:         tnOrg1,
			user:               tnu,
			osID:               os5.ID.String(),
			expectedErr:        false,
			expectedStatus:     http.StatusAccepted,
			verifyChildSpanner: true,
			clientPool:         scpWithNICoNotFound,
			tClient:            tscWithNICoNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, tc.name, "")

			// Setup echo server/context
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/", nil)

			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			ec := e.NewContext(req, rec)
			names := []string{"orgName", "id"}
			ec.SetParamNames(names...)
			values := []string{tc.reqOrgName, tc.osID}
			ec.SetParamValues(values...)
			if tc.user != nil {
				ec.Set("user", tc.user)
			}

			ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
			ec.SetRequest(ec.Request().WithContext(ctx))

			tClient := tempClient
			if tc.tClient != nil {
				tClient = tc.tClient
			}

			clientPool := tempScp
			if tc.clientPool != nil {
				clientPool = tc.clientPool
			}

			tah := DeleteOperatingSystemHandler{
				dbSession: dbSession,
				tc:        tClient,
				scp:       clientPool,
				cfg:       cfg,
			}
			err := tah.Handle(ec)
			assert.Nil(t, err)

			assert.Equal(t, tc.expectedStatus, rec.Code)
			assert.Equal(t, tc.expectedErr, rec.Code != http.StatusAccepted)

			if !tc.expectedErr {
				// check that os does not exist
				osDAO := cdbm.NewOperatingSystemDAO(dbSession)
				id1, err := uuid.Parse(tc.osID)
				assert.Nil(t, err)

				os, err := osDAO.GetByID(ctx, nil, id1, nil)
				if os != nil {
					assert.Equal(t, os.Type, cdbm.OperatingSystemTypeImage)
					assert.Equal(t, os.Status, cdbm.OperatingSystemStatusDeleting)
				} else {
					assert.NotNil(t, err)
				}
			}

			if tc.verifyChildSpanner {
				span := oteltrace.SpanFromContext(ec.Request().Context())
				assert.True(t, span.SpanContext().IsValid())
			}
		})
	}
}
