// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbu "github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	"github.com/NVIDIA/infra-controller-rest/workflow/internal/config"
	sc "github.com/NVIDIA/infra-controller-rest/workflow/pkg/client/site"
	"github.com/NVIDIA/infra-controller-rest/workflow/pkg/util"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/uptrace/bun/extra/bundebug"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"

	tnsv1 "go.temporal.io/api/namespace/v1"
	tOperatorv1 "go.temporal.io/api/operatorservice/v1"
	tWorkflowv1 "go.temporal.io/api/workflowservice/v1"

	tosv1mock "go.temporal.io/api/operatorservicemock/v1"
	twsv1mock "go.temporal.io/api/workflowservicemock/v1"
	tmocks "go.temporal.io/sdk/mocks"
)

// testTemporalSiteClientPool Building site client pool
func testTemporalSiteClientPool(t *testing.T) *sc.ClientPool {
	keyPath, certPath := config.SetupTestCerts(t)
	defer os.Remove(keyPath)
	defer os.Remove(certPath)

	cfg := config.NewConfig()
	cfg.SetTemporalCertPath(certPath)
	cfg.SetTemporalKeyPath(keyPath)
	cfg.SetTemporalCaPath(certPath)

	tcfg, err := cfg.GetTemporalConfig()
	assert.NoError(t, err)

	tSiteClientPool := sc.NewClientPool(tcfg)
	return tSiteClientPool
}

func testSiteInitDB(t *testing.T) *cdb.Session {
	dbSession := cdbu.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("BUNDEBUG"),
	))
	return dbSession
}

func TestManageSite_DeleteSiteComponentsFromDB(t *testing.T) {
	ctx := context.Background()

	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org-1"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, ipu)

	tnOrg := "test-tenant-org-1"
	tnRoles := []string{"FORGE_TENANT_ADMIN"}

	tnu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{tnOrg}, tnRoles)
	tncfg := cdbm.TenantConfig{
		EnableSSHAccess: true,
	}

	tenant := util.TestBuildTenant(t, dbSession, "test-tenant", tnOrg, &tncfg, tnu)

	vpcDAO := cdbm.NewVpcDAO(dbSession)
	ibpDAO := cdbm.NewInfiniBandPartitionDAO(dbSession)
	itDAO := cdbm.NewInstanceTypeDAO(dbSession)
	iDAO := cdbm.NewInstanceDAO(dbSession)

	// Site 1 that will be deleted normally
	site := util.TestBuildSite(t, dbSession, ip, "test-site", cdbm.SiteStatusPending, nil, ipu)
	vpc := util.TestBuildVpc(t, dbSession, ip, site, tenant, "test-vpc")
	machine := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, cdb.GetStrPtr("x86"), cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine2 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, cdb.GetStrPtr("x86"), cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	allocation := util.TestBuildAllocation(t, dbSession, ip, tenant, site, "test-allocation")
	instanceType := util.TestBuildInstanceType(t, dbSession, ip, site, "test-instance-type")
	_ = util.TestBuildAllocationContraints(t, dbSession, allocation, cdbm.AllocationResourceTypeInstanceType, instanceType.ID, cdbm.AllocationConstraintTypeReserved, 1, ipu)
	operatingSystem := util.TestBuildOperatingSystem(t, dbSession, "test-os")
	ibp := util.TestBuildInfiniBandPartition(t, dbSession, "test-infiniband-partition", site, tenant, nil, cdbm.InfiniBandInterfaceStatusReady, false)

	ins1, _ := iDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance",
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine.ID,
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusPending,
			PowerStatus:              cdb.GetStrPtr(cdbm.InstancePowerStatusRebooting),
			CreatedBy:                tnu.ID,
		},
	)

	ins2, _ := iDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-2",
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine2.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusPending,
			PowerStatus:              cdb.GetStrPtr(cdbm.InstancePowerStatusRebooting),
			CreatedBy:                tnu.ID,
		},
	)

	// Site 2 where the Machine components will be purged
	site2 := util.TestBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusPending, nil, ipu)
	vpc2 := util.TestBuildVpc(t, dbSession, ip, site2, tenant, "test-vpc-2")
	machine3 := util.TestBuildMachine(t, dbSession, ip.ID, site2.ID, cdb.GetStrPtr("mcTypeTest2"), cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine4 := util.TestBuildMachine(t, dbSession, ip.ID, site2.ID, cdb.GetStrPtr("mcTypeTest3"), cdb.GetBoolPtr(true), cdbm.MachineStatusReady)

	allocation2 := util.TestBuildAllocation(t, dbSession, ip, tenant, site2, "test-allocation-2")
	instanceType2 := util.TestBuildInstanceType(t, dbSession, ip, site2, "test-instance-type-2")
	_ = util.TestBuildAllocationContraints(t, dbSession, allocation2, cdbm.AllocationResourceTypeInstanceType, instanceType2.ID, cdbm.AllocationConstraintTypeReserved, 2, ipu)
	operatingSystem2 := util.TestBuildOperatingSystem(t, dbSession, "test-os-2")

	ins3, _ := iDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-3",
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site2.ID,
			InstanceTypeID:           &instanceType2.ID,
			VpcID:                    vpc2.ID,
			MachineID:                &machine3.ID,
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem2.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusPending,
			PowerStatus:              cdb.GetStrPtr(cdbm.InstancePowerStatusRebooting),
			CreatedBy:                tnu.ID,
		},
	)
	ins4, _ := iDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-4",
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site2.ID,
			InstanceTypeID:           &instanceType2.ID,
			VpcID:                    vpc2.ID,
			MachineID:                &machine4.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem2.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusPending,
			PowerStatus:              cdb.GetStrPtr(cdbm.InstancePowerStatusRebooting),
			CreatedBy:                tnu.ID,
		},
	)

	tSiteClientPool := testTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	temporalsuit := testsuite.WorkflowTestSuite{}
	env := temporalsuit.NewTestWorkflowEnvironment()

	type fields struct {
		dbSession      *cdb.Session
		siteClientPool *sc.ClientPool
		env            *testsuite.TestWorkflowEnvironment
	}

	type args struct {
		ctx            context.Context
		siteID         uuid.UUID
		ipID           *uuid.UUID
		vpcID          *uuid.UUID
		ibpID          *uuid.UUID
		machineIDs     []string
		instanceTypeID *uuid.UUID
		instanceIDs    []uuid.UUID
		purgeMachines  bool
	}

	tests := []struct {
		name           string
		fields         fields
		args           args
		want           error
		wantErr        bool
		expectDeletion bool
	}{
		{
			name: "test Site delete component activity successfully completed",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:            context.Background(),
				siteID:         site.ID,
				ipID:           &ip.ID,
				vpcID:          &vpc.ID,
				ibpID:          &ibp.ID,
				machineIDs:     []string{machine.ID, machine2.ID},
				instanceTypeID: &instanceType.ID,
				instanceIDs:    []uuid.UUID{ins1.ID, ins2.ID},
			},
			want:           nil,
			expectDeletion: true,
		},
		{
			name: "test Site delete component activity successfully completed when site doesn't exits",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    context.Background(),
				siteID: uuid.New(),
				ipID:   cdb.GetUUIDPtr(uuid.New()),
			},
			want:           nil,
			expectDeletion: false,
		},
		{
			name: "test Site delete component activity successfully completed with purge",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:            context.Background(),
				siteID:         site2.ID,
				ipID:           &ip.ID,
				vpcID:          &vpc2.ID,
				machineIDs:     []string{machine3.ID, machine4.ID},
				instanceTypeID: &instanceType2.ID,
				instanceIDs:    []uuid.UUID{ins3.ID, ins4.ID},
				purgeMachines:  true,
			},
			want:           nil,
			expectDeletion: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mv := ManageSite{
				dbSession:      tt.fields.dbSession,
				siteClientPool: tSiteClientPool,
			}

			err := mv.DeleteSiteComponentsFromDB(tt.args.ctx, tt.args.siteID, *tt.args.ipID, tt.args.purgeMachines)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			// Check if the VPC was deleted in the DB
			if tt.args.vpcID != nil {
				_, err = vpcDAO.GetByID(ctx, nil, *tt.args.vpcID, nil)
				if tt.expectDeletion {
					assert.Equal(t, cdb.ErrDoesNotExist, err)
				}
			}

			// Check if Instance Type is deleted from DB
			if tt.args.instanceTypeID != nil {
				_, err = itDAO.GetByID(ctx, nil, *tt.args.instanceTypeID, nil)
				if tt.expectDeletion {
					assert.Equal(t, cdb.ErrDoesNotExist, err)
				}
			}

			// Check if InfinitBand Partition is deleted from DB
			if tt.args.ibpID != nil {
				_, err := ibpDAO.GetByID(ctx, nil, *tt.args.ibpID, nil)
				if tt.expectDeletion {
					assert.Equal(t, cdb.ErrDoesNotExist, err)
				}
			}

			if tt.expectDeletion {
				// Check if Machines are deleted from DB
				for _, mID := range tt.args.machineIDs {
					var res cdbm.Machine
					if tt.args.purgeMachines {
						err = dbSession.DB.NewSelect().Model(&res).Where("m.id = ?", mID).WhereAllWithDeleted().Scan(ctx)
					} else {
						err = dbSession.DB.NewSelect().Model(&res).Where("m.id = ?", mID).Scan(ctx)
					}

					assert.Equal(t, sql.ErrNoRows, err)
				}

				// Check if Instances are deleted from DB
				for _, iID := range tt.args.instanceIDs {
					var res cdbm.Instance

					err = dbSession.DB.NewSelect().Model(&res).Where("i.id = ?", iID).Scan(ctx)
					assert.Equal(t, sql.ErrNoRows, err)

					if tt.args.purgeMachines {
						err = dbSession.DB.NewSelect().Model(&res).Where("i.id = ?", iID).WhereAllWithDeleted().Scan(ctx)
						assert.NoError(t, err)
						assert.Nil(t, res.MachineID)
					}
				}
			}
		})
	}
}

func TestNewManageSite(t *testing.T) {
	type args struct {
		dbSession      *cdb.Session
		siteClientPool *sc.ClientPool
		tc             client.Client
		cfg            *config.Config
	}

	dbSession := &cdb.Session{}
	keyPath, certPath := config.SetupTestCerts(t)
	defer os.Remove(keyPath)
	defer os.Remove(certPath)

	cfg := config.NewConfig()
	cfg.SetTemporalCertPath(certPath)
	cfg.SetTemporalKeyPath(keyPath)
	cfg.SetTemporalCaPath(certPath)

	tcfg, err := cfg.GetTemporalConfig()
	assert.NoError(t, err)

	tc := &tmocks.Client{}
	scp := sc.NewClientPool(tcfg)

	tests := []struct {
		name string
		args args
		want ManageSite
	}{
		{
			name: "test new ManageSite instantiation",
			args: args{
				dbSession:      dbSession,
				siteClientPool: scp,
				tc:             tc,
				cfg:            cfg,
			},
			want: ManageSite{
				dbSession:      dbSession,
				siteClientPool: scp,
				tc:             tc,
				cfg:            cfg,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewManageSite(tt.args.dbSession, tt.args.siteClientPool, tc, cfg); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewManageSite() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManageSite_MonitorInventoryReceiptForAllSites(t *testing.T) {
	ctx := context.Background()

	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org-1"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, ipu)

	site1 := util.TestBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusPending, nil, ipu)
	site2 := util.TestBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered, cdb.GetTimePtr(time.Now().Add(-1*time.Hour)), ipu)
	site3 := util.TestBuildSite(t, dbSession, ip, "test-site-3", cdbm.SiteStatusRegistered, cdb.GetTimePtr(time.Now()), ipu)
	site4 := util.TestBuildSite(t, dbSession, ip, "test-site-4", cdbm.SiteStatusRegistered, cdb.GetTimePtr(time.Now().Add(-1*time.Hour)), ipu)

	tSiteClientPool := testTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	temporalsuit := testsuite.WorkflowTestSuite{}
	temporalsuit.NewTestWorkflowEnvironment()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	cfg := config.NewConfig()
	cfg.SetNotificationsSlackWebhookURL(testServer.URL)

	cfg2 := config.NewConfig()
	cfg2.SetNotificationsSlackWebhookURL("")

	type fields struct {
		dbSession      *cdb.Session
		siteClientPool *sc.ClientPool
		cfg            *config.Config
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantStatus map[uuid.UUID]string
	}{
		{
			name: "test monitor inventory receipt for all sites with Slack notification",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				cfg:            cfg,
			},
			args: args{
				ctx: ctx,
			},
			wantStatus: map[uuid.UUID]string{
				site1.ID: cdbm.SiteStatusPending,
				site2.ID: cdbm.SiteStatusError,
				site3.ID: cdbm.SiteStatusRegistered,
			},
		},
		{
			name: "test monitor inventory receipt for all sites without Slack notification",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				cfg:            cfg2,
			},
			args: args{
				ctx: ctx,
			},
			wantStatus: map[uuid.UUID]string{
				site4.ID: cdbm.SiteStatusError,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mst := ManageSite{
				dbSession:      tt.fields.dbSession,
				siteClientPool: tt.fields.siteClientPool,
				cfg:            tt.fields.cfg,
			}
			err := mst.MonitorInventoryReceiptForAllSites(tt.args.ctx)
			assert.NoError(t, err)

			for siteID, wantStatus := range tt.wantStatus {
				siteDAO := cdbm.NewSiteDAO(dbSession)
				site, err := siteDAO.GetByID(ctx, nil, siteID, nil, false)
				assert.NoError(t, err)
				assert.Equal(t, wantStatus, site.Status)
			}
		})
	}
}

func TestManageSite_MonitorInventoryReceiptForAllSites_PagerDutyEnabled(t *testing.T) {
	ctx := context.Background()

	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org-1"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, ipu)

	// Create sites with expired inventory receipt times
	site1 := util.TestBuildSite(t, dbSession, ip, "pagerduty-test-site-1", cdbm.SiteStatusRegistered, cdb.GetTimePtr(time.Now().Add(-2*time.Hour)), ipu)
	site2 := util.TestBuildSite(t, dbSession, ip, "pagerduty-test-site-2", cdbm.SiteStatusRegistered, cdb.GetTimePtr(time.Now().Add(-30*time.Minute)), ipu)

	tSiteClientPool := testTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	temporalsuit := testsuite.WorkflowTestSuite{}
	temporalsuit.NewTestWorkflowEnvironment()

	// Create a mock PagerDuty server
	pdEventCount := 0
	testPagerDutyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate it's a POST request to the right path
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v2/enqueue", r.URL.Path)

		pdEventCount++

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"success","message":"Event processed","dedup_key":"test-dedup-key"}`))
	}))
	defer testPagerDutyServer.Close()

	// Override the default http.Client to redirect PagerDuty requests to our test server
	originalTransport := http.DefaultTransport
	http.DefaultTransport = &mockPagerDutyTransport{
		testServerURL: testPagerDutyServer.URL,
		original:      originalTransport,
	}
	defer func() {
		http.DefaultTransport = originalTransport
	}()

	// Configure PagerDuty
	cfg := config.NewConfig()
	cfg.SetNotificationsPagerDutyIntegrationKey("test-integration-key")

	mst := ManageSite{
		dbSession:      dbSession,
		siteClientPool: tSiteClientPool,
		cfg:            cfg,
	}

	err := mst.MonitorInventoryReceiptForAllSites(ctx)
	assert.NoError(t, err)

	// Verify site statuses were updated correctly
	siteDAO := cdbm.NewSiteDAO(dbSession)
	site1Result, err := siteDAO.GetByID(ctx, nil, site1.ID, nil, false)
	assert.NoError(t, err)
	assert.Equal(t, cdbm.SiteStatusError, site1Result.Status)

	site2Result, err := siteDAO.GetByID(ctx, nil, site2.ID, nil, false)
	assert.NoError(t, err)
	assert.Equal(t, cdbm.SiteStatusError, site2Result.Status)

	// Assert on PagerDuty events received (both sites should trigger alerts)
	assert.Equal(t, 2, pdEventCount, "Expected 2 PagerDuty events but got %d", pdEventCount)
}

func TestManageSite_MonitorInventoryReceiptForAllSites_PagerDutyDisabled(t *testing.T) {
	ctx := context.Background()

	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org-1"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, ipu)

	// Create sites with expired inventory receipt times
	_ = util.TestBuildSite(t, dbSession, ip, "pagerduty-test-site-3", cdbm.SiteStatusRegistered, cdb.GetTimePtr(time.Now().Add(-2*time.Hour)), ipu)
	_ = util.TestBuildSite(t, dbSession, ip, "pagerduty-test-site-4", cdbm.SiteStatusRegistered, cdb.GetTimePtr(time.Now().Add(-30*time.Minute)), ipu)

	tSiteClientPool := testTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	temporalsuit := testsuite.WorkflowTestSuite{}
	temporalsuit.NewTestWorkflowEnvironment()

	cfg := config.NewConfig()

	mst := ManageSite{
		dbSession:      dbSession,
		siteClientPool: tSiteClientPool,
		cfg:            cfg,
	}

	err := mst.MonitorInventoryReceiptForAllSites(ctx)
	assert.NoError(t, err)
}

// mockPagerDutyTransport intercepts requests to PagerDuty and redirects them to a test server
type mockPagerDutyTransport struct {
	testServerURL string
	original      http.RoundTripper
}

func (m *mockPagerDutyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Intercept requests to PagerDuty's API
	if req.URL.Host == "events.pagerduty.com" {
		// Redirect to our test server
		req.URL.Scheme = "http"
		req.URL.Host = m.testServerURL[7:] // Remove "http://" prefix
		return m.original.RoundTrip(req)
	}
	// Pass through all other requests
	return m.original.RoundTrip(req)
}

// MockTemporalClient is a mock for Temporal Client
type MockTemporalClient struct {
	mock.Mock
}

func (m *MockTemporalClient) ExecuteWorkflow(ctx context.Context, options client.StartWorkflowOptions, workflow interface{}, args ...interface{}) (client.WorkflowRun, error) {
	argsM := m.Called(ctx, options, workflow, args)
	return argsM.Get(0).(client.WorkflowRun), argsM.Error(1)
}

func TestManageSite_CheckOTPExpirationAndRenewForAllSites(t *testing.T) {
	ctx := context.Background()

	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	// Initialize schema and mock data
	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org-1"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, ipu)

	site1 := util.TestBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusRegistered, nil, ipu)
	site2 := util.TestBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered, nil, ipu)

	// Mock the HTTP server to simulate Site Manager responses
	almostExpired := time.Now().Add(-23 * time.Hour).Format("2006-01-02 15:04:05 -0700 MST")
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"siteuuid": "` + uuid.New().String() + `",
			"otp": "mocked-otp",
			"otpexpiry": "` + almostExpired + `"
		}`))
	}))
	defer testServer.Close()

	// Mock Temporal Client
	wrun1 := &tmocks.WorkflowRun{}
	wrun1.On("GetID").Return("test-workflow-id-1")

	mockTemporalClient := &tmocks.Client{}
	mockTemporalClient.On("ExecuteWorkflow", mock.Anything, mock.Anything, "RotateTemporalCertAccessOTP", mock.Anything).Return(wrun1, nil)

	tSiteClientPool := sc.NewClientPool(nil)
	tSiteClientPool.IDClientMap[site1.ID.String()] = mockTemporalClient
	tSiteClientPool.IDClientMap[site2.ID.String()] = mockTemporalClient

	// Set up test environment
	cfg := config.NewConfig()
	cfg.SetSiteManagerEndpoint(testServer.URL)

	temporalsuit := testsuite.WorkflowTestSuite{}
	temporalsuit.NewTestWorkflowEnvironment()

	// Define test cases
	type fields struct {
		dbSession      *cdb.Session
		siteClientPool *sc.ClientPool
	}
	tests := []struct {
		name       string
		fields     fields
		wantErr    bool
		wantStatus map[uuid.UUID]string
	}{
		{
			name: "Test OTP expiration and renewal for all sites with no errors",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
			},
			wantErr: false,
			wantStatus: map[uuid.UUID]string{
				site1.ID: cdbm.SiteStatusRegistered,
				site2.ID: cdbm.SiteStatusRegistered,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mst := ManageSite{
				dbSession:      tt.fields.dbSession,
				siteClientPool: tt.fields.siteClientPool,
				cfg:            cfg,
			}

			err := mst.CheckOTPExpirationAndRenewForAllSites(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckOTPExpirationAndRenewForAllSites() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for siteID, wantStatus := range tt.wantStatus {
				siteDAO := cdbm.NewSiteDAO(dbSession)
				site, err := siteDAO.GetByID(ctx, nil, siteID, nil, false)
				assert.NoError(t, err)
				assert.Equal(t, wantStatus, site.Status)
			}
		})
	}
}

func TestManageSite_CheckOTPExpirationAndRenewForAllSites_MoreThanDefaultPageSize(t *testing.T) {
	ctx := context.Background()
	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	// Initialize schema and mock data
	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org-1"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, ipu)

	// Create more than 20 sites to exceed the default page size.
	siteCount := 25
	siteIDs := make([]uuid.UUID, 0, siteCount)
	for i := 1; i <= siteCount; i++ {
		site := util.TestBuildSite(t, dbSession, ip, fmt.Sprintf("test-site-%d", i), cdbm.SiteStatusRegistered, nil, ipu)
		siteIDs = append(siteIDs, site.ID)
	}
	almostExpiredTime := time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04:05 -0700 MST")

	requestCount := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
            "siteuuid": "` + uuid.New().String() + `",
            "otp": "mocked-otp",
            "otpexpiry": "` + almostExpiredTime + `"
        }`))
	}))
	defer testServer.Close()

	wrun := &tmocks.WorkflowRun{}
	wrun.On("GetID").Return("test-workflow-id")

	mockTemporalClient := &tmocks.Client{}
	mockTemporalClient.On(
		"ExecuteWorkflow",
		mock.Anything, // context
		mock.Anything, // StartWorkflowOptions
		"RotateTemporalCertAccessOTP",
		mock.Anything, // OTP
	).Return(wrun, nil)

	tSiteClientPool := sc.NewClientPool(nil)
	for _, sid := range siteIDs {
		tSiteClientPool.IDClientMap[sid.String()] = mockTemporalClient
	}

	// Set up config with the test server's endpoint
	cfg := config.NewConfig()
	cfg.SetSiteManagerEndpoint(testServer.URL)

	mst := ManageSite{
		dbSession:      dbSession,
		siteClientPool: tSiteClientPool,
		cfg:            cfg}

	err := mst.CheckOTPExpirationAndRenewForAllSites(ctx)
	require.NoError(t, err, "Expected no error from CheckOTPExpirationAndRenewForAllSites")

	// Assert that the site-manager endpoint was called as many times as the number of sites
	// times 2: Once because we'll call RollSite and once for GetSiteOTP again
	assert.Equal(t, siteCount*2, requestCount, "Expected site manager to be called for all sites")

	// Assert that Temporal client was called for each site
	assert.Equal(t, siteCount, len(mockTemporalClient.Calls), "Expected Temporal client to be called for all sites")
}

func TestManageSite_UpdateAgentCertExpiry_Activity(t *testing.T) {
	ctx := context.Background()

	dbSession := cdbu.GetTestDBSession(t, false)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	// Create infrastructure provider org and user
	ipOrg := "test-provider-org-1"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}
	ipu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)

	// Create infrastructure provider with a valid user
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, ipu)

	// Create a site without AgentCertExpiry, providing the same user as createdBy
	site := util.TestBuildSite(t, dbSession, ip, "test-site", cdbm.SiteStatusRegistered, nil, ipu)

	mst := ManageSite{
		dbSession: dbSession,
	}

	// Check initial condition: AgentCertExpiry is nil
	siteDAO := cdbm.NewSiteDAO(dbSession)
	existingSite, err := siteDAO.GetByID(ctx, nil, site.ID, nil, false)
	assert.NoError(t, err)
	assert.Nil(t, existingSite.AgentCertExpiry)

	// Now let's update AgentCertExpiry
	newCertExpiry := time.Now().Add(48 * time.Hour).UTC().Round(time.Microsecond)
	err = mst.UpdateAgentCertExpiry(ctx, site.ID, newCertExpiry)
	assert.NoError(t, err)

	// Verify AgentCertExpiry is updated
	updatedSite, err := siteDAO.GetByID(ctx, nil, site.ID, nil, false)
	assert.NoError(t, err)
	assert.NotNil(t, updatedSite.AgentCertExpiry)
	assert.True(t, updatedSite.AgentCertExpiry.Equal(newCertExpiry))
}

func TestManageSite_DeleteOrphanedSiteTemporalNamespaces_Activity(t *testing.T) {
	ctx := context.Background()

	dbSession := cdbu.GetTestDBSession(t, false)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	// Create infrastructure provider org and user
	ipOrg := "test-provider-org-1"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}
	ipu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)

	// Create infrastructure provider with a valid user
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, ipu)

	stDAO := cdbm.NewSiteDAO(dbSession)

	// Create a site with a namespace
	site1 := util.TestBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, site1)
	site2 := util.TestBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, site2)
	site3 := util.TestBuildSite(t, dbSession, ip, "test-site-3", cdbm.SiteStatusRegistered, nil, ipu)
	err := stDAO.Delete(ctx, nil, site3.ID)
	assert.Nil(t, err)
	site4 := util.TestBuildSite(t, dbSession, ip, "test-site-4", cdbm.SiteStatusRegistered, nil, ipu)
	err = stDAO.Delete(ctx, nil, site4.ID)
	assert.Nil(t, err)
	site5 := util.TestBuildSite(t, dbSession, ip, "test-site-5", cdbm.SiteStatusRegistered, nil, ipu)
	err = stDAO.Delete(ctx, nil, site5.ID)
	assert.Nil(t, err)

	tc := &tmocks.Client{}
	gmockctrl1 := gomock.NewController(t)

	tws1 := twsv1mock.NewMockWorkflowServiceClient(gmockctrl1)

	nextPageToken := []byte("next-page-token")
	tws1.EXPECT().ListNamespaces(gomock.Any(), &tWorkflowv1.ListNamespacesRequest{
		PageSize:      100,
		NextPageToken: nil,
	}).Return(&tWorkflowv1.ListNamespacesResponse{
		Namespaces: []*tWorkflowv1.DescribeNamespaceResponse{
			{
				NamespaceInfo: &tnsv1.NamespaceInfo{
					Name: site1.ID.String(),
				},
			},
			{
				NamespaceInfo: &tnsv1.NamespaceInfo{
					Name: site2.ID.String(),
				},
			},
			{
				NamespaceInfo: &tnsv1.NamespaceInfo{
					Name: "cloud",
				},
			},
			{
				NamespaceInfo: &tnsv1.NamespaceInfo{
					Name: site3.ID.String(),
				},
			},
			{
				NamespaceInfo: &tnsv1.NamespaceInfo{
					Name: site4.ID.String(),
				},
			},
		},
		NextPageToken: nextPageToken,
	}, nil).Times(1)

	tws1.EXPECT().ListNamespaces(gomock.Any(), &tWorkflowv1.ListNamespacesRequest{
		PageSize:      100,
		NextPageToken: nextPageToken,
	}).Return(&tWorkflowv1.ListNamespacesResponse{
		Namespaces: []*tWorkflowv1.DescribeNamespaceResponse{
			{
				NamespaceInfo: &tnsv1.NamespaceInfo{
					Name: site5.ID.String(),
				},
			},
		},
		NextPageToken: nil,
	}, nil).Times(1)

	tc.Mock.On("WorkflowService").Return(tws1)

	tosc1 := tosv1mock.NewMockOperatorServiceClient(gmockctrl1)

	// Delete namespace should be called for the 2 random UUID namespaces
	tosc1.EXPECT().DeleteNamespace(gomock.Any(), gomock.Any()).Return(&tOperatorv1.DeleteNamespaceResponse{}, nil).Times(3)

	tc.Mock.On("OperatorService").Return(tosc1)

	temporalsuit := testsuite.WorkflowTestSuite{}
	temporalsuit.NewTestWorkflowEnvironment()

	mst := ManageSite{
		dbSession: dbSession,
		tc:        tc,
	}

	err = mst.DeleteOrphanedSiteTemporalNamespaces(ctx)
	assert.NoError(t, err, "Expected no error when deleting orphaned site temporal namespaces")

	gmockctrl1.Finish()
}

// TestManageSite_DeleteSiteComponentsFromDB_NewResources covers the additional
// site-scoped resources that DeleteSiteComponentsFromDB now cleans up
// (interfaces, vpc prefixes, vpc peerings, NVLink logical partitions,
// SSH key group site/instance associations, network security groups, DPU
// extension service deployments, SKUs, expected machine, expected switch, and
// expected powershelf records).
//
// The test builds the same set of records under two sites, runs the cleanup
// against site 1, and then asserts that:
//   - every site-1 record is gone (soft-deleted, or hard-deleted for SKU and
//     the expected_* tables which have no soft_delete column), and
//   - every site-2 record is still present and active.
//
// SSHKeyAssociation is intentionally not asserted on here: the workflow's
// current call to skaDAO.GetAll filters by sshKeyGroupIDs using the siteID,
// which is effectively a no-op (no group has a site UUID). It is built so the
// scenario is realistic but is not part of the cleanup contract being tested.
func TestManageSite_DeleteSiteComponentsFromDB_NewResources(t *testing.T) {
	ctx := context.Background()

	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org-1"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}
	ipu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "testIP", ipOrg, ipu)

	tnOrg := "test-tenant-org-1"
	tnRoles := []string{"FORGE_TENANT_ADMIN"}
	tnu := util.TestBuildUser(t, dbSession, uuid.New().String(), []string{tnOrg}, tnRoles)
	tncfg := cdbm.TenantConfig{EnableSSHAccess: true}
	tenant := util.TestBuildTenant(t, dbSession, "test-tenant", tnOrg, &tncfg, tnu)

	iDAO := cdbm.NewInstanceDAO(dbSession)
	operatingSystem := util.TestBuildOperatingSystem(t, dbSession, "test-os")

	// siteResources captures the IDs we expect to verify after the cleanup
	// runs. Pointer types are used where the underlying ID type isn't
	// uuid.UUID (NSG, SKU all use string IDs).
	type siteResources struct {
		site               *cdbm.Site
		instance           *cdbm.Instance
		vpc                *cdbm.Vpc
		ipBlock            *cdbm.IPBlock
		vpcPrefixID        uuid.UUID
		vpcPeeringID       uuid.UUID
		nvllpID            uuid.UUID
		nsgID              string
		skuID              string
		dpuDeploymentID    uuid.UUID
		interfaceIDs       []uuid.UUID
		ibInterfaceIDs     []uuid.UUID
		nvlinkInterfaceIDs []uuid.UUID
		sshKeyGroupSiteID  uuid.UUID
		sshKeyGroupInstID  uuid.UUID
		sshKeyAssocID      uuid.UUID
		expectedMachineID  uuid.UUID
		expectedSwitchID   uuid.UUID
		expectedShelfID    uuid.UUID
		imageOSSAID        uuid.UUID
	}

	buildSiteResources := func(tag string) *siteResources {
		site := util.TestBuildSite(t, dbSession, ip, "test-site-"+tag, cdbm.SiteStatusPending, nil, ipu)

		// Core dependencies for an instance. A second VPC is needed so the
		// VpcPeering row can satisfy its (vpc1_id, vpc2_id) foreign keys.
		vpc := util.TestBuildVpc(t, dbSession, ip, site, tenant, "vpc-"+tag)
		vpc2 := util.TestBuildVpc(t, dbSession, ip, site, tenant, "vpc2-"+tag)
		machine := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, cdb.GetStrPtr("x86"), cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
		instanceType := util.TestBuildInstanceType(t, dbSession, ip, site, "it-"+tag)

		instance, err := iDAO.Create(
			ctx, nil,
			cdbm.InstanceCreateInput{
				Name:                     "ins-" + tag,
				TenantID:                 tenant.ID,
				InfrastructureProviderID: ip.ID,
				SiteID:                   site.ID,
				InstanceTypeID:           &instanceType.ID,
				VpcID:                    vpc.ID,
				MachineID:                &machine.ID,
				Hostname:                 cdb.GetStrPtr(tag + ".test.com"),
				OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
				IpxeScript:               cdb.GetStrPtr("ipxe"),
				UserData:                 cdb.GetStrPtr("userdata"),
				Labels:                   map[string]string{},
				Status:                   cdbm.InstanceStatusPending,
				CreatedBy:                tnu.ID,
			},
		)
		require.NoError(t, err)

		// VPC Prefix needs an IPBlock.
		ipBlock := util.TestBuildBuildIPBlock(t, dbSession, "ipblock-"+tag, site, ip, &tenant.ID, cdbm.IPBlockRoutingTypeDatacenterOnly, "10.0.0.0/16", 16, cdbm.IPBlockProtocolVersionV4, true, cdbm.IPBlockStatusReady, ipu)
		vpcPrefix := util.TestBuildVPCPrefix(t, dbSession, "vpfx-"+tag, site, tenant, vpc.ID, &ipBlock.ID, cdb.GetStrPtr("10.1.0.0/24"), cdb.GetIntPtr(24), "Pending", ipu)

		// VpcPeering uses two distinct vpc1/vpc2 IDs and the schema enforces
		// real FKs on both, so we use the two VPCs created above.
		vpcPeering := util.TestBuildVpcPeering(t, dbSession, vpc.ID, vpc2.ID, site.ID, ip.ID, tenant.ID, ipu.ID)

		// NVLink logical partition + an NVLink interface attached to it.
		nvllp := util.TestBuildNVLinkLogicalPartition(t, dbSession, "nvllp-"+tag, nil, site, tenant, cdbm.NVLinkLogicalPartitionStatusReady, false)
		nvli := util.TestBuildNVLinkInterface(t, dbSession, instance.ID, site.ID, nvllp.ID, cdb.GetStrPtr("Nvidia GB200"), 0, cdb.GetStrPtr("guid-"+tag), nil, cdbm.NVLinkInterfaceStatusReady)

		// InfiniBand partition + an InfiniBand interface attached to it.
		ibp := util.TestBuildInfiniBandPartition(t, dbSession, "ibp-"+tag, site, tenant, nil, cdbm.InfiniBandPartitionStatusReady, false)
		ibi := util.TestBuildInfiniBandInterface(t, dbSession, instance.ID, site.ID, ibp.ID, "mlx5_0", 0, true, nil, cdbm.InfiniBandInterfaceStatusReady, false)

		// Two ethernet interfaces on the instance.
		iface1 := util.TestBuildInterface(t, dbSession, &instance.ID, nil, nil, true, cdb.GetStrPtr("eth0"), cdb.GetIntPtr(0), nil, &ipu.ID, cdbm.InterfaceStatusReady)
		iface2 := util.TestBuildInterface(t, dbSession, &instance.ID, nil, nil, false, cdb.GetStrPtr("eth1"), cdb.GetIntPtr(1), nil, &ipu.ID, cdbm.InterfaceStatusPending)

		// Network Security Group
		nsg := util.TestBuildNetworkSecurityGroup(t, dbSession, "nsg-"+tag, site, tenant, cdbm.NetworkSecurityGroupStatusReady, ipu)

		// DPU extension service + deployment
		des := util.TestBuildDpuExtensionService(t, dbSession, "des-"+tag, site, tenant, "test-type", cdb.GetStrPtr("v1"), nil, []string{"v1"}, cdbm.DpuExtensionServiceStatusReady, ipu)
		desd := util.TestBuildDpuExtensionServiceDeployment(t, dbSession, des.ID, site.ID, tenant.ID, instance.ID, "v1", cdbm.DpuExtensionServiceStatusReady, ipu)

		// SKU (hard delete)
		sku := util.TestBuildSku(t, dbSession, "sku-"+tag, site)

		// SSH key group + site/instance associations + key + key association.
		// The site/instance associations are scoped by SiteID; the key
		// association is intentionally unscoped (see test docstring).
		skg := util.TestBuildSSHKeyGroup(t, dbSession, "skg-"+tag, tenant.Org, nil, tenant.ID, cdb.GetStrPtr("v1"), cdbm.SSHKeyGroupStatusSynced, ipu.ID)
		skgsa := util.TestBuildSSHKeyGroupSiteAssociation(t, dbSession, skg.ID, site.ID, cdb.GetStrPtr("v1"), cdbm.SSHKeyGroupSiteAssociationStatusSynced, ipu.ID)
		skgia := util.TestBuildSSHKeyGroupInstanceAssociation(t, dbSession, skg.ID, site.ID, instance.ID, ipu.ID)
		sshKey := util.TestBuildSSHKey(t, dbSession, "key-"+tag, tenant, "ssh-rsa AAAA...", ipu)
		ska := util.TestBuildSSHKeyAssociation(t, dbSession, skg.ID, sshKey.ID, ipu.ID)

		// Expected records (hard-deleted by the workflow). MAC addresses are
		// scoped per-tag so the optional (bmc_mac_address, site_id) unique
		// constraint, if present, will not be tripped across sites.
		em := util.TestBuildExpectedMachine(t, dbSession, site, "00:11:22:33:44:0"+tag, "chassis-"+tag, ipu)
		es := util.TestBuildExpectedSwitch(t, dbSession, site, "00:11:22:33:55:0"+tag, "switch-"+tag, ipu)
		eps := util.TestBuildExpectedPowerShelf(t, dbSession, site, "00:11:22:33:66:0"+tag, "shelf-"+tag, ipu)

		// OperatingSystem with a single ossa on this site.
		imageOS := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, nil, "img-"+tag, ipOrg, cdb.GetStrPtr("v1"), cdbm.OperatingSystemStatusReady)
		imageOSSA := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, imageOS.ID, site.ID, cdbm.OperatingSystemSiteAssociationStatusSynced, "v1", false)

		return &siteResources{
			site:               site,
			instance:           instance,
			vpc:                vpc,
			ipBlock:            ipBlock,
			vpcPrefixID:        vpcPrefix.ID,
			vpcPeeringID:       vpcPeering.ID,
			nvllpID:            nvllp.ID,
			nsgID:              nsg.ID,
			skuID:              sku.ID,
			dpuDeploymentID:    desd.ID,
			interfaceIDs:       []uuid.UUID{iface1.ID, iface2.ID},
			ibInterfaceIDs:     []uuid.UUID{ibi.ID},
			nvlinkInterfaceIDs: []uuid.UUID{nvli.ID},
			sshKeyGroupSiteID:  skgsa.ID,
			sshKeyGroupInstID:  skgia.ID,
			sshKeyAssocID:      ska.ID,
			expectedMachineID:  em.ID,
			expectedSwitchID:   es.ID,
			expectedShelfID:    eps.ID,
			imageOSSAID:        imageOSSA.ID,
		}
	}

	site1Resources := buildSiteResources("a")
	site2Resources := buildSiteResources("b")

	tSiteClientPool := testTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	mv := ManageSite{
		dbSession:      dbSession,
		siteClientPool: tSiteClientPool,
	}

	err := mv.DeleteSiteComponentsFromDB(ctx, site1Resources.site.ID, ip.ID, false)
	require.NoError(t, err)

	// assertGone checks that a soft-deletable row identified by `id` is no
	// longer visible to a default (non-WhereAllWithDeleted) select. Caller
	// passes a fresh empty model pointer so we can vary the type.
	assertGone := func(label string, model interface{}, idColumn string, id interface{}) {
		t.Helper()
		err := dbSession.DB.NewSelect().Model(model).Where(idColumn+" = ?", id).Scan(ctx)
		assert.Equal(t, sql.ErrNoRows, err, "%s with id %v should be soft-deleted/hard-deleted", label, id)
	}

	// assertPresent checks that a row is still visible to a default select
	// (i.e. not soft-deleted).
	assertPresent := func(label string, model interface{}, idColumn string, id interface{}) {
		t.Helper()
		err := dbSession.DB.NewSelect().Model(model).Where(idColumn+" = ?", id).Scan(ctx)
		assert.NoError(t, err, "%s with id %v should still be present", label, id)
	}

	// --- Site 1: every site-scoped resource we built should be gone. ---

	// Ethernet interfaces (DeleteAllByInstanceIDs)
	for _, id := range site1Resources.interfaceIDs {
		assertGone("interface", &cdbm.Interface{}, "ifc.id", id)
	}
	// InfiniBand interfaces (DeleteAllBySiteID)
	for _, id := range site1Resources.ibInterfaceIDs {
		assertGone("infiniband_interface", &cdbm.InfiniBandInterface{}, "ibi.id", id)
	}
	// NVLink interfaces (DeleteAllBySiteID)
	for _, id := range site1Resources.nvlinkInterfaceIDs {
		assertGone("nvlink_interface", &cdbm.NVLinkInterface{}, "nvli.id", id)
	}
	assertGone("vpc_prefix", &cdbm.VpcPrefix{}, "vp.id", site1Resources.vpcPrefixID)
	assertGone("vpc_peering", &cdbm.VpcPeering{}, "vp.id", site1Resources.vpcPeeringID)
	assertGone("nvlink_logical_partition", &cdbm.NVLinkLogicalPartition{}, "nvllp.id", site1Resources.nvllpID)
	assertGone("ssh_key_group_site_association", &cdbm.SSHKeyGroupSiteAssociation{}, "skgsa.id", site1Resources.sshKeyGroupSiteID)
	assertGone("ssh_key_group_instance_association", &cdbm.SSHKeyGroupInstanceAssociation{}, "skgia.id", site1Resources.sshKeyGroupInstID)
	assertGone("network_security_group", &cdbm.NetworkSecurityGroup{}, "nsg.id", site1Resources.nsgID)
	assertGone("dpu_extension_service_deployment", &cdbm.DpuExtensionServiceDeployment{}, "desd.id", site1Resources.dpuDeploymentID)
	assertGone("sku", &cdbm.SKU{}, "sk.id", site1Resources.skuID)
	assertGone("expected_machine", &cdbm.ExpectedMachine{}, "em.id", site1Resources.expectedMachineID)
	assertGone("expected_switch", &cdbm.ExpectedSwitch{}, "es.id", site1Resources.expectedSwitchID)
	assertGone("expected_power_shelf", &cdbm.ExpectedPowerShelf{}, "eps.id", site1Resources.expectedShelfID)
	assertGone("operating_system_site_association (site 1 image OS)", &cdbm.OperatingSystemSiteAssociation{}, "ossa.id", site1Resources.imageOSSAID)

	// --- Site 2: nothing should have been touched. ---

	for _, id := range site2Resources.interfaceIDs {
		assertPresent("interface", &cdbm.Interface{}, "ifc.id", id)
	}
	for _, id := range site2Resources.ibInterfaceIDs {
		assertPresent("infiniband_interface", &cdbm.InfiniBandInterface{}, "ibi.id", id)
	}
	for _, id := range site2Resources.nvlinkInterfaceIDs {
		assertPresent("nvlink_interface", &cdbm.NVLinkInterface{}, "nvli.id", id)
	}
	assertPresent("vpc_prefix", &cdbm.VpcPrefix{}, "vp.id", site2Resources.vpcPrefixID)
	assertPresent("vpc_peering", &cdbm.VpcPeering{}, "vp.id", site2Resources.vpcPeeringID)
	assertPresent("nvlink_logical_partition", &cdbm.NVLinkLogicalPartition{}, "nvllp.id", site2Resources.nvllpID)
	assertPresent("ssh_key_group_site_association", &cdbm.SSHKeyGroupSiteAssociation{}, "skgsa.id", site2Resources.sshKeyGroupSiteID)
	assertPresent("ssh_key_group_instance_association", &cdbm.SSHKeyGroupInstanceAssociation{}, "skgia.id", site2Resources.sshKeyGroupInstID)
	assertPresent("network_security_group", &cdbm.NetworkSecurityGroup{}, "nsg.id", site2Resources.nsgID)
	assertPresent("dpu_extension_service_deployment", &cdbm.DpuExtensionServiceDeployment{}, "desd.id", site2Resources.dpuDeploymentID)
	assertPresent("sku", &cdbm.SKU{}, "sk.id", site2Resources.skuID)
	assertPresent("expected_machine", &cdbm.ExpectedMachine{}, "em.id", site2Resources.expectedMachineID)
	assertPresent("expected_switch", &cdbm.ExpectedSwitch{}, "es.id", site2Resources.expectedSwitchID)
	assertPresent("expected_power_shelf", &cdbm.ExpectedPowerShelf{}, "eps.id", site2Resources.expectedShelfID)
	// Site 2's image OS and its association are independent of site 1
	assertPresent("operating_system_site_association (site 2 image OS)", &cdbm.OperatingSystemSiteAssociation{}, "ossa.id", site2Resources.imageOSSAID)

	// SSHKeyAssociation for site 1 should still be present since the
	// workflow's call effectively no-ops against site IDs (see test docstring).
	assertPresent("ssh_key_association (intentionally not cleaned)", &cdbm.SSHKeyAssociation{}, "ska.id", site1Resources.sshKeyAssocID)
}
