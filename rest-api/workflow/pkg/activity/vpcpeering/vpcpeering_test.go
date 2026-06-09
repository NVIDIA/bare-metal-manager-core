// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package vpcpeering

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbu "github.com/NVIDIA/infra-controller/rest-api/db/pkg/util"
	sc "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/client/site"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun/extra/bundebug"
	"go.temporal.io/sdk/testsuite"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/NVIDIA/infra-controller/rest-api/workflow/internal/config"

	"os"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

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

func testVpcPeeringInitDB(t *testing.T) *cdb.Session {
	dbSession := cdbu.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("BUNDEBUG"),
	))
	return dbSession
}

func testVpcPeeringSetupSchema(t *testing.T, dbSession *cdb.Session) {
	err := dbSession.DB.ResetModel(context.Background(), (*cdbm.InfrastructureProvider)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Site)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Tenant)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Allocation)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.StatusDetail)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Vpc)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.VpcPeering)(nil))
	assert.Nil(t, err)
}

func testVpcPeeringSiteBuildInfrastructureProvider(t *testing.T, dbSession *cdb.Session, name string, org string, user *cdbm.User) *cdbm.InfrastructureProvider {
	ipDAO := cdbm.NewInfrastructureProviderDAO(dbSession)

	ip, err := ipDAO.CreateFromParams(context.Background(), nil, name, cutil.GetPtr("Test Provider"), org, nil, user)
	assert.Nil(t, err)

	return ip
}

func testVpcPeeringBuildSite(t *testing.T, dbSession *cdb.Session, ip *cdbm.InfrastructureProvider, name string, user *cdbm.User) *cdbm.Site {
	stDAO := cdbm.NewSiteDAO(dbSession)

	st, err := stDAO.Create(context.Background(), nil, cdbm.SiteCreateInput{
		Name:                        name,
		DisplayName:                 cutil.GetPtr("Test Site"),
		Description:                 cutil.GetPtr("Test Site Description"),
		Org:                         ip.Org,
		InfrastructureProviderID:    ip.ID,
		SiteControllerVersion:       cutil.GetPtr("1.0.0"),
		SiteAgentVersion:            cutil.GetPtr("1.0.0"),
		RegistrationToken:           cutil.GetPtr("1234-5678-9012-3456"),
		RegistrationTokenExpiration: cutil.GetPtr(cdb.GetCurTime()),
		IsInfinityEnabled:           false,
		IsSerialConsoleEnabled:      false,
		Status:                      cdbm.SiteStatusPending,
		CreatedBy:                   user.ID,
	})
	assert.Nil(t, err)

	return st
}

func testVpcPeeringBuildTenant(t *testing.T, dbSession *cdb.Session, name string, org string, user *cdbm.User) *cdbm.Tenant {
	tnDAO := cdbm.NewTenantDAO(dbSession)

	tn, err := tnDAO.Create(context.Background(), nil, cdbm.TenantCreateInput{
		Name:        name,
		DisplayName: cutil.GetPtr("Test Tenant"),
		Org:         org,
		CreatedBy:   user.ID,
	})
	assert.Nil(t, err)

	return tn
}

func testVpcPeeringBuildUser(t *testing.T, dbSession *cdb.Session, starfleetID string, org string, roles []string) *cdbm.User {
	uDAO := cdbm.NewUserDAO(dbSession)

	u, err := uDAO.Create(context.Background(), nil, cdbm.UserCreateInput{
		AuxiliaryID: nil,
		StarfleetID: &starfleetID,
		Email:       cutil.GetPtr("jdoe@test.com"),
		FirstName:   cutil.GetPtr("John"),
		LastName:    cutil.GetPtr("Doe"),
		OrgData: cdbm.OrgData{
			org: cdbm.Org{
				ID:      123,
				Name:    org,
				OrgType: "ENTERPRISE",
				Roles:   roles,
			},
		},
	})
	assert.Nil(t, err)

	return u
}

// testVPCPeeringBuildVPC Building VPC in DB
func testVpcPeeringBuildVPC(
	t *testing.T,
	dbSession *cdb.Session,
	name string,
	ip *cdbm.InfrastructureProvider,
	tn *cdbm.Tenant,
	st *cdbm.Site,
	networkVirtualizationType *string,
	ct *uuid.UUID,
	lb map[string]string,
	user *cdbm.User,
	status string,
) *cdbm.Vpc {
	vpcDAO := cdbm.NewVpcDAO(dbSession)

	input := cdbm.VpcCreateInput{
		Name:                      name,
		Description:               cutil.GetPtr("Test VPC"),
		Org:                       st.Org,
		InfrastructureProviderID:  ip.ID,
		TenantID:                  tn.ID,
		SiteID:                    st.ID,
		NetworkVirtualizationType: networkVirtualizationType,
		ControllerVpcID:           ct,
		Labels:                    lb,
		Status:                    status,
		CreatedBy:                 *user,
	}

	vpc, err := vpcDAO.Create(context.Background(), nil, input)
	assert.Nil(t, err)

	return vpc
}

func testVpcPeeringBuildVpcPeering(
	t *testing.T,
	dbSession *cdb.Session,
	vpc1ID uuid.UUID,
	vpc2ID uuid.UUID,
	siteID uuid.UUID,
	isMultiTenant bool,
	createdByID uuid.UUID,
) *cdbm.VpcPeering {
	vpcPeeringDAO := cdbm.NewVpcPeeringDAO(dbSession)

	vpcPeering, err := vpcPeeringDAO.Create(
		context.Background(),
		nil,
		cdbm.VpcPeeringCreateInput{
			Vpc1ID:        vpc1ID,
			Vpc2ID:        vpc2ID,
			SiteID:        siteID,
			IsMultiTenant: isMultiTenant,
			CreatedByID:   createdByID,
		},
	)
	assert.Nil(t, err)

	return vpcPeering
}

func TestManageVpcPeering_UpdateVpcPeeringsInDB(t *testing.T) {
	ctx := context.Background()

	dbSession := testVpcPeeringInitDB(t)
	defer dbSession.Close()

	testVpcPeeringSetupSchema(t, dbSession)

	// Setup users, site, tenant, vpcs
	org := "test-org"
	roles := []string{"FORGE_PROVIDER_ADMIN"}
	user := testVpcPeeringBuildUser(t, dbSession, uuid.NewString(), org, roles)
	ip := testVpcPeeringSiteBuildInfrastructureProvider(t, dbSession, "test-provider", org, user)
	site := testVpcPeeringBuildSite(t, dbSession, ip, "test-site", user)
	site2 := testVpcPeeringBuildSite(t, dbSession, ip, "test-site-2", user)
	site3 := testVpcPeeringBuildSite(t, dbSession, ip, "test-site-3", user)
	tenant := testVpcPeeringBuildTenant(t, dbSession, "test-tenant", org, user)

	// Build VPCs
	vpc1 := testVpcPeeringBuildVPC(t, dbSession, "vpc-1", ip, tenant, site, nil, nil, nil, user, "READY")
	assert.NotNil(t, vpc1)
	vpc2 := testVpcPeeringBuildVPC(t, dbSession, "vpc-2", ip, tenant, site, nil, nil, nil, user, "READY")
	assert.NotNil(t, vpc2)
	vpc3 := testVpcPeeringBuildVPC(t, dbSession, "vpc-3", ip, tenant, site, nil, nil, nil, user, "READY")
	assert.NotNil(t, vpc3)

	// Create VPC Peerings in DB
	vp1 := testVpcPeeringBuildVpcPeering(t, dbSession, vpc1.ID, vpc2.ID, site.ID, false, user.ID)
	assert.NotNil(t, vp1)
	vp2 := testVpcPeeringBuildVpcPeering(t, dbSession, vpc2.ID, vpc1.ID, site.ID, false, user.ID)
	assert.NotNil(t, vp2)
	_, err := dbSession.DB.Exec("UPDATE vpc_peering SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cutil.InventoryReceiptInterval*2)), vp2.ID)
	assert.NoError(t, err)
	vp3 := testVpcPeeringBuildVpcPeering(t, dbSession, vpc1.ID, vpc3.ID, site.ID, false, user.ID)
	assert.NotNil(t, vp3)
	_, err = dbSession.DB.Exec("UPDATE vpc_peering SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cutil.InventoryReceiptInterval*2)), vp3.ID)
	assert.NoError(t, err)
	vp4 := testVpcPeeringBuildVpcPeering(t, dbSession, vpc2.ID, vpc3.ID, site.ID, false, user.ID)
	assert.NotNil(t, vp4)
	_, err = dbSession.DB.Exec("UPDATE vpc_peering SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cutil.InventoryReceiptInterval*2)), vp4.ID)
	assert.NoError(t, err)

	tSiteClientPool := testTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	temporalsuit := testsuite.WorkflowTestSuite{}
	env := temporalsuit.NewTestWorkflowEnvironment()

	pagedVpcPeerings := []*cdbm.VpcPeering{}
	pagedInvIds := []string{}
	pagedCtrlVpcPeerings := []*cwssaws.VpcPeering{}

	paged_vpc1 := testVpcPeeringBuildVPC(t, dbSession, fmt.Sprintf("test-vpc-paged-%d", 0), ip, tenant, site3, nil, nil, nil, user, "READY")
	curr_vpc := paged_vpc1

	// Cloud has 38 VPC Peerings, 34 of which are in the inventory
	for i := 0; i < 38; i++ {
		prev_vpc := curr_vpc
		curr_vpc = testVpcPeeringBuildVPC(t, dbSession, fmt.Sprintf("test-vpc-paged-%d", i+1), ip, tenant, site3, nil, nil, nil, user, "READY")
		vpcPeering := testVpcPeeringBuildVpcPeering(t, dbSession, prev_vpc.ID, curr_vpc.ID, site3.ID, false, user.ID)

		mvp := NewManageVpcPeering(dbSession, nil)
		// Set status to Ready
		err = mvp.updateVpcPeeringStatusInDB(ctx, nil, vpcPeering.ID, cutil.GetPtr(cdbm.VpcPeeringStatusReady), cutil.GetPtr("VPC Peering was created in DB from site inventory"))
		assert.NoError(t, err)
		// Set created to 2x inventory interval ago
		_, err := dbSession.DB.Exec("UPDATE vpc_peering SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cutil.InventoryReceiptInterval*2)), vpcPeering.ID)
		assert.NoError(t, err)

		if i < 34 {
			ctrlVpcPeering := &cwssaws.VpcPeering{
				Id:        &cwssaws.VpcPeeringId{Value: vpcPeering.ID.String()},
				VpcId:     &cwssaws.VpcId{Value: prev_vpc.ID.String()},
				PeerVpcId: &cwssaws.VpcId{Value: curr_vpc.ID.String()},
			}
			pagedCtrlVpcPeerings = append(pagedCtrlVpcPeerings, ctrlVpcPeering)
		}
		pagedVpcPeerings = append(pagedVpcPeerings, vpcPeering)
		pagedInvIds = append(pagedInvIds, vpcPeering.ID.String())
	}

	type fields struct {
		dbSession      *cdb.Session
		siteClientPool *sc.ClientPool
		env            *testsuite.TestWorkflowEnvironment
	}

	type args struct {
		ctx                 context.Context
		siteID              uuid.UUID
		vpcPeeringInventory *cwssaws.VPCPeeringInventory
	}

	tests := []struct {
		name               string
		fields             fields
		args               args
		readyVpcPeerings   []*cdbm.VpcPeering
		deletedVpcPeerings []*cdbm.VpcPeering
		wantErr            bool
	}{
		{
			name: "test Vpc Peering inventory processing error, non-existent Site",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: uuid.New(),
				vpcPeeringInventory: &cwssaws.VPCPeeringInventory{
					VpcPeerings: []*cwssaws.VpcPeering{},
				},
			},
			wantErr: true,
		},
		{
			name: "test Vpc Peering inventory processing success on full inventory",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: site.ID,
				vpcPeeringInventory: &cwssaws.VPCPeeringInventory{
					VpcPeerings: []*cwssaws.VpcPeering{
						{Id: &cwssaws.VpcPeeringId{Value: vp1.ID.String()}},
						{Id: &cwssaws.VpcPeeringId{Value: vp2.ID.String()}},
						{Id: &cwssaws.VpcPeeringId{Value: vp3.ID.String()}},
						{Id: &cwssaws.VpcPeeringId{Value: vp4.ID.String()}},
					},
				},
			},
			readyVpcPeerings: []*cdbm.VpcPeering{vp1, vp2, vp3, vp4},
			wantErr:          false,
		},
		{
			name: "test Vpc Peering inventory processing success on partial inventory",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: site.ID,
				vpcPeeringInventory: &cwssaws.VPCPeeringInventory{
					VpcPeerings: []*cwssaws.VpcPeering{
						{Id: &cwssaws.VpcPeeringId{Value: vp1.ID.String()}},
					},
				},
			},
			readyVpcPeerings:   []*cdbm.VpcPeering{vp1},
			deletedVpcPeerings: []*cdbm.VpcPeering{vp2, vp3, vp4},
			wantErr:            false,
		},
		{
			name: "test paged Vpc Peering inventory processing, empty inventory",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: site2.ID,
				vpcPeeringInventory: &cwssaws.VPCPeeringInventory{
					VpcPeerings: []*cwssaws.VpcPeering{},
					Timestamp:   timestamppb.Now(),
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 1,
						TotalPages:  0,
						PageSize:    25,
						TotalItems:  0,
						ItemIds:     []string{},
					},
				},
			},
			readyVpcPeerings:   []*cdbm.VpcPeering{vp1},
			deletedVpcPeerings: []*cdbm.VpcPeering{vp2, vp3, vp4},
			wantErr:            false,
		},
		{
			name: "test paged Vpc Peering inventory processing, first page",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: site3.ID,
				vpcPeeringInventory: &cwssaws.VPCPeeringInventory{
					VpcPeerings: pagedCtrlVpcPeerings[0:10],
					Timestamp:   timestamppb.Now(),
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 1,
						TotalPages:  4,
						PageSize:    10,
						TotalItems:  34,
						ItemIds:     pagedInvIds[0:34],
					},
				},
			},
			readyVpcPeerings: pagedVpcPeerings[0:34],
			wantErr:          false,
		},
		{
			name: "test paged Vpc Peering inventory processing, last page",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: site3.ID,
				vpcPeeringInventory: &cwssaws.VPCPeeringInventory{
					VpcPeerings: pagedCtrlVpcPeerings[30:34],
					Timestamp:   timestamppb.Now(),
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 4,
						TotalPages:  4,
						PageSize:    10,
						TotalItems:  34,
						ItemIds:     pagedInvIds[0:34],
					},
				},
			},
			readyVpcPeerings:   pagedVpcPeerings[0:34],
			deletedVpcPeerings: pagedVpcPeerings[34:38],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mv := ManageVpcPeering{
				dbSession:      tt.fields.dbSession,
				siteClientPool: tt.fields.siteClientPool,
			}

			err := mv.UpdateVpcPeeringsInDB(tt.args.ctx, tt.args.siteID, tt.args.vpcPeeringInventory)
			assert.Equal(t, tt.wantErr, err != nil)

			if tt.wantErr {
				return
			}

			vpcPeeringDAO := cdbm.NewVpcPeeringDAO(dbSession)

			for _, vp := range tt.readyVpcPeerings {
				ready, err := vpcPeeringDAO.GetByID(ctx, nil, vp.ID, nil)
				assert.NoError(t, err)
				assert.Equal(t, cdbm.VpcPeeringStatusReady, ready.Status)
			}

			for _, vp := range tt.deletedVpcPeerings {
				_, err := vpcPeeringDAO.GetByID(ctx, nil, vp.ID, nil)
				assert.Equal(t, cdb.ErrDoesNotExist, err, fmt.Sprintf("VPC Peering %s should have been deleted", vp.ID))
			}
		})
	}
}

func TestNewManageVpcPeering(t *testing.T) {
	type args struct {
		dbSession      *cdb.Session
		siteClientPool *sc.ClientPool
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
	scp := sc.NewClientPool(tcfg)

	tests := []struct {
		name string
		args args
		want ManageVpcPeering
	}{
		{
			name: "test new ManageVpcPeering instantiation",
			args: args{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
			want: ManageVpcPeering{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewManageVpcPeering(tt.args.dbSession, tt.args.siteClientPool); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewManageVpcPeering() = %v, want %v", got, tt.want)
			}
		})
	}
}
