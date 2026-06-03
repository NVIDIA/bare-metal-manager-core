// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package vpcprefix

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/ipam"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbu "github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	cipam "github.com/NVIDIA/infra-controller-rest/ipam"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	sc "github.com/NVIDIA/infra-controller-rest/workflow/pkg/client/site"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/extra/bundebug"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller-rest/workflow/internal/config"

	"os"

	"go.temporal.io/sdk/testsuite"

	cwutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
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

func testVpcPrefixInitDB(t *testing.T) *cdb.Session {
	dbSession := cdbu.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("BUNDEBUG"),
	))
	return dbSession
}

func testVPCPrefixSetupSchema(t *testing.T, dbSession *cdb.Session) {
	// create Infrastructure Provider table
	err := dbSession.DB.ResetModel(context.Background(), (*cdbm.InfrastructureProvider)(nil))
	assert.Nil(t, err)
	// create Site table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Site)(nil))
	assert.Nil(t, err)
	// create Tenant table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Tenant)(nil))
	assert.Nil(t, err)
	// create User table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil))
	assert.Nil(t, err)
	// create Allocation table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Allocation)(nil))
	assert.Nil(t, err)
	// create Status Details table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.StatusDetail)(nil))
	assert.Nil(t, err)
	// create VPC table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Vpc)(nil))
	assert.Nil(t, err)
	// create VPCPrefix table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.VpcPrefix)(nil))
	assert.Nil(t, err)
}

// testVPCSiteBuildInfrastructureProvider Building Infra Provider in DB
func testVPCSiteBuildInfrastructureProvider(t *testing.T, dbSession *cdb.Session, name string, org string, user *cdbm.User) *cdbm.InfrastructureProvider {
	ipDAO := cdbm.NewInfrastructureProviderDAO(dbSession)

	ip, err := ipDAO.CreateFromParams(context.Background(), nil, name, cdb.GetStrPtr("Test Provider"), org, nil, user)
	assert.Nil(t, err)

	return ip
}

// testVPCBuildSite Building Site in DB
func testVPCBuildSite(t *testing.T, dbSession *cdb.Session, ip *cdbm.InfrastructureProvider, name string, user *cdbm.User) *cdbm.Site {
	stDAO := cdbm.NewSiteDAO(dbSession)

	st, err := stDAO.Create(context.Background(), nil, cdbm.SiteCreateInput{
		Name:                        name,
		DisplayName:                 cdb.GetStrPtr("Test Site"),
		Description:                 cdb.GetStrPtr("Test Site Description"),
		Org:                         ip.Org,
		InfrastructureProviderID:    ip.ID,
		SiteControllerVersion:       cdb.GetStrPtr("1.0.0"),
		SiteAgentVersion:            cdb.GetStrPtr("1.0.0"),
		RegistrationToken:           cdb.GetStrPtr("1234-5678-9012-3456"),
		RegistrationTokenExpiration: cdb.GetTimePtr(cdb.GetCurTime()),
		IsInfinityEnabled:           false,
		IsSerialConsoleEnabled:      false,
		Status:                      cdbm.SiteStatusPending,
		CreatedBy:                   user.ID,
	})
	assert.Nil(t, err)

	return st
}

// testVPCBuildTenant Building Tenant in DB
func testVPCBuildTenant(t *testing.T, dbSession *cdb.Session, name string, org string, user *cdbm.User) *cdbm.Tenant {
	tnDAO := cdbm.NewTenantDAO(dbSession)

	tn, err := tnDAO.CreateFromParams(context.Background(), nil, name, cdb.GetStrPtr("Test Tenant"), org, nil, nil, user)
	assert.Nil(t, err)

	return tn
}

// testVPCBuildUser Building User in DB
func testVPCBuildUser(t *testing.T, dbSession *cdb.Session, starfleetID string, org string, roles []string) *cdbm.User {
	uDAO := cdbm.NewUserDAO(dbSession)

	u, err := uDAO.Create(context.Background(), nil, cdbm.UserCreateInput{
		AuxiliaryID: nil,
		StarfleetID: &starfleetID,
		Email:       cdb.GetStrPtr("jdoe@test.com"),
		FirstName:   cdb.GetStrPtr("John"),
		LastName:    cdb.GetStrPtr("Doe"),
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

// testVPCSiteBuildAllocation Building Site Allocation in DB
func testVPCSiteBuildAllocation(t *testing.T, dbSession *cdb.Session, st *cdbm.Site, tn *cdbm.Tenant, name string, user *cdbm.User) *cdbm.Allocation {
	alDAO := cdbm.NewAllocationDAO(dbSession)

	createInput := cdbm.AllocationCreateInput{
		Name:                     name,
		Description:              cdb.GetStrPtr("Test Allocation Description"),
		InfrastructureProviderID: st.InfrastructureProviderID,
		TenantID:                 tn.ID,
		SiteID:                   st.ID,
		Status:                   cdbm.AllocationStatusPending,
		CreatedBy:                user.ID,
	}
	al, err := alDAO.Create(context.Background(), nil, createInput)
	assert.Nil(t, err)

	return al
}

// testVPCBuildVPC Building VPCPrefix in DB
func testVPCBuildVPC(t *testing.T, dbSession *cdb.Session, name string, ip *cdbm.InfrastructureProvider, tn *cdbm.Tenant, st *cdbm.Site, ct *uuid.UUID, lb map[string]string, user *cdbm.User, status string) *cdbm.Vpc {
	vpcDAO := cdbm.NewVpcDAO(dbSession)

	input := cdbm.VpcCreateInput{
		Name:                      name,
		Description:               cdb.GetStrPtr("Test VPCPrefix"),
		Org:                       st.Org,
		InfrastructureProviderID:  ip.ID,
		TenantID:                  tn.ID,
		SiteID:                    st.ID,
		NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcEthernetVirtualizer),
		ControllerVpcID:           ct,
		Labels:                    lb,
		Status:                    status,
		CreatedBy:                 *user,
	}

	vpc, err := vpcDAO.Create(context.Background(), nil, input)
	assert.Nil(t, err)

	return vpc
}

// testVPCPrefixBuildIPBlock Building IPBlock in DB
func testVPCPrefixBuildIPBlock(t *testing.T, dbSession *cdb.Session, name string, site *cdbm.Site, ip *cdbm.InfrastructureProvider, tenantID *uuid.UUID, routingType, prefix string, blockSize int, protocolVersion string, fullGrant bool, status string, user *cdbm.User) *cdbm.IPBlock {
	ipbDAO := cdbm.NewIPBlockDAO(dbSession)
	ipb, err := ipbDAO.Create(
		context.Background(),
		nil,
		cdbm.IPBlockCreateInput{
			Name:                     name,
			SiteID:                   site.ID,
			InfrastructureProviderID: ip.ID,
			TenantID:                 tenantID,
			RoutingType:              routingType,
			Prefix:                   prefix,
			PrefixLength:             blockSize,
			ProtocolVersion:          protocolVersion,
			FullGrant:                fullGrant,
			Status:                   status,
			CreatedBy:                &user.ID,
		},
	)
	assert.Nil(t, err)
	return ipb
}

func testVPCBuildVPCPrefix(t *testing.T, dbSession *cdb.Session, name string, st *cdbm.Site, tenant *cdbm.Tenant, vpcID uuid.UUID, ipv4BlockID *uuid.UUID, prefix *string, prefixLength *int, status string, user *cdbm.User) *cdbm.VpcPrefix {
	vpcPrefixDAO := cdbm.NewVpcPrefixDAO(dbSession)

	vpcprefix, err := vpcPrefixDAO.Create(context.Background(), nil, cdbm.VpcPrefixCreateInput{Name: name, TenantOrg: st.Org, SiteID: st.ID, VpcID: vpcID, TenantID: tenant.ID, IpBlockID: ipv4BlockID, Prefix: *prefix, PrefixLength: *prefixLength, Status: status, CreatedBy: user.ID})
	assert.Nil(t, err)

	return vpcprefix
}

func TestManageVpcPrefix_UpdateVpcPrefixesInDB(t *testing.T) {
	ctx := context.Background()

	dbSession := testVpcPrefixInitDB(t)
	defer dbSession.Close()

	testVPCPrefixSetupSchema(t, dbSession)

	ipamStorage := ipam.NewIpamStorage(dbSession.DB, nil)

	ipOrg := "test-provider-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := testVPCBuildUser(t, dbSession, uuid.NewString(), ipOrg, ipRoles)
	ip := testVPCSiteBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)

	tnOrg := "test-tenant-org"
	tnRoles := []string{"FORGE_TENANT_ADMIN"}

	tnu := testVPCBuildUser(t, dbSession, uuid.NewString(), tnOrg, tnRoles)
	tn := testVPCBuildTenant(t, dbSession, "test-tenant", tnOrg, tnu)

	st := testVPCBuildSite(t, dbSession, ip, "test-site", ipu)
	st2 := testVPCBuildSite(t, dbSession, ip, "test-site-2", ipu)
	st3 := testVPCBuildSite(t, dbSession, ip, "test-site-3", ipu)

	vpc1 := testVPCBuildVPC(t, dbSession, "test-vpc-1", ip, tn, st, cdb.GetUUIDPtr(uuid.New()), nil, tnu, cdbm.VpcStatusReady)

	ipb1 := testVPCPrefixBuildIPBlock(t, dbSession, "testipb", st, ip, &st.ID, cdbm.IPBlockRoutingTypeDatacenterOnly, "192.168.0.0", 24, cdbm.IPBlockProtocolVersionV4, false, cdbm.IPBlockStatusReady, tnu)
	assert.NotNil(t, ipb1)

	_, err := ipam.CreateIpamEntryForIPBlock(ctx, ipamStorage, ipb1.Prefix, ipb1.PrefixLength, ipb1.RoutingType, ipb1.InfrastructureProviderID.String(), ipb1.SiteID.String())
	assert.Nil(t, err)

	vpcPrefix1 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-1", st, tn, vpc1.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusReady, tnu)

	vpc2 := testVPCBuildVPC(t, dbSession, "test-vpc-2", ip, tn, st, cdb.GetUUIDPtr(uuid.New()), nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix2 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-2", st, tn, vpc2.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusReady, tnu)

	vpc3 := testVPCBuildVPC(t, dbSession, "test-vpc-3", ip, tn, st, cdb.GetUUIDPtr(uuid.New()), nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix3 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-3", st, tn, vpc3.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusDeleting, tnu)

	vpc4 := testVPCBuildVPC(t, dbSession, "test-vpc-4", ip, tn, st, cdb.GetUUIDPtr(uuid.New()), nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix4 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-4", st, tn, vpc4.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusDeleting, tnu)

	// VPC Prefix 5 and 6 are missing and will be deleted
	prefix5, err := ipam.CreateChildIpamEntryForIPBlock(ctx, nil, dbSession, ipamStorage, ipb1, 28)
	assert.NoError(t, err)
	_, prefix5Len, err := ipam.ParseCidrIntoPrefixAndBlockSize(prefix5.Cidr)
	assert.NoError(t, err)

	vpc5 := testVPCBuildVPC(t, dbSession, "test-vpc-5", ip, tn, st, cdb.GetUUIDPtr(uuid.New()), nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix5 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-5", st, tn, vpc5.ID, &ipb1.ID, &prefix5.Cidr, &prefix5Len, cdbm.VpcPrefixStatusDeleting, tnu)
	vpcPrefix5.IPBlock = ipb1

	prefix6, err := ipam.CreateChildIpamEntryForIPBlock(ctx, nil, dbSession, ipamStorage, ipb1, 28)
	assert.NoError(t, err)
	_, prefix6Len, err := ipam.ParseCidrIntoPrefixAndBlockSize(prefix6.Cidr)
	assert.NoError(t, err)

	vpc6 := testVPCBuildVPC(t, dbSession, "test-vpc-6", ip, tn, st, nil, nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix6 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-6", st, tn, vpc6.ID, &ipb1.ID, &prefix6.Cidr, &prefix6Len, cdbm.VpcPrefixStatusDeleting, tnu)
	vpcPrefix6.IPBlock = ipb1

	vpc7 := testVPCBuildVPC(t, dbSession, "test-vpc-7", ip, tn, st, cdb.GetUUIDPtr(uuid.New()), nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix7 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-7", st, tn, vpc7.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusReady, tnu)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE vpc_prefix SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)), vpcPrefix7.ID.String())
	assert.NoError(t, err)

	vpc8 := testVPCBuildVPC(t, dbSession, "test-vpc-8", ip, tn, st, cdb.GetUUIDPtr(uuid.New()), nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix8 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-8", st, tn, vpc8.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusReady, tnu)

	vpc9 := testVPCBuildVPC(t, dbSession, "test-vpc-9", ip, tn, st, nil, nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix9 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-9", st, tn, vpc9.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusReady, tnu)

	vpc10 := testVPCBuildVPC(t, dbSession, "test-vpc-10", ip, tn, st, nil, nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix10 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-10", st, tn, vpc10.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusDeleting, tnu)

	vpc11 := testVPCBuildVPC(t, dbSession, "test-vpc-11", ip, tn, st, cdb.GetUUIDPtr(uuid.New()), nil, tnu, cdbm.VpcStatusReady)
	vpcPrefix11 := testVPCBuildVPCPrefix(t, dbSession, "test-vpcprefix-11", st, tn, vpc11.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusReady, tnu)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE vpc_prefix SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)), vpcPrefix11.ID.String())
	assert.NoError(t, err)

	vpcPrefixDAO := cdbm.NewVpcPrefixDAO(dbSession)
	vpcPrefix8, err = vpcPrefixDAO.Update(ctx, nil, cdbm.VpcPrefixUpdateInput{VpcPrefixID: vpcPrefix8.ID, Status: cdb.GetStrPtr(cdbm.VpcStatusReady), IsMissingOnSite: cdb.GetBoolPtr(true)})
	assert.NoError(t, err)

	tSiteClientPool := testTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	temporalsuit := testsuite.WorkflowTestSuite{}
	env := temporalsuit.NewTestWorkflowEnvironment()

	// Build VpcPrefix inventory that is paginated
	// Generate data for 34 VpcPrefix reported from Site Agent while Cloud has 38 VpcPrefixes
	pagedVpcPrefixes := []*cdbm.VpcPrefix{}
	pagedInvIds := []string{}

	for i := 0; i < 38; i++ {
		vpc := testVPCBuildVPC(t, dbSession, fmt.Sprintf("test-vpc-paged-%d", i), ip, tn, st3, cdb.GetUUIDPtr(uuid.New()), map[string]string{}, tnu, cdbm.VpcStatusReady)
		vpcPrefix := testVPCBuildVPCPrefix(t, dbSession, fmt.Sprintf("test-vpc-prefix-paged-%d", i), st3, tn, vpc.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusReady, tnu)
		// Update creation timestamp to be earlier than inventory processing interval
		_, err = dbSession.DB.Exec("UPDATE vpc_prefix SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval*2)), vpcPrefix.ID.String())
		assert.NoError(t, err)
		pagedVpcPrefixes = append(pagedVpcPrefixes, vpcPrefix)
		pagedInvIds = append(pagedInvIds, vpcPrefix.ID.String())
	}

	pagedCtrlVpcPrefixes := []*cwssaws.VpcPrefix{}
	for i := 0; i < 34; i++ {
		ctrlVpcPrefix := &cwssaws.VpcPrefix{
			Id:   &cwssaws.VpcPrefixId{Value: pagedVpcPrefixes[i].ID.String()},
			Name: pagedVpcPrefixes[i].Name,
		}
		pagedCtrlVpcPrefixes = append(pagedCtrlVpcPrefixes, ctrlVpcPrefix)
	}

	type fields struct {
		dbSession      *cdb.Session
		siteClientPool *sc.ClientPool
		env            *testsuite.TestWorkflowEnvironment
	}

	type args struct {
		ctx                context.Context
		siteID             uuid.UUID
		vpcPrefixInventory *cwssaws.VpcPrefixInventory
	}

	tests := []struct {
		name                string
		fields              fields
		args                args
		updatedVpcPrefix    *cdbm.VpcPrefix
		readyVpcPrefixes    []*cdbm.VpcPrefix
		deletedVpcPrefixes  []*cdbm.VpcPrefix
		missingVpcPrefixes  []*cdbm.VpcPrefix
		restoredVpcPrefixes []*cdbm.VpcPrefix
		unpairedVpcPrefixes []*cdbm.VpcPrefix
		wantErr             bool
	}{
		{
			name: "test Vpc Prefix inventory processing error, non-existent Site",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: uuid.New(),
				vpcPrefixInventory: &cwssaws.VpcPrefixInventory{
					VpcPrefixes: []*cwssaws.VpcPrefix{},
				},
			},
			wantErr: true,
		},
		{
			name: "test Vpc Prefix inventory processing success",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st.ID,
				vpcPrefixInventory: &cwssaws.VpcPrefixInventory{
					VpcPrefixes: []*cwssaws.VpcPrefix{
						{
							Id:   &cwssaws.VpcPrefixId{Value: vpcPrefix1.ID.String()},
							Name: vpcPrefix1.ID.String(),
						},
						{
							Id:   &cwssaws.VpcPrefixId{Value: vpcPrefix2.ID.String()},
							Name: vpcPrefix2.ID.String(),
						},
						{
							Id:   &cwssaws.VpcPrefixId{Value: vpcPrefix3.ID.String()},
							Name: vpcPrefix3.ID.String(),
						},
						{
							Id:   &cwssaws.VpcPrefixId{Value: vpcPrefix4.ID.String()},
							Name: vpcPrefix4.ID.String(),
						},
						{
							Id:   &cwssaws.VpcPrefixId{Value: vpcPrefix8.ID.String()},
							Name: vpcPrefix8.ID.String(),
						},
						{
							Id:   &cwssaws.VpcPrefixId{Value: vpcPrefix9.ID.String()},
							Name: vpcPrefix9.ID.String(),
						},
						{
							Id:   &cwssaws.VpcPrefixId{Value: vpcPrefix10.ID.String()},
							Name: vpcPrefix10.ID.String(),
						},
					},
				},
			},
			deletedVpcPrefixes:  []*cdbm.VpcPrefix{vpcPrefix5, vpcPrefix6},
			missingVpcPrefixes:  []*cdbm.VpcPrefix{vpcPrefix7, vpcPrefix11},
			restoredVpcPrefixes: []*cdbm.VpcPrefix{vpcPrefix8},
			wantErr:             false,
		},
		{
			name: "test paged Vpc Prefix inventory processing, empty inventory",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st2.ID,
				vpcPrefixInventory: &cwssaws.VpcPrefixInventory{
					VpcPrefixes:     []*cwssaws.VpcPrefix{},
					Timestamp:       timestamppb.Now(),
					InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 1,
						TotalPages:  0,
						PageSize:    25,
						TotalItems:  0,
						ItemIds:     []string{},
					},
				},
			},
		},
		{
			name: "test paged Vpc Prefix inventory processing, first page",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st3.ID,
				vpcPrefixInventory: &cwssaws.VpcPrefixInventory{
					VpcPrefixes: pagedCtrlVpcPrefixes[0:10],
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
			readyVpcPrefixes: pagedVpcPrefixes[0:34],
		},
		{
			name: "test paged Vpc Prefix inventory processing, last page",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st3.ID,
				vpcPrefixInventory: &cwssaws.VpcPrefixInventory{
					VpcPrefixes: pagedCtrlVpcPrefixes[30:34],
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
			readyVpcPrefixes:   pagedVpcPrefixes[0:34],
			missingVpcPrefixes: pagedVpcPrefixes[34:38],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mv := ManageVpcPrefix{
				dbSession:      tt.fields.dbSession,
				siteClientPool: tt.fields.siteClientPool,
			}

			err := mv.UpdateVpcPrefixesInDB(tt.args.ctx, tt.args.siteID, tt.args.vpcPrefixInventory)
			assert.Equal(t, tt.wantErr, err != nil)

			if tt.wantErr {
				return
			}

			vpcPrefixDAO := cdbm.NewVpcPrefixDAO(dbSession)
			// Check that VPC Prefix status was updated in DB
			if tt.updatedVpcPrefix != nil {
				updatedVPCPrefix, _ := vpcPrefixDAO.GetByID(ctx, nil, tt.updatedVpcPrefix.ID, nil)
				assert.Equal(t, cdbm.VpcPrefixStatusReady, updatedVPCPrefix.Status)
			}

			for _, vpcPrefix := range tt.readyVpcPrefixes {
				rv, _ := vpcPrefixDAO.GetByID(ctx, nil, vpcPrefix.ID, nil)
				assert.False(t, rv.IsMissingOnSite)
				assert.Equal(t, cdbm.VpcPrefixStatusReady, rv.Status)
			}

			for _, vpcPrefix := range tt.deletedVpcPrefixes {
				_, err = vpcPrefixDAO.GetByID(ctx, nil, vpcPrefix.ID, nil)
				require.Equal(t, cdb.ErrDoesNotExist, err, fmt.Sprintf("VPC Prefix %s should have been deleted", vpcPrefix.Name))

				// Check that corresponding IPAM entry was removed
				if vpcPrefix.IPBlock.PrefixLength != vpcPrefix.PrefixLength {
					ipamStorage := ipam.NewIpamStorage(dbSession.DB, nil)
					ipamer := cipam.NewWithStorage(ipamStorage)
					ipamer.SetNamespace(ipam.GetIpamNamespaceForIPBlock(ctx, ipb1.RoutingType, ipb1.InfrastructureProviderID.String(), ipb1.SiteID.String()))
					pref := ipamer.PrefixFrom(ctx, vpcPrefix.Prefix)
					assert.Nil(t, pref)
				}
			}

			for _, vpcprefix := range tt.missingVpcPrefixes {
				uv, _ := vpcPrefixDAO.GetByID(ctx, nil, vpcprefix.ID, nil)
				assert.True(t, uv.IsMissingOnSite)
			}

			for _, vpcprefix := range tt.restoredVpcPrefixes {
				rv, _ := vpcPrefixDAO.GetByID(ctx, nil, vpcprefix.ID, nil)
				assert.False(t, rv.IsMissingOnSite)
				assert.Equal(t, cdbm.VpcPrefixStatusReady, rv.Status)
			}

		})
	}
}

func TestNewManageVpcPrefix(t *testing.T) {
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
		want ManageVpcPrefix
	}{
		{
			name: "test new ManageVpcPrefix instantiation",
			args: args{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
			want: ManageVpcPrefix{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewManageVpcPrefix(tt.args.dbSession, tt.args.siteClientPool); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewManageVpcPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}
