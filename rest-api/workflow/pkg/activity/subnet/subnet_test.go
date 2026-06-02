// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package subnet

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
	cwsv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	sc "github.com/NVIDIA/infra-controller-rest/workflow/pkg/client/site"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/extra/bundebug"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller-rest/workflow/internal/config"

	"os"

	"go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"

	"go.temporal.io/sdk/testsuite"

	"github.com/prometheus/client_golang/prometheus"

	cwm "github.com/NVIDIA/infra-controller-rest/workflow/internal/metrics"
	"github.com/NVIDIA/infra-controller-rest/workflow/pkg/util"

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

func testSubnetInitDB(t *testing.T) *cdb.Session {
	dbSession := cdbu.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("BUNDEBUG"),
	))
	return dbSession
}

func testSubnetSetupSchema(t *testing.T, dbSession *cdb.Session) {
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
	// create Domain table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Domain)(nil))
	assert.Nil(t, err)
	// create IPBlock table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.IPBlock)(nil))
	assert.Nil(t, err)
	// create VPC table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Vpc)(nil))
	assert.Nil(t, err)
	// create Subnet table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Subnet)(nil))
	assert.Nil(t, err)
	// setup ipam table
	ipamStorage := cipam.NewBunStorage(dbSession.DB, nil)
	assert.Nil(t, ipamStorage.ApplyDbSchema())
	assert.Nil(t, ipamStorage.DeleteAllPrefixes(context.Background(), ""))
}

// testSubnetSiteBuildInfrastructureProvider Building Infra Provider in DB
func testSubnetSiteBuildInfrastructureProvider(t *testing.T, dbSession *cdb.Session, name string, org string, user *cdbm.User) *cdbm.InfrastructureProvider {
	ipDAO := cdbm.NewInfrastructureProviderDAO(dbSession)

	ip, err := ipDAO.CreateFromParams(context.Background(), nil, name, cdb.GetStrPtr("Test Provider"), org, nil, user)
	assert.Nil(t, err)

	return ip
}

// testSubnetBuildSite Building Site in DB
func testSubnetBuildSite(t *testing.T, dbSession *cdb.Session, ip *cdbm.InfrastructureProvider, name string, user *cdbm.User) *cdbm.Site {
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

// testSubnetBuildTenant Building Tenant in DB
func testSubnetBuildTenant(t *testing.T, dbSession *cdb.Session, name string, org string, user *cdbm.User) *cdbm.Tenant {
	tnDAO := cdbm.NewTenantDAO(dbSession)

	tn, err := tnDAO.CreateFromParams(context.Background(), nil, name, cdb.GetStrPtr("Test Tenant"), org, nil, nil, user)
	assert.Nil(t, err)

	return tn
}

// testSubnetBuildUser Building User in DB
func testSubnetBuildUser(t *testing.T, dbSession *cdb.Session, starfleetID string, org string, roles []string) *cdbm.User {
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

// testSubnetBuildVPC Building VPC in DB
func testSubnetBuildVPC(t *testing.T, dbSession *cdb.Session, name string, ip *cdbm.InfrastructureProvider, tn *cdbm.Tenant, st *cdbm.Site, ct *uuid.UUID, lb map[string]string, user *cdbm.User) *cdbm.Vpc {
	vpcDAO := cdbm.NewVpcDAO(dbSession)

	input := cdbm.VpcCreateInput{
		Name:                      name,
		Description:               cdb.GetStrPtr("Test VPC"),
		Org:                       st.Org,
		InfrastructureProviderID:  ip.ID,
		TenantID:                  tn.ID,
		SiteID:                    st.ID,
		NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcEthernetVirtualizer),
		ControllerVpcID:           ct,
		Labels:                    lb,
		Status:                    cdbm.VpcStatusPending,
		CreatedBy:                 *user,
	}

	vpc, err := vpcDAO.Create(context.Background(), nil, input)
	assert.Nil(t, err)

	return vpc
}

// testSubnetBuildDomain Building Domain in DB
func testSubnetBuildDomain(t *testing.T, dbSession *cdb.Session, hostname, org string, user *cdbm.User) *cdbm.Domain {
	domain := &cdbm.Domain{
		ID:        uuid.New(),
		Hostname:  hostname,
		Org:       org,
		Status:    cdbm.DomainStatusPending,
		CreatedBy: user.ID,
	}
	_, err := dbSession.DB.NewInsert().Model(domain).Exec(context.Background())
	assert.Nil(t, err)
	return domain
}

// testSubnetBuildSubnet Building Subnet in DB
func testSubnetBuildSubnet(t *testing.T, dbSession *cdb.Session, name string, tenant *cdbm.Tenant, vpc *cdbm.Vpc, domainID *uuid.UUID, ctrlSegmentID *uuid.UUID, routingType *string, ipv4prefix *string, ipv4gateway *string, ipv4BlockID *uuid.UUID, ipBlockSize int, status string, user *cdbm.User) *cdbm.Subnet {
	subnetDAO := cdbm.NewSubnetDAO(dbSession)

	subnet, err := subnetDAO.Create(context.Background(), nil, cdbm.SubnetCreateInput{
		Name:                       name,
		Description:                cdb.GetStrPtr("Test Subnet"),
		Org:                        tenant.Org,
		SiteID:                     vpc.SiteID,
		VpcID:                      vpc.ID,
		DomainID:                   domainID,
		TenantID:                   tenant.ID,
		ControllerNetworkSegmentID: ctrlSegmentID,
		RoutingType:                routingType,
		IPv4Prefix:                 ipv4prefix,
		IPv4Gateway:                ipv4gateway,
		IPv4BlockID:                ipv4BlockID,
		PrefixLength:               ipBlockSize,
		Status:                     status,
		CreatedBy:                  user.ID,
	})
	assert.Nil(t, err)

	return subnet
}

// testSubnetBuildIPBlock Building IPBlock in DB
func testSubnetBuildIPBlock(t *testing.T, dbSession *cdb.Session, name string, site *cdbm.Site, ip *cdbm.InfrastructureProvider, tenantID *uuid.UUID, routingType, prefix string, blockSize int, protocolVersion string, fullGrant bool, status string, user *cdbm.User) *cdbm.IPBlock {
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

func TestManageSubnet_UpdateSubnetsInDB(t *testing.T) {
	ctx := context.Background()

	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()

	ipamStorage := ipam.NewIpamStorage(dbSession.DB, nil)

	testSubnetSetupSchema(t, dbSession)

	ipOrg := "test-provider-org"
	ipOrgRoles := []string{"FORGE_PROVIDER_ADMIN"}

	tnOrg := "test-tenant-org"
	tnOrgRoles := []string{"FORGE_TENANT_ADMIN"}

	ipu := testSubnetBuildUser(t, dbSession, "test-starfleet-id-1", ipOrg, ipOrgRoles)
	ip := testSubnetSiteBuildInfrastructureProvider(t, dbSession, "test-infrastructure-provider", ipOrg, ipu)

	tnu := testSubnetBuildUser(t, dbSession, "test-starfleet-id-2", tnOrg, tnOrgRoles)
	tn := testSubnetBuildTenant(t, dbSession, "test-tenant", tnOrg, tnu)

	st := testSubnetBuildSite(t, dbSession, ip, "test-site-1", ipu)
	assert.NotNil(t, st)

	al := testVPCSiteBuildAllocation(t, dbSession, st, tn, "test-allocation", ipu)
	assert.NotNil(t, al)

	vpc := testSubnetBuildVPC(t, dbSession, "test-vpc", ip, tn, st, nil, nil, tnu)
	assert.NotNil(t, vpc)

	ipb := testSubnetBuildIPBlock(t, dbSession, "testipb", st, ip, &tn.ID, cdbm.IPBlockRoutingTypeDatacenterOnly, "192.0.8.0", 22, cdbm.IPBlockProtocolVersionV4, false, cdbm.IPBlockStatusReady, ipu)
	assert.NotNil(t, ipb)

	_, err := ipam.CreateIpamEntryForIPBlock(ctx, ipamStorage, ipb.Prefix, ipb.PrefixLength, ipb.RoutingType, ipb.InfrastructureProviderID.String(), ipb.SiteID.String())
	assert.Nil(t, err)

	// Subnet 1 receives updates from Site Controller, namely status update
	subnet1 := testSubnetBuildSubnet(t, dbSession, "test-subnet-1", tn, vpc, nil, cdb.GetUUIDPtr(uuid.New()), &ipb.RoutingType, cdb.GetStrPtr("192.0.1.0"), cdb.GetStrPtr("192.0.1.0"), nil, 24, cdbm.SubnetStatusProvisioning, tnu)

	// Subnet 2 & FG is in Deleting state and gets deleted when no longer present in Site Controller inventory
	sbPrefix, err := ipam.CreateChildIpamEntryForIPBlock(ctx, nil, dbSession, ipamStorage, ipb, 24)
	assert.NoError(t, err)
	ipv4Prefix, _, err := ipam.ParseCidrIntoPrefixAndBlockSize(sbPrefix.Cidr)
	assert.NoError(t, err)
	ipv4Gateway, err := ipam.GetFirstIPFromCidr(sbPrefix.Cidr)
	assert.NoError(t, err)
	subnet2 := testSubnetBuildSubnet(t, dbSession, "test-subnet-2", tn, vpc, nil, cdb.GetUUIDPtr(uuid.New()), &ipb.RoutingType, &ipv4Prefix, &ipv4Gateway, &ipb.ID, 24, cdbm.SubnetStatusDeleting, tnu)
	subnet2.IPv4Block = ipb

	// Full Grant subnet deletion
	ipv4PrefixFG := "193.1.1.0"
	ipv4GatewayFG := "193.1.1.1"

	ipbFG := testSubnetBuildIPBlock(t, dbSession, "test-ipb-full-grant", st, ip, &tn.ID, cdbm.IPBlockRoutingTypeDatacenterOnly, ipv4PrefixFG, 24, cdbm.IPBlockProtocolVersionV4, false, cdbm.IPBlockStatusReady, ipu)
	_, err = ipam.CreateIpamEntryForIPBlock(ctx, ipamStorage, ipbFG.Prefix, ipbFG.PrefixLength, ipbFG.RoutingType, ip.ID.String(), st.ID.String())
	assert.NoError(t, err)
	_, err = ipam.CreateChildIpamEntryForIPBlock(ctx, nil, dbSession, ipamStorage, ipbFG, 24)
	assert.NoError(t, err)
	subnetFG := testSubnetBuildSubnet(t, dbSession, "test-subnet-FG", tn, vpc, nil, cdb.GetUUIDPtr(uuid.New()), &ipb.RoutingType, &ipv4PrefixFG, &ipv4GatewayFG, cdb.GetUUIDPtr(ipbFG.ID), 24, cdbm.SubnetStatusDeleting, tnu)
	subnetFG.IPv4Block = ipbFG

	// Subnet 3 is missing from Site Controller inventory but was not requested by user to be deleted, hence gets missing flag set
	subnet3 := testSubnetBuildSubnet(t, dbSession, "test-subnet-3", tn, vpc, nil, cdb.GetUUIDPtr(uuid.New()), &ipb.RoutingType, cdb.GetStrPtr("192.0.1.8"), cdb.GetStrPtr("192.0.1.8"), nil, 24, cdbm.SubnetStatusProvisioning, tnu)
	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE subnet SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)), subnet3.ID.String())
	assert.NoError(t, err)

	sbPrefix, err = ipam.CreateChildIpamEntryForIPBlock(ctx, nil, dbSession, ipamStorage, ipb, 26)
	assert.NoError(t, err)
	ipv4Prefix, _, err = ipam.ParseCidrIntoPrefixAndBlockSize(sbPrefix.Cidr)
	assert.NoError(t, err)
	ipv4Gateway, err = ipam.GetFirstIPFromCidr(sbPrefix.Cidr)
	assert.NoError(t, err)

	// Subnet 4 is missing from Site Controller inventory but does not have controller ID set, hence gets missing flag does not get set
	subnet4 := testSubnetBuildSubnet(t, dbSession, "test-subnet-4", tn, vpc, nil, nil, &ipb.RoutingType, &ipv4Prefix, &ipv4Gateway, &ipb.ID, 26, cdbm.SubnetStatusProvisioning, tnu)

	// Subnet 5 is reported as Ready in Controller inventory but is being deleted, so does not get updated
	subnet5 := testSubnetBuildSubnet(t, dbSession, "test-subnet-5", tn, vpc, nil, cdb.GetUUIDPtr(uuid.New()), &ipb.RoutingType, &ipv4Prefix, &ipv4Gateway, &ipb.ID, 26, cdbm.SubnetStatusDeleting, tnu)

	// Subnet 6 was previously missing but is reported as Ready in Controller inventory
	subnet6 := testSubnetBuildSubnet(t, dbSession, "test-subnet-6", tn, vpc, nil, cdb.GetUUIDPtr(uuid.New()), &ipb.RoutingType, &ipv4Prefix, &ipv4Gateway, &ipb.ID, 26, cdbm.SubnetStatusError, tnu)

	// Subnet 7 is in Deleting state and has no controller ID, gets deleted on inventory update
	sbPrefix7, err := ipam.CreateChildIpamEntryForIPBlock(ctx, nil, dbSession, ipamStorage, ipb, 24)
	assert.NoError(t, err)
	ipv4Prefix7, _, err := ipam.ParseCidrIntoPrefixAndBlockSize(sbPrefix7.Cidr)
	assert.NoError(t, err)
	ipv4Gateway7, err := ipam.GetFirstIPFromCidr(sbPrefix7.Cidr)
	assert.NoError(t, err)
	subnet7 := testSubnetBuildSubnet(t, dbSession, "test-subnet-7", tn, vpc, nil, nil, &ipb.RoutingType, &ipv4Prefix7, &ipv4Gateway7, &ipb.ID, 24, cdbm.SubnetStatusDeleting, tnu)
	subnet7.IPv4Block = ipb

	// Subnet 8 & 9 do not have controller ID, but it was created and inventory returns them
	subnet8 := testSubnetBuildSubnet(t, dbSession, "test-subnet-8", tn, vpc, nil, nil, &ipb.RoutingType, &ipv4Prefix, &ipv4Gateway, &ipb.ID, 26, cdbm.SubnetStatusProvisioning, tnu)

	// Subnet 9 does not have controller ID, but it was created and inventory returns it
	subnet9 := testSubnetBuildSubnet(t, dbSession, "test-subnet-9", tn, vpc, nil, nil, &ipb.RoutingType, &ipv4Prefix, &ipv4Gateway, &ipb.ID, 26, cdbm.SubnetStatusDeleting, tnu)

	subnetDAO := cdbm.NewSubnetDAO(dbSession)
	_, err = subnetDAO.Update(ctx, nil, cdbm.SubnetUpdateInput{SubnetId: subnet6.ID, IsMissingOnSite: cdb.GetBoolPtr(true)})
	assert.NoError(t, err)

	// Build Subnet inventory that is paginated
	// Generate data for 34 Subnets reported from Site Agent while Cloud has 38 Subnets
	pagedSubnets := []*cdbm.Subnet{}
	pagedInvIds := []string{}
	for i := 0; i < 38; i++ {
		subnet := testSubnetBuildSubnet(t, dbSession, fmt.Sprintf("test-vpc-paged-%d", i), tn, vpc, nil, cdb.GetUUIDPtr(uuid.New()), &ipb.RoutingType, &ipv4Prefix, &ipv4Gateway, &ipb.ID, 26, cdbm.SubnetStatusProvisioning, tnu)
		// Update creation timestamp to be earlier than inventory processing interval
		_, err = dbSession.DB.Exec("UPDATE subnet SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)), subnet.ID.String())
		assert.NoError(t, err)
		pagedSubnets = append(pagedSubnets, subnet)
		pagedInvIds = append(pagedInvIds, subnet.ControllerNetworkSegmentID.String())
	}

	pagedCtrlSubnets := []*cwssaws.NetworkSegment{}
	for i := 0; i < 34; i++ {
		ctrlSubnet := &cwssaws.NetworkSegment{
			Id:   &cwssaws.NetworkSegmentId{Value: pagedSubnets[i].ControllerNetworkSegmentID.String()},
			Name: pagedSubnets[i].Name,
		}
		pagedCtrlSubnets = append(pagedCtrlSubnets, ctrlSubnet)
	}

	tSiteClientPool := testTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	wtc := &tmocks.Client{}

	temporalsuit := testsuite.WorkflowTestSuite{}
	env := temporalsuit.NewTestWorkflowEnvironment()

	mtu := int32(1500)

	type fields struct {
		dbSession      *cdb.Session
		ipamStorage    cipam.Storage
		siteClientPool *sc.ClientPool
		tc             client.Client
		env            *testsuite.TestWorkflowEnvironment
	}

	type args struct {
		ctx             context.Context
		siteID          uuid.UUID
		subnetInventory *cwsv1.SubnetInventory
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		updatedSubnet   *cdbm.Subnet
		deletedSubnets  []*cdbm.Subnet
		deletingSubnet  *cdbm.Subnet
		missingSubnets  []*cdbm.Subnet
		restoredSubnet  *cdbm.Subnet
		unpairedSubnets []*cdbm.Subnet
		wantErr         bool
	}{
		{
			name: "test Subnet inventory processing error, non-existent Site",
			fields: fields{
				dbSession:      dbSession,
				ipamStorage:    ipamStorage,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: uuid.New(),
				subnetInventory: &cwsv1.SubnetInventory{
					Segments: []*cwsv1.NetworkSegment{
						{
							Id:    &cwsv1.NetworkSegmentId{Value: subnet1.ControllerNetworkSegmentID.String()},
							State: cwsv1.TenantState_READY,
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test Subnet inventory processing success",
			fields: fields{
				dbSession:      dbSession,
				ipamStorage:    ipamStorage,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st.ID,
				subnetInventory: &cwsv1.SubnetInventory{
					Segments: []*cwsv1.NetworkSegment{
						{
							Id:    &cwsv1.NetworkSegmentId{Value: subnet1.ControllerNetworkSegmentID.String()},
							Name:  subnet1.Name,
							State: cwsv1.TenantState_READY,
							Mtu:   &mtu,
						},
						{
							Id:    &cwsv1.NetworkSegmentId{Value: subnet5.ControllerNetworkSegmentID.String()},
							Name:  subnet5.Name,
							State: cwsv1.TenantState_READY,
						},
						{
							Id:    &cwsv1.NetworkSegmentId{Value: subnet6.ControllerNetworkSegmentID.String()},
							Name:  subnet6.Name,
							State: cwsv1.TenantState_READY,
						},
						{
							Id:    &cwsv1.NetworkSegmentId{Value: uuid.NewString()},
							Name:  subnet8.ID.String(),
							State: cwsv1.TenantState_READY,
						},
						{
							Id:    &cwsv1.NetworkSegmentId{Value: uuid.NewString()},
							Name:  subnet9.ID.String(),
							State: cwsv1.TenantState_READY,
						},
					},
				},
			},
			updatedSubnet:   subnet1,
			deletedSubnets:  []*cdbm.Subnet{subnet2, subnetFG, subnet7},
			deletingSubnet:  subnet5,
			missingSubnets:  []*cdbm.Subnet{subnet3, subnet4},
			restoredSubnet:  subnet6,
			unpairedSubnets: []*cdbm.Subnet{subnet8, subnet9},
			wantErr:         false,
		},
		{
			name: "test paged Subnet inventory processing, empty inventory",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st.ID,
				subnetInventory: &cwssaws.SubnetInventory{
					Segments:        []*cwssaws.NetworkSegment{},
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
			name: "test paged Subnet inventory processing, first page",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st.ID,
				subnetInventory: &cwssaws.SubnetInventory{
					Segments:  pagedCtrlSubnets[0:10],
					Timestamp: timestamppb.Now(),
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 1,
						TotalPages:  4,
						PageSize:    10,
						TotalItems:  34,
						ItemIds:     pagedInvIds[0:34],
					},
				},
			},
		},
		{
			name: "test paged Subnet inventory processing, last page",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st.ID,
				subnetInventory: &cwssaws.SubnetInventory{
					Segments:  pagedCtrlSubnets[30:34],
					Timestamp: timestamppb.Now(),
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 4,
						TotalPages:  4,
						PageSize:    10,
						TotalItems:  34,
						ItemIds:     pagedInvIds[0:34],
					},
				},
			},
			missingSubnets: pagedSubnets[34:38],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := NewManageSubnet(tt.fields.dbSession, tt.fields.siteClientPool, wtc)

			mtc := &tmocks.Client{}
			ms.siteClientPool.IDClientMap[vpc.SiteID.String()] = mtc

			_, err := ms.UpdateSubnetsInDB(tt.args.ctx, tt.args.siteID, tt.args.subnetInventory)
			assert.Equal(t, tt.wantErr, err != nil)

			if tt.wantErr {
				return
			}

			subnetDAO := cdbm.NewSubnetDAO(dbSession)

			// Check that Subnet status was updated in DB for Subnet 1
			if tt.updatedSubnet != nil {
				updatedSubnet, serr := subnetDAO.GetByID(ctx, nil, tt.updatedSubnet.ID, nil)
				assert.Nil(t, serr)
				assert.Equal(t, cdbm.SubnetStatusReady, updatedSubnet.Status)
				assert.Equal(t, *updatedSubnet.MTU, int(mtu))
			}

			for _, subnet := range tt.deletedSubnets {
				_, err = subnetDAO.GetByID(ctx, nil, subnet.ID, nil)
				require.Equal(t, cdb.ErrDoesNotExist, err, fmt.Sprintf("Subnet %s should have been deleted", subnet.Name))

				// Check that it's IPAM entry was removed
				if subnet.IPv4Block.PrefixLength != subnet.PrefixLength {
					ipamStorage := ipam.NewIpamStorage(dbSession.DB, nil)
					ipamer := cipam.NewWithStorage(ipamStorage)
					ipamer.SetNamespace(ipam.GetIpamNamespaceForIPBlock(ctx, ipb.RoutingType, ipb.InfrastructureProviderID.String(), ipb.SiteID.String()))
					pref := ipamer.PrefixFrom(ctx, ipam.GetCidrForIPBlock(ctx, *subnet.IPv4Prefix, subnet.PrefixLength))
					assert.Nil(t, pref)
				}
			}

			// Check that Subnet 3, which is missing from Site inventory has missing flag set and status set to Error
			for _, subnet := range tt.missingSubnets {
				us, serr := subnetDAO.GetByID(ctx, nil, subnet.ID, nil)
				assert.Nil(t, serr)

				if us.ControllerNetworkSegmentID != nil {
					assert.True(t, us.IsMissingOnSite)
					assert.Equal(t, cdbm.SubnetStatusError, us.Status)
				} else {
					assert.False(t, us.IsMissingOnSite)
				}
			}

			// Check that Subnet 6, which was previously marked missing is now restored
			if tt.restoredSubnet != nil {
				us, serr := subnetDAO.GetByID(ctx, nil, tt.restoredSubnet.ID, nil)
				assert.Nil(t, serr)
				assert.NotNil(t, us.ControllerNetworkSegmentID)
				assert.False(t, us.IsMissingOnSite)
				assert.Equal(t, cdbm.SubnetStatusReady, us.Status)
			}

			// Check that Subnet 5, which was in Deleting state, did not get its state changed to Ready if Site inventory reports it as Ready
			if tt.deletingSubnet != nil {
				us, err := subnetDAO.GetByID(ctx, nil, tt.deletingSubnet.ID, nil)
				assert.Nil(t, err)
				assert.Equal(t, cdbm.SubnetStatusDeleting, us.Status)
			}

			// Check that Subnet 8 & 9, which previously did not have controller ID, now have it
			for _, subnet := range tt.unpairedSubnets {
				us, serr := subnetDAO.GetByID(ctx, nil, subnet.ID, nil)
				assert.Nil(t, serr)
				assert.NotNil(t, us.ControllerNetworkSegmentID)
			}
		})
	}
}

func TestNewManageSubnet(t *testing.T) {
	type args struct {
		dbSession      *cdb.Session
		ipamStorage    cipam.Storage
		siteClientPool *sc.ClientPool
		tc             client.Client
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
	ipamStorage := ipam.NewIpamStorage(dbSession.DB, nil)
	scp := sc.NewClientPool(tcfg)

	wtc := &tmocks.Client{}

	tests := []struct {
		name string
		args args
		want ManageSubnet
	}{
		{
			name: "test new ManageSubnet instantiation",
			args: args{
				dbSession:      dbSession,
				ipamStorage:    ipamStorage,
				siteClientPool: scp,
				tc:             wtc,
			},
			want: ManageSubnet{
				dbSession:      dbSession,
				siteClientPool: scp,
				tc:             wtc,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewManageSubnet(tt.args.dbSession, tt.args.siteClientPool, wtc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewManageSubnet() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test Subnet Metrics - CREATE operations
func Test_SubnetMetrics_Create_PendingToReady(t *testing.T) {
	// Case 1: pending -> ready (should emit metric with duration t2-t1)
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageSubnetLifecycleMetrics(reg, dbSession)
	testSubnetID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime                                     // pending started
	t2 := baseTime.Add(150 * time.Millisecond)         // ready achieved
	createTime := baseTime.Add(200 * time.Millisecond) // create event happened
	expectedDuration := t2.Sub(t1)                     // 150ms

	// t1: pending
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusPending, nil, t1)

	// t2: ready
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusReady, nil, t2)

	// Process create event
	ctx := context.Background()
	err := lifecycleMetrics.RecordSubnetStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testSubnetID, Created: &createTime},
	})
	assert.NoError(t, err)

	// Verify metric was emitted with correct duration (150ms)
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_subnet_operation_latency_seconds", 1, map[string]string{
		"operation_type": "create",
		"from_status":    cdbm.SubnetStatusPending,
		"to_status":      cdbm.SubnetStatusReady,
	}, expectedDuration)
}

func Test_SubnetMetrics_Create_PendingErrorReady(t *testing.T) {
	// Case 2: pending -> error -> ready (should emit metric with duration t3-t1, ignoring error)
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageSubnetLifecycleMetrics(reg, dbSession)
	testSubnetID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime                                     // pending started
	t2 := baseTime.Add(100 * time.Millisecond)         // error occurred
	t3 := baseTime.Add(250 * time.Millisecond)         // ready achieved
	createTime := baseTime.Add(300 * time.Millisecond) // create event happened
	expectedDuration := t3.Sub(t1)                     // 250ms (ignoring error)

	// t1: pending
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusPending, nil, t1)

	// t2: error
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusError, nil, t2)

	// t3: ready
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusReady, nil, t3)

	// Process create event
	ctx := context.Background()
	err := lifecycleMetrics.RecordSubnetStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testSubnetID, Created: &createTime},
	})
	assert.NoError(t, err)

	// Verify metric was emitted with duration t3-t1 (250ms)
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_subnet_operation_latency_seconds", 1, map[string]string{
		"operation_type": "create",
		"from_status":    cdbm.SubnetStatusPending,
		"to_status":      cdbm.SubnetStatusReady,
	}, expectedDuration)
}

func Test_SubnetMetrics_Create_ReadyErrorReady(t *testing.T) {
	// Case 3: ready -> error -> ready (should NOT emit metric, duplicate ready)
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageSubnetLifecycleMetrics(reg, dbSession)
	testSubnetID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime                                     // ready (initial)
	t2 := baseTime.Add(100 * time.Millisecond)         // error occurred
	t3 := baseTime.Add(200 * time.Millisecond)         // ready (duplicate)
	createTime := baseTime.Add(300 * time.Millisecond) // create event happened

	// t1: ready (initial)
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusReady, nil, t1)

	// t2: error
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusError, nil, t2)

	// t3: ready (duplicate)
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusReady, nil, t3)

	// Process create event
	ctx := context.Background()
	err := lifecycleMetrics.RecordSubnetStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testSubnetID, Created: &createTime},
	})
	assert.NoError(t, err)

	// Verify NO metric was emitted (duplicate ready, no pending->ready transition)
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_subnet_operation_latency_seconds", 0, nil, 0)
}

// Test Subnet Metrics - DELETE operations
func Test_SubnetMetrics_Delete_DeletingOnly(t *testing.T) {
	// Case 1: deleting (should emit metric with duration now-t1)
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageSubnetLifecycleMetrics(reg, dbSession)
	testSubnetID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime                                     // deleting started
	deleteTime := baseTime.Add(180 * time.Millisecond) // delete happened 180ms later
	expectedDuration := deleteTime.Sub(t1)

	// t1: deleting
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusDeleting, nil, t1)

	// Process delete event
	ctx := context.Background()
	err := lifecycleMetrics.RecordSubnetStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testSubnetID, Deleted: &deleteTime},
	})
	assert.NoError(t, err)

	// Verify metric was emitted with correct duration (180ms)
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_subnet_operation_latency_seconds", 1, map[string]string{
		"operation_type": "delete",
		"from_status":    cdbm.SubnetStatusDeleting,
		"to_status":      cdbm.SubnetStatusDeleted,
	}, expectedDuration)
}

func Test_SubnetMetrics_Delete_MultipleDeletingTerminating(t *testing.T) {
	// Case 2: deleting -> deleting -> deleting (should emit metric with duration now-t1)
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageSubnetLifecycleMetrics(reg, dbSession)
	testSubnetID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime                                     // first deleting
	t2 := baseTime.Add(60 * time.Millisecond)          // second deleting
	t3 := baseTime.Add(120 * time.Millisecond)         // third deleting
	deleteTime := baseTime.Add(350 * time.Millisecond) // delete happened
	expectedDuration := deleteTime.Sub(t1)             // should use first deleting timestamp

	// t1: deleting
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusDeleting, nil, t1)

	// t2: deleting
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusDeleting, nil, t2)

	// t3: deleting
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusDeleting, nil, t3)

	// Process delete event
	ctx := context.Background()
	err := lifecycleMetrics.RecordSubnetStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testSubnetID, Deleted: &deleteTime},
	})
	assert.NoError(t, err)

	// Verify metric was emitted (should use first deleting timestamp, duration 350ms)
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_subnet_operation_latency_seconds", 1, map[string]string{
		"operation_type": "delete",
		"from_status":    cdbm.SubnetStatusDeleting,
		"to_status":      cdbm.SubnetStatusDeleted,
	}, expectedDuration)
}

func Test_SubnetMetrics_Delete_NoDeleting(t *testing.T) {
	// Case 3: ready (no deleting, should NOT emit metric)
	dbSession := testSubnetInitDB(t)
	defer dbSession.Close()
	testSubnetSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageSubnetLifecycleMetrics(reg, dbSession)
	testSubnetID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime
	deleteTime := baseTime.Add(120 * time.Millisecond)

	// t1: ready (no deleting status)
	util.TestBuildStatusDetailWithTime(t, dbSession, testSubnetID.String(), cdbm.SubnetStatusReady, nil, t1)

	// Process delete event
	ctx := context.Background()
	err := lifecycleMetrics.RecordSubnetStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testSubnetID, Deleted: &deleteTime},
	})
	assert.NoError(t, err)

	// Verify NO metric was emitted (no deleting status found)
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_subnet_operation_latency_seconds", 0, nil, 0)
}
