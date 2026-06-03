// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package instance

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	cwutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	sc "github.com/NVIDIA/infra-controller-rest/workflow/pkg/client/site"
	"github.com/NVIDIA/infra-controller-rest/workflow/pkg/queue"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller-rest/workflow/internal/config"
	cwm "github.com/NVIDIA/infra-controller-rest/workflow/internal/metrics"
	"github.com/NVIDIA/infra-controller-rest/workflow/pkg/util"

	cwsv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"

	"os"

	"go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
)

// testTemporalSiteClientPool Building site client pool
// TODO commonize this
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

func TestManageInstance_deleteInstanceFromDB(t *testing.T) {
	ctx := context.Background()

	dbSession := util.TestInitDB(t)
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
	tenant := util.TestBuildTenant(t, dbSession, tnOrg, "Test Tenant", &tncfg, tnu)

	site := util.TestBuildSite(t, dbSession, ip, "testSite", cdbm.SiteStatusPending, nil, ipu)
	vpc := util.TestBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	machine := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, cdb.GetStrPtr("mcTypeTest"), cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	allocation := util.TestBuildAllocation(t, dbSession, ip, tenant, site, "testAllocation")
	instanceType := util.TestBuildInstanceType(t, dbSession, ip, site, "testInstanceType")
	_ = util.TestBuildAllocationContraints(t, dbSession, allocation, cdbm.AllocationResourceTypeInstanceType, instanceType.ID, cdbm.AllocationConstraintTypeReserved, 5, ipu)
	operatingSystem := util.TestBuildOperatingSystem(t, dbSession, "testOS")

	isd := cdbm.NewInstanceDAO(dbSession)

	instance, err := isd.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test1",
			Description:              cdb.GetStrPtr("Test description"),
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
			Status:                   cdbm.InstanceStatusTerminating,
			PowerStatus:              cdb.GetStrPtr(cdbm.InstancePowerStatusBootCompleted),
			CreatedBy:                tnu.ID,
		},
	)
	require.NoError(t, err)

	ibp := util.TestBuildInfiniBandPartition(t, dbSession, "ibpart", site, tenant, nil, cdbm.InfiniBandPartitionStatusReady, false)
	nvlp := util.TestBuildNVLinkLogicalPartition(t, dbSession, "nvlp", cdb.GetStrPtr("nvlp"), site, tenant, cdbm.NVLinkLogicalPartitionStatusReady, false)

	ibiDAO := cdbm.NewInfiniBandInterfaceDAO(dbSession)
	_, err = ibiDAO.Create(ctx, nil, cdbm.InfiniBandInterfaceCreateInput{
		InstanceID:            instance.ID,
		SiteID:                site.ID,
		InfiniBandPartitionID: ibp.ID,
		Device:                "ib0",
		DeviceInstance:        0,
		IsPhysical:            true,
		Status:                cdbm.InfiniBandInterfaceStatusReady,
		CreatedBy:             tnu.ID,
	})
	require.NoError(t, err)

	nvliDAO := cdbm.NewNVLinkInterfaceDAO(dbSession)
	_, err = nvliDAO.Create(ctx, nil, cdbm.NVLinkInterfaceCreateInput{
		InstanceID:               instance.ID,
		SiteID:                   site.ID,
		NVLinkLogicalPartitionID: nvlp.ID,
		DeviceInstance:           0,
		Status:                   cdbm.NVLinkInterfaceStatusReady,
		CreatedBy:                tnu.ID,
	})
	require.NoError(t, err)

	// Add SSH Key Group Instance Association
	skg := util.TestBuildSSHKeyGroup(t, dbSession, "test-ssh-key-group-1", tnOrg, nil, tenant.ID, cdb.GetStrPtr("fbc692b61ffef6fbfc38a3833f6b7e7ae508da75"), cdbm.SSHKeyGroupStatusSynced, tnu.ID)
	_ = util.TestBuildSSHKeyGroupSiteAssociation(t, dbSession, skg.ID, site.ID, cdb.GetStrPtr("V1-1234567890"), cdbm.SSHKeyGroupSiteAssociationStatusSynced, tnu.ID)
	_ = util.TestBuildSSHKeyGroupInstanceAssociation(t, dbSession, skg.ID, site.ID, instance.ID, tnu.ID)

	// Add DPU Extension Service Deployment
	des := util.TestBuildDpuExtensionService(t, dbSession, "test-dpu-extension-service-1", site, tenant, cdbm.DpuExtensionServiceServiceTypeKubernetesPod, cdb.GetStrPtr("V1-1234567890"),
		&cdbm.DpuExtensionServiceVersionInfo{
			Version:        "V1-1234567890",
			Data:           "test-data",
			HasCredentials: true,
			Created:        time.Now(),
		}, []string{"V1-1234567890"}, cdbm.DpuExtensionServiceStatusReady, ipu)
	_ = util.TestBuildDpuExtensionServiceDeployment(t, dbSession, des.ID, site.ID, tenant.ID, instance.ID, "V1-1234567890", cdbm.DpuExtensionServiceDeploymentStatusRunning, tnu)

	tx, err := cdb.BeginTx(ctx, dbSession, &sql.TxOptions{})
	require.NoError(t, err)

	tSiteClientPool := testTemporalSiteClientPool(t)
	wtc := &tmocks.Client{}
	cfg := config.GetTestConfig()
	ms := NewManageInstance(dbSession, tSiteClientPool, wtc, cfg)

	err = ms.deleteInstanceFromDB(ctx, tx, instance, zerolog.Nop())
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	ibis, _, err := ibiDAO.GetAll(ctx, nil, cdbm.InfiniBandInterfaceFilterInput{InstanceIDs: []uuid.UUID{instance.ID}}, paginator.PageInput{Limit: cdb.GetIntPtr(paginator.TotalLimit)}, nil)
	require.NoError(t, err)
	require.Empty(t, ibis)

	nvlis, _, err := nvliDAO.GetAll(ctx, nil, cdbm.NVLinkInterfaceFilterInput{InstanceIDs: []uuid.UUID{instance.ID}}, paginator.PageInput{Limit: cdb.GetIntPtr(paginator.TotalLimit)}, nil)
	require.NoError(t, err)
	require.Empty(t, nvlis)

	skgiaDAO := cdbm.NewSSHKeyGroupInstanceAssociationDAO(dbSession)
	skgias, _, err := skgiaDAO.GetAll(ctx, nil, nil, nil, []uuid.UUID{instance.ID}, nil, nil, cdb.GetIntPtr(paginator.TotalLimit), nil)
	require.NoError(t, err)
	require.Empty(t, skgias)

	desdDAO := cdbm.NewDpuExtensionServiceDeploymentDAO(dbSession)
	desds, _, err := desdDAO.GetAll(ctx, nil, cdbm.DpuExtensionServiceDeploymentFilterInput{InstanceIDs: []uuid.UUID{instance.ID}}, paginator.PageInput{Limit: cdb.GetIntPtr(paginator.TotalLimit)}, nil)
	require.NoError(t, err)
	require.Empty(t, desds)
}

func TestManageInstance_UpdateInstancesInDB(t *testing.T) {
	ctx := context.Background()

	dbSession := util.TestInitDB(t)
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
	tenant := util.TestBuildTenant(t, dbSession, tnOrg, "Test Tenant", &tncfg, tnu)

	site := util.TestBuildSite(t, dbSession, ip, "testSite", cdbm.SiteStatusPending, nil, ipu)
	vpc := util.TestBuildVpc(t, dbSession, ip, site, tenant, "testVpc")
	subnet1 := util.TestBuildSubnet(t, dbSession, tenant, vpc, "testSubnet1", cdbm.SubnetStatusPending, cdb.GetUUIDPtr(uuid.New()))
	subnet2 := util.TestBuildSubnet(t, dbSession, tenant, vpc, "testSubnet2", cdbm.SubnetStatusPending, cdb.GetUUIDPtr(uuid.New()))
	subnet3 := util.TestBuildSubnet(t, dbSession, tenant, vpc, "testSubnet2", cdbm.SubnetStatusPending, nil)

	ipb1 := util.TestBuildBuildIPBlock(t, dbSession, "testipb", site, ip, &tenant.ID, cdbm.IPBlockRoutingTypeDatacenterOnly, "192.168.0.0", 24, cdbm.IPBlockProtocolVersionV4, false, cdbm.IPBlockStatusReady, tnu)
	assert.NotNil(t, ipb1)
	vpcPrefix1 := util.TestBuildVPCPrefix(t, dbSession, "test-vpcprefix-1", site, tenant, vpc.ID, &ipb1.ID, cdb.GetStrPtr("192.168.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusReady, tnu)
	vpcPrefix2 := util.TestBuildVPCPrefix(t, dbSession, "test-vpcprefix-2", site, tenant, vpc.ID, &ipb1.ID, cdb.GetStrPtr("192.172.0.0/24"), cdb.GetIntPtr(24), cdbm.VpcPrefixStatusReady, tnu)

	partition1 := util.TestBuildInfiniBandPartition(t, dbSession, "test-partition-1", site, tenant, cdb.GetUUIDPtr(uuid.New()), cdbm.InfiniBandPartitionStatusProvisioning, false)

	nvllPartition1 := util.TestBuildNVLinkLogicalPartition(t, dbSession, "test-nvlinklpartition-1", nil, site, tenant, cdbm.NVLinkLogicalPartitionStatusReady, false)
	assert.NotNil(t, nvllPartition1)

	machine1 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine2 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine3 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine4 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine5 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine6 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine7 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine8 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine9 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine10 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine11 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine13 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	machine15 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)

	allocation := util.TestBuildAllocation(t, dbSession, ip, tenant, site, "testAllocation")
	instanceType := util.TestBuildInstanceType(t, dbSession, ip, site, "testInstanceType")
	_ = util.TestBuildAllocationContraints(t, dbSession, allocation, cdbm.AllocationResourceTypeInstanceType, instanceType.ID, cdbm.AllocationConstraintTypeReserved, 7, ipu)
	operatingSystem := util.TestBuildOperatingSystem(t, dbSession, "testOS")

	instanceDAO := cdbm.NewInstanceDAO(dbSession)
	sdDAO := cdbm.NewStatusDetailDAO(dbSession)

	// Instance 1 receives updates from Site Controller, namely status update and Instance Subnet status, attribute updates
	instance1, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-1",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine1.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance1.ID.String())
	assert.NoError(t, err)

	interface1 := util.TestBuildInterface(t, dbSession, &instance1.ID, &subnet1.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, interface1)
	interface2 := util.TestBuildInterface(t, dbSession, &instance1.ID, &subnet2.ID, nil, false, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, interface2)
	interface3 := util.TestBuildInterface(t, dbSession, &instance1.ID, &subnet3.ID, nil, false, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, interface3)

	ibInterface1 := util.TestBuildInfiniBandInterface(t, dbSession, instance1.ID, site.ID, partition1.ID, "MT2910 Family [ConnectX-7]", 0, true, nil, cdbm.InfiniBandInterfaceStatusPending, false)
	assert.NotNil(t, ibInterface1)

	ibInterface2 := util.TestBuildInfiniBandInterface(t, dbSession, instance1.ID, site.ID, partition1.ID, "MT2910 Family [ConnectX-7]", 1, true, nil, cdbm.InfiniBandInterfaceStatusPending, false)
	assert.NotNil(t, ibInterface2)

	ibInterface3 := util.TestBuildInfiniBandInterface(t, dbSession, instance1.ID, site.ID, partition1.ID, "MT2910 Family [ConnectX-7]", 2, true, nil, cdbm.InfiniBandInterfaceStatusDeleting, false)
	assert.NotNil(t, ibInterface3)

	// Make Deleting InfiniBand row old enough to pass IsTimeWithinStaleInventoryThreshold deferral during inventory reconcile
	_, err = dbSession.DB.Exec("UPDATE infiniband_interface SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), ibInterface3.ID.String())
	assert.NoError(t, err)

	// NVLink Interfaces
	nvlinkInterface1 := util.TestBuildNVLinkInterface(t, dbSession, instance1.ID, site.ID, nvllPartition1.ID, cdb.GetStrPtr(""), 0, nil, nil, cdbm.NVLinkInterfaceStatusPending)
	assert.NotNil(t, nvlinkInterface1)

	nvlinkInterface2 := util.TestBuildNVLinkInterface(t, dbSession, instance1.ID, site.ID, nvllPartition1.ID, cdb.GetStrPtr(""), 1, nil, nil, cdbm.NVLinkInterfaceStatusPending)
	assert.NotNil(t, nvlinkInterface2)

	nvlinkInterface3 := util.TestBuildNVLinkInterface(t, dbSession, instance1.ID, site.ID, nvllPartition1.ID, cdb.GetStrPtr(""), 2, cdb.GetStrPtr("e1f2a30200d71e9f"), nil, cdbm.NVLinkInterfaceStatusDeleting)
	assert.NotNil(t, nvlinkInterface3)

	// Set updated earlier than the inventory receipt interval for nvlinkInterface3 so it can be deleted
	_, err = dbSession.DB.Exec("UPDATE nvlink_interface SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlinkInterface3.ID.String())
	assert.NoError(t, err)

	nvlinkInterface4 := util.TestBuildNVLinkInterface(t, dbSession, instance1.ID, site.ID, nvllPartition1.ID, cdb.GetStrPtr(""), 3, nil, nil, cdbm.NVLinkInterfaceStatusPending)
	assert.NotNil(t, nvlinkInterface4)

	// Instance 2 is in Terminating state and gets deleted when missing from Site Controller inventory
	instance2, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-2",
			Description:              cdb.GetStrPtr("Test description"),
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
			Status:                   cdbm.InstanceStatusTerminating,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance2.ID.String())
	assert.NoError(t, err)

	instance2Subnet := util.TestBuildInterface(t, dbSession, &instance2.ID, &subnet1.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, instance2Subnet)

	skg1 := util.TestBuildSSHKeyGroup(t, dbSession, "test-sshkeygroup-1", tnOrg, cdb.GetStrPtr("test1"), tenant.ID, cdb.GetStrPtr("122345"), cdbm.SSHKeyGroupStatusSyncing, tnu.ID)
	assert.NotNil(t, skg1)
	skgsa1 := util.TestBuildSSHKeyGroupSiteAssociation(t, dbSession, skg1.ID, site.ID, cdb.GetStrPtr("1134"), cdbm.SSHKeyGroupSiteAssociationStatusSyncing, tnu.ID)
	assert.NotNil(t, skgsa1)
	skgia1 := util.TestBuildSSHKeyGroupInstanceAssociation(t, dbSession, skg1.ID, site.ID, instance2.ID, tnu.ID)
	assert.NotNil(t, skgia1)

	// Instance 3 is missing from Site Controller inventory, has controller ID, hence missing flag gets set and error raised
	instance3, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "Test Instance 3",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine3.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)
	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)), instance3.ID.String())
	assert.NoError(t, err)

	// Set updated earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance3.ID.String())
	assert.NoError(t, err)

	instance3Subnet := util.TestBuildInterface(t, dbSession, &instance3.ID, &subnet1.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, instance3Subnet)

	// Instance 4 is missing from Site Controller inventory and does not have controller ID, hence missing flag does not get set
	instance4, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "Test Instance 4",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine4.ID,
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set updated earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance4.ID.String())
	assert.NoError(t, err)

	instance4Subnet := util.TestBuildInterface(t, dbSession, &instance4.ID, &subnet1.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusError)
	assert.NotNil(t, instance4Subnet)

	// Instance 5 is in Terminating state and does not get set back to Ready state from stale inventory
	instance5, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "Test Instance 5",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine5.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			PhoneHomeEnabled:         true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusTerminating,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance5.ID.String())
	assert.NoError(t, err)

	// Instance 6 is in Error state and gets restored to Ready state from inventory
	instance6, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "Test Instance 6",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine6.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			PhoneHomeEnabled:         true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusError,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)
	_, err = instanceDAO.Update(ctx, nil, cdbm.InstanceUpdateInput{InstanceID: instance6.ID, InstanceUpdateCommonInput: cdbm.InstanceUpdateCommonInput{IsMissingOnSite: cdb.GetBoolPtr(true)}})
	assert.Nil(t, err)

	// Set updated earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance6.ID.String())
	assert.NoError(t, err)

	// Instance 7 does not have controller Instance ID set and is present in inventory, and gets controller Instance ID set
	instance7, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "Test Instance 7",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine7.ID,
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			PhoneHomeEnabled:         true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set updated earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance7.ID.String())
	assert.NoError(t, err)

	// Instance 8 is in Terminating state and has no controller ID, gets deleted on inventory update
	instance8, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "Test Instance 8",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine8.ID,
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			PhoneHomeEnabled:         true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusTerminating,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set updated earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance8.ID.String())
	assert.NoError(t, err)

	// Instance 9 is in Ready state and power status is Rebooting, gets set to BootCompleted
	instance9, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "Test Instance 9",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine9.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			PhoneHomeEnabled:         true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusReady,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set updated earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance9.ID.String())
	assert.NoError(t, err)

	var vfID uint32 = 1
	macAddress := "2F-FC-34-AE-9C-2A"
	ipAddresses := []string{"200.32.11.190", "51aa:f78b:ffb0:1c58:7bee:b9e7:bf35:0962"}
	requestedIpAddress := "10.0.0.15"
	routingProfilePrefixes := []string{"192.0.2.0/24", "2001:db8::/64"}

	// Instance 10 is already set to Error/marked as missing, no new status details is created for it when it's reported missing again
	instance10, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-10",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine10.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusError,
			CreatedBy:                tnu.ID,
		},
	)
	assert.NoError(t, err)
	// Update creation timestamp to be earlier than inventory processing interval
	_, err = dbSession.DB.Exec("UPDATE instance SET is_missing_on_site = true, created = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance10.ID.String())
	assert.NoError(t, err)

	// Set updated earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance10.ID.String())
	assert.NoError(t, err)

	// Create status detail for instance 10
	_, err = sdDAO.CreateFromParams(ctx, nil, instance10.ID.String(), instance10.Status, cdb.GetStrPtr("Instance is missing on Site"))
	assert.NoError(t, err)

	// Instance 11 receives updates from Site Controller, namely status update and Instance VPC Prefix status, attribute updates
	instance11, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-11",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine11.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			NetworkSecurityGroupPropagationDetails: &cdbm.NetworkSecurityGroupPropagationDetails{
				NetworkSecurityGroupPropagationObjectStatus: &cwsv1.NetworkSecurityGroupPropagationObjectStatus{},
			},
			CreatedBy: tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance11.ID.String())
	assert.NoError(t, err)

	// Replicate the bug fix test
	ifcvpc0 := util.TestBuildInterface(t, dbSession, &instance11.ID, nil, &vpcPrefix1.ID, true, cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"), nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, ifcvpc0)
	_, err = cdbm.NewInterfaceDAO(dbSession).Update(ctx, nil, cdbm.InterfaceUpdateInput{
		InterfaceID: ifcvpc0.ID,
		InlineRoutingProfile: &cdbm.InterfaceInlineRoutingProfile{
			AllowedAnycastPrefixes: []string{"198.51.100.0/24"},
		},
	})
	assert.Nil(t, err)

	ifcvpc0_1 := util.TestBuildInterface(t, dbSession, &instance11.ID, nil, &vpcPrefix1.ID, false, cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"), nil, db.GetIntPtr(1), &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, ifcvpc0_1)

	ifcvpc1 := util.TestBuildInterface(t, dbSession, &instance11.ID, nil, &vpcPrefix1.ID, true, cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"), cdb.GetIntPtr(1), nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, ifcvpc1)

	ifcvpc1_1 := util.TestBuildInterface(t, dbSession, &instance11.ID, nil, &vpcPrefix1.ID, false, cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"), cdb.GetIntPtr(1), db.GetIntPtr(1), &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, ifcvpc1_1)

	// Instance 12 is defined below

	// Instance 13 receives updates from Site Controller but same status as current
	instance13, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-11",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine13.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)
	util.TestBuildStatusDetail(t, dbSession, instance13.ID.String(), cdbm.InstanceStatusProvisioning, cdb.GetStrPtr("Instance is being provisioned on Site"))

	// Instance 14 receives updates from Site Controller, but cloud DB saw an update that was too recent.
	instance14, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-1",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine1.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)
	util.TestBuildStatusDetail(t, dbSession, instance14.ID.String(), cdbm.InstanceStatusProvisioning, cdb.GetStrPtr("Instance is being provisioned on Site"))

	// Instance 15 is in Configuring state and gets set to Ready
	// Make sure the interfaces are deleted and pending one is converted to ready

	// Instance 15 receives updates from Site Controller, namely status update and Instance VPC Prefix status, attribute updates
	instance15, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-15",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine15.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusConfiguring,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance15.ID.String())
	assert.NoError(t, err)

	ifcvpc_deleting := util.TestBuildInterface(t, dbSession, &instance15.ID, nil, &vpcPrefix1.ID, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusDeleting)
	assert.NotNil(t, ifcvpc_deleting)

	ifcvpc_pending := util.TestBuildInterface(t, dbSession, &instance15.ID, nil, &vpcPrefix2.ID, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, ifcvpc_pending)
	_, err = cdbm.NewInterfaceDAO(dbSession).Update(ctx, nil, cdbm.InterfaceUpdateInput{
		InterfaceID:        ifcvpc_pending.ID,
		RequestedIpAddress: &requestedIpAddress,
		InlineRoutingProfile: &cdbm.InterfaceInlineRoutingProfile{
			AllowedAnycastPrefixes: []string{"198.51.100.0/24"},
		},
	})
	assert.Nil(t, err)

	// Instance 16 starts with an initial TPM EK certificate and gets updated with a new certificate value
	machine16 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	instance16, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-16",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine16.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			// Start with an initial TPM EK certificate
			TpmEkCertificate: cdb.GetStrPtr("initial-cert-value"),
			CreatedBy:        tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance16.ID.String())
	assert.NoError(t, err)

	// Instance 17 starts with nil TPM EK certificate and gets updated with a certificate value
	machine17 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	instance17, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-17",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine17.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			// Start with nil TPM EK certificate
			TpmEkCertificate: nil,
			CreatedBy:        tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance17.ID.String())
	assert.NoError(t, err)

	// Sample base64 encoded TPM EK certificate (truncated for brevity but realistic format)
	tpmEKCertBase64 := "MIICXjCCAUYCFGvJgf1k9b2LqK2F3VzjRkGbXfGGMA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMMGFRQTSBFSyBDZXJ0aWZpY2F0ZSBUZXN0MB4XDTIzMTAwMTA4MDAzNVoXDTMzMDkyODA4MDAzNVowIzEhMB8GA1UEAwwYVFBNIEVLIENlcnRpZmljYXRlIFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8uKdyQ1P+KqHGfyJLIvJhDzQ3rHnS"

	// Instance 18 receives updates from Site Controller, namely status update and Instance Subnet status, attribute updates
	machine18 := util.TestBuildMachine(t, dbSession, ip.ID, site.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	instance18, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-18",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site.ID,
			InstanceTypeID:           &instanceType.ID,
			VpcID:                    vpc.ID,
			MachineID:                &machine18.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusProvisioning,
			CreatedBy:                tnu.ID,
		},
	)
	assert.Nil(t, err)

	// Set created earlier than the inventory receipt interval
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance18.ID.String())
	assert.NoError(t, err)

	interface18_1 := util.TestBuildInterface(t, dbSession, &instance18.ID, &subnet1.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, interface18_1)
	interface18_2 := util.TestBuildInterface(t, dbSession, &instance18.ID, &subnet2.ID, nil, false, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, interface18_2)
	interface18_3 := util.TestBuildInterface(t, dbSession, &instance18.ID, &subnet3.ID, nil, false, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)
	assert.NotNil(t, interface18_3)

	ibInterface18_1 := util.TestBuildInfiniBandInterface(t, dbSession, instance18.ID, site.ID, partition1.ID, "MT2910 Family [ConnectX-7]", 0, true, nil, cdbm.InfiniBandInterfaceStatusDeleting, false)
	assert.NotNil(t, ibInterface18_1)

	ibInterface18_2 := util.TestBuildInfiniBandInterface(t, dbSession, instance18.ID, site.ID, partition1.ID, "MT2910 Family [ConnectX-7]", 1, true, nil, cdbm.InfiniBandInterfaceStatusDeleting, false)
	assert.NotNil(t, ibInterface18_2)

	ibInterface18_3 := util.TestBuildInfiniBandInterface(t, dbSession, instance18.ID, site.ID, partition1.ID, "MT2910 Family [ConnectX-7]", 2, true, nil, cdbm.InfiniBandInterfaceStatusDeleting, false)
	assert.NotNil(t, ibInterface18_3)

	for _, ibd := range []*cdbm.InfiniBandInterface{ibInterface18_1, ibInterface18_2, ibInterface18_3} {
		_, err = dbSession.DB.Exec("UPDATE infiniband_interface SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), ibd.ID.String())
		assert.NoError(t, err)
	}

	// Build DPU Extension Services and Deployments for testing
	dpuExtensionService1 := util.TestBuildDpuExtensionService(t, dbSession, "test-dpu-ext-service-1", site, tenant, "ovs-offload", cdb.GetStrPtr("1"), nil, []string{}, cdbm.DpuExtensionServiceStatusReady, ipu)
	assert.NotNil(t, dpuExtensionService1)

	dpuExtensionService2 := util.TestBuildDpuExtensionService(t, dbSession, "test-dpu-ext-service-2", site, tenant, "ovs-offload", cdb.GetStrPtr("1"), nil, []string{}, cdbm.DpuExtensionServiceStatusReady, ipu)
	assert.NotNil(t, dpuExtensionService2)

	// Create DPU Extension Service Deployment for instance1 - will be updated to Running
	dpuExtServiceDeployment1 := util.TestBuildDpuExtensionServiceDeployment(t, dbSession, dpuExtensionService1.ID, site.ID, tenant.ID, instance1.ID, "1.0.0", cdbm.DpuExtensionServiceDeploymentStatusPending, ipu)
	assert.NotNil(t, dpuExtServiceDeployment1)

	// Create DPU Extension Service Deployment for instance1 - will be deleted (missing from inventory)
	dpuExtServiceDeployment2 := util.TestBuildDpuExtensionServiceDeployment(t, dbSession, dpuExtensionService2.ID, site.ID, tenant.ID, instance1.ID, "1.0.0", cdbm.DpuExtensionServiceDeploymentStatusRunning, ipu)
	assert.NotNil(t, dpuExtServiceDeployment2)

	// Set updated earlier than the inventory receipt interval for dpuExtServiceDeployment2 so it can be deleted
	_, err = dbSession.DB.Exec("UPDATE dpu_extension_service_deployment SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), dpuExtServiceDeployment2.ID.String())
	assert.NoError(t, err)

	instanceInventory := &cwsv1.InstanceInventory{
		NetworkSecurityGroupPropagations: []*cwsv1.NetworkSecurityGroupPropagationObjectStatus{
			&cwsv1.NetworkSecurityGroupPropagationObjectStatus{
				Id:      instance1.ID.String(),
				Status:  cwsv1.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_FULL,
				Details: db.GetStrPtr("nothing to see here"),
			},
		},
		Instances: []*cwsv1.Instance{
			{
				Id: &cwsv1.InstanceId{Value: instance1.ID.String()},
				Config: &cwsv1.InstanceConfig{
					Network: &cwsv1.InstanceNetworkConfig{
						Interfaces: []*cwsv1.InstanceInterfaceConfig{
							{
								FunctionType:     cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION,
								NetworkSegmentId: &cwsv1.NetworkSegmentId{Value: subnet1.ControllerNetworkSegmentID.String()},
							},
							{
								FunctionType:     cwsv1.InterfaceFunctionType_VIRTUAL_FUNCTION,
								NetworkSegmentId: &cwsv1.NetworkSegmentId{Value: subnet2.ControllerNetworkSegmentID.String()},
							},
						},
					},
					// InfiniBand config/status keys must align with reconcile map: controller IB partition id + device + device instance
					Infiniband: &cwsv1.InstanceInfinibandConfig{
						IbInterfaces: []*cwsv1.InstanceIBInterfaceConfig{
							{
								Device:         "MT2910 Family [ConnectX-7]",
								Vendor:         cdb.GetStrPtr("Mellanox Technologies"),
								DeviceInstance: 0,
								FunctionType:   cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION,
								IbPartitionId:  &cwsv1.IBPartitionId{Value: partition1.ControllerIBPartitionID.String()},
							},
							{
								Device:         "MT2910 Family [ConnectX-7]",
								Vendor:         cdb.GetStrPtr("Mellanox Technologies"),
								DeviceInstance: 1,
								FunctionType:   cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION,
								IbPartitionId:  &cwsv1.IBPartitionId{Value: partition1.ControllerIBPartitionID.String()},
							},
						},
					},
					DpuExtensionServices: &cwsv1.InstanceDpuExtensionServicesConfig{
						ServiceConfigs: []*cwsv1.InstanceDpuExtensionServiceConfig{
							{
								ServiceId: dpuExtensionService1.ID.String(),
								Version:   "1.0.0",
							},
						},
					},
					Nvlink: &cwsv1.InstanceNVLinkConfig{
						GpuConfigs: []*cwsv1.InstanceNVLinkGpuConfig{
							{
								DeviceInstance:     0,
								LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition1.ID.String()},
							},
							{
								DeviceInstance:     1,
								LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition1.ID.String()},
							},
							{
								DeviceInstance:     2,
								LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition1.ID.String()},
							},
							{
								DeviceInstance:     3,
								LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition1.ID.String()},
							},
						},
					},
				},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
					Network: &cwsv1.InstanceNetworkStatus{
						Interfaces: []*cwsv1.InstanceInterfaceStatus{
							{
								MacAddress: &macAddress,
								Addresses:  ipAddresses,
							},
							{
								VirtualFunctionId: &vfID,
								MacAddress:        &macAddress,
								Addresses:         ipAddresses,
							},
						},
						ConfigsSynced: cwsv1.SyncState_SYNCED,
					},
					Infiniband: &cwsv1.InstanceInfinibandStatus{
						IbInterfaces: []*cwsv1.InstanceIBInterfaceStatus{
							{
								PfGuid: cdb.GetStrPtr("1070fd0300bd43ad"),
								Guid:   cdb.GetStrPtr("1070fd0300bd43ad"),
							},
							{
								PfGuid: cdb.GetStrPtr("c470bd0300ebe2b8"),
								Guid:   cdb.GetStrPtr("c470bd0300ebe2b8"),
							},
						},
						ConfigsSynced: cwsv1.SyncState_SYNCED,
					},
					DpuExtensionServices: &cwsv1.InstanceDpuExtensionServicesStatus{
						DpuExtensionServices: []*cwsv1.InstanceDpuExtensionServiceStatus{
							{
								ServiceId:        dpuExtensionService1.ID.String(),
								Version:          "1.0.0",
								DeploymentStatus: cwsv1.DpuExtensionServiceDeploymentStatus_DPU_EXTENSION_SERVICE_RUNNING,
							},
						},
					},
					Nvlink: &cwsv1.InstanceNVLinkStatus{
						GpuStatuses: []*cwsv1.InstanceNVLinkGpuStatus{
							{
								GpuGuid:            cdb.GetStrPtr("a8f4c20500d71e9f"),
								DomainId:           &cwsv1.NVLinkDomainId{Value: uuid.New().String()},
								LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition1.ID.String()},
							},
							{
								GpuGuid:            cdb.GetStrPtr("b3e8d70400c52f1a"),
								DomainId:           &cwsv1.NVLinkDomainId{Value: uuid.New().String()},
								LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition1.ID.String()},
							},
							{
								GpuGuid:            cdb.GetStrPtr("c470bd0300ebe2b8"),
								DomainId:           &cwsv1.NVLinkDomainId{Value: uuid.New().String()},
								LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition1.ID.String()},
							},
							{
								GpuGuid:            cdb.GetStrPtr("d3e7d60400c52f1a"),
								DomainId:           &cwsv1.NVLinkDomainId{Value: uuid.New().String()},
								LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition1.ID.String()},
							},
						},
						ConfigsSynced: cwsv1.SyncState_SYNCED,
					},
					Update: &cwsv1.InstanceUpdateStatus{
						UserApprovalReceived: false,
					},
				},
			},
			{
				Id:     &cwsv1.InstanceId{Value: instance5.ControllerInstanceID.String()},
				Config: &cwsv1.InstanceConfig{},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
				},
			},
			{
				Id:     &cwsv1.InstanceId{Value: instance6.ControllerInstanceID.String()},
				Config: &cwsv1.InstanceConfig{},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
				},
			},
			{
				Id:     &cwsv1.InstanceId{Value: instance7.ID.String()},
				Config: &cwsv1.InstanceConfig{},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
				},
			},
			{
				Id:     &cwsv1.InstanceId{Value: instance9.ID.String()},
				Config: &cwsv1.InstanceConfig{},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
				},
			},
			{
				Id: &cwsv1.InstanceId{Value: instance11.ControllerInstanceID.String()},
				Config: &cwsv1.InstanceConfig{
					Network: &cwsv1.InstanceNetworkConfig{
						Interfaces: []*cwsv1.InstanceInterfaceConfig{
							{
								FunctionType:     cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION,
								NetworkSegmentId: nil,
								// VPC Prefix info
								NetworkDetails: &cwsv1.InstanceInterfaceConfig_VpcPrefixId{
									VpcPrefixId: &cwsv1.VpcPrefixId{Value: vpcPrefix1.ID.String()},
								},
								Device:    cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"),
								IpAddress: &requestedIpAddress,
								RoutingProfile: &cwsv1.InstanceInterfaceRoutingProfile{
									AllowedAnycastPrefixes: []*cwsv1.PrefixFilterPolicyEntry{
										{Prefix: routingProfilePrefixes[0]},
										{Prefix: routingProfilePrefixes[1]},
									},
								},
							},
							{
								FunctionType:     cwsv1.InterfaceFunctionType_VIRTUAL_FUNCTION,
								NetworkSegmentId: nil,
								// VPC Prefix info
								NetworkDetails: &cwsv1.InstanceInterfaceConfig_VpcPrefixId{
									VpcPrefixId: &cwsv1.VpcPrefixId{Value: vpcPrefix1.ID.String()},
								},
								Device:            cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"),
								VirtualFunctionId: &vfID,
							},
							{
								FunctionType:     cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION,
								NetworkSegmentId: nil,
								// VPC Prefix info
								NetworkDetails: &cwsv1.InstanceInterfaceConfig_VpcPrefixId{
									VpcPrefixId: &cwsv1.VpcPrefixId{Value: vpcPrefix1.ID.String()},
								},
								Device:         cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"),
								DeviceInstance: 1,
							},
							{
								FunctionType:     cwsv1.InterfaceFunctionType_VIRTUAL_FUNCTION,
								NetworkSegmentId: nil,
								// VPC Prefix info
								NetworkDetails: &cwsv1.InstanceInterfaceConfig_VpcPrefixId{
									VpcPrefixId: &cwsv1.VpcPrefixId{Value: vpcPrefix1.ID.String()},
								},
								Device:            cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"),
								DeviceInstance:    1,
								VirtualFunctionId: &vfID,
							},
						},
					},
				},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
					Network: &cwsv1.InstanceNetworkStatus{
						Interfaces: []*cwsv1.InstanceInterfaceStatus{
							{
								MacAddress: &macAddress,
								Addresses:  ipAddresses,
								Device:     cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"),
							},
							{
								MacAddress:        &macAddress,
								Addresses:         ipAddresses,
								Device:            cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"),
								VirtualFunctionId: &vfID,
							},
							{
								VirtualFunctionId: nil,
								MacAddress:        &macAddress,
								Addresses:         ipAddresses,
								Device:            cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"),
								DeviceInstance:    1,
							},
							{
								MacAddress:        &macAddress,
								Addresses:         ipAddresses,
								Device:            cdb.GetStrPtr("MT43244 BlueField-3 integrated ConnectX-7 network controller"),
								DeviceInstance:    1,
								VirtualFunctionId: &vfID,
							},
						},
						ConfigsSynced: cwsv1.SyncState_SYNCED,
					},
					Update: &cwsv1.InstanceUpdateStatus{
						UserApprovalReceived: false,
					},
				},
			},
			{
				Id: &cwsv1.InstanceId{Value: instance15.ControllerInstanceID.String()},
				Config: &cwsv1.InstanceConfig{
					Network: &cwsv1.InstanceNetworkConfig{
						Interfaces: []*cwsv1.InstanceInterfaceConfig{
							{
								FunctionType:     cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION,
								NetworkSegmentId: nil,
								// VPC Prefix info
								NetworkDetails: &cwsv1.InstanceInterfaceConfig_VpcPrefixId{
									VpcPrefixId: &cwsv1.VpcPrefixId{Value: vpcPrefix2.ID.String()},
								},
							},
						},
					},
				},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
					Network: &cwsv1.InstanceNetworkStatus{
						Interfaces: []*cwsv1.InstanceInterfaceStatus{
							{
								VirtualFunctionId: &vfID,
								MacAddress:        &macAddress,
								Addresses:         ipAddresses,
							},
						},
						ConfigsSynced: cwsv1.SyncState_SYNCED,
					},
					Update: &cwsv1.InstanceUpdateStatus{
						UserApprovalReceived: false,
					},
				},
			},
			{
				Id:     &cwsv1.InstanceId{Value: instance13.ID.String()},
				Config: &cwsv1.InstanceConfig{},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_PROVISIONING,
					},
				},
			},
			{
				Id:     &cwsv1.InstanceId{Value: instance14.ID.String()},
				Config: &cwsv1.InstanceConfig{},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
				},
			},
			{
				Id:               &cwsv1.InstanceId{Value: instance16.ControllerInstanceID.String()},
				Config:           &cwsv1.InstanceConfig{},
				TpmEkCertificate: &tpmEKCertBase64,
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
				},
			},
			{
				Id:               &cwsv1.InstanceId{Value: instance17.ControllerInstanceID.String()},
				Config:           &cwsv1.InstanceConfig{},
				TpmEkCertificate: &tpmEKCertBase64,
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
				},
			},
			{
				Id: &cwsv1.InstanceId{Value: instance18.ID.String()},
				Config: &cwsv1.InstanceConfig{
					Network: &cwsv1.InstanceNetworkConfig{
						Interfaces: []*cwsv1.InstanceInterfaceConfig{
							{
								FunctionType:     cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION,
								NetworkSegmentId: &cwsv1.NetworkSegmentId{Value: subnet1.ControllerNetworkSegmentID.String()},
							},
							{
								FunctionType:     cwsv1.InterfaceFunctionType_VIRTUAL_FUNCTION,
								NetworkSegmentId: &cwsv1.NetworkSegmentId{Value: subnet2.ControllerNetworkSegmentID.String()},
							},
						},
					},
					Infiniband: nil,
				},
				Status: &cwsv1.InstanceStatus{
					Tenant: &cwsv1.InstanceTenantStatus{
						State: cwsv1.TenantState_READY,
					},
					Network: &cwsv1.InstanceNetworkStatus{
						Interfaces: []*cwsv1.InstanceInterfaceStatus{
							{
								MacAddress: &macAddress,
								Addresses:  ipAddresses,
							},
							{
								VirtualFunctionId: &vfID,
								MacAddress:        &macAddress,
								Addresses:         ipAddresses,
							},
						},
						ConfigsSynced: cwsv1.SyncState_SYNCED,
					},
					Infiniband: nil,
					Update: &cwsv1.InstanceUpdateStatus{
						UserApprovalReceived: false,
					},
				},
			},
		},
	}

	site2 := util.TestBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered, nil, ipu)
	vpc2 := util.TestBuildVpc(t, dbSession, ip, site2, tenant, "test-vpc-2")

	// Build another 38 Machines for pagination
	pageMachines := []*cdbm.Machine{}
	for i := 0; i < 38; i++ {
		machine := util.TestBuildMachine(t, dbSession, ip.ID, site2.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
		pageMachines = append(pageMachines, machine)
	}

	allocation2 := util.TestBuildAllocation(t, dbSession, ip, tenant, site2, "test-allocation-2")
	instanceType2 := util.TestBuildInstanceType(t, dbSession, ip, site, "test-instance-type-2")
	_ = util.TestBuildAllocationContraints(t, dbSession, allocation2, cdbm.AllocationResourceTypeInstanceType, instanceType2.ID, cdbm.AllocationConstraintTypeReserved, 38, ipu)

	// Build Instance inventory that is paginated
	// Generate data for 34 Instances reported from Site Agent while Cloud has 38 Instances
	pagedIns := []*cdbm.Instance{}
	pagedInvIds := []string{}
	labels := map[string]string{}
	for i := 0; i < 38; i++ {

		// Making labels mismatch
		if i == 1 {
			labels = map[string]string{
				"west1": "gpu",
			}
		}

		ins, err := instanceDAO.Create(
			ctx, nil,
			cdbm.InstanceCreateInput{
				Name:                     fmt.Sprintf("Test Instance %d", i),
				Description:              cdb.GetStrPtr("Test description"),
				TenantID:                 tenant.ID,
				InfrastructureProviderID: ip.ID,
				SiteID:                   site2.ID,
				InstanceTypeID:           &instanceType2.ID,
				VpcID:                    vpc2.ID,
				MachineID:                &pageMachines[i].ID,
				ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
				Hostname:                 cdb.GetStrPtr("test.com"),
				OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
				IpxeScript:               cdb.GetStrPtr("ipxe"),
				AlwaysBootWithCustomIpxe: true,
				UserData:                 cdb.GetStrPtr("userdata"),
				Labels:                   labels,
				Status:                   cdbm.InstanceStatusReady,
				CreatedBy:                tnu.ID,
			},
		)

		assert.NoError(t, err)
		// Update creation timestamp to be earlier than inventory processing interval
		_, err = dbSession.DB.Exec("UPDATE instance SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), ins.ID.String())
		assert.NoError(t, err)

		// Update updated timestamp to be earlier than inventory processing interval
		_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), ins.ID.String())
		assert.NoError(t, err)

		pagedIns = append(pagedIns, ins)
		pagedInvIds = append(pagedInvIds, ins.ControllerInstanceID.String())
	}

	pagedCtrlIns := []*cwsv1.Instance{}
	for i := 0; i < 34; i++ {
		ctrlIns := &cwsv1.Instance{
			Id:     &cwsv1.InstanceId{Value: pagedInvIds[i]},
			Config: &cwsv1.InstanceConfig{},
			Status: &cwsv1.InstanceStatus{
				Tenant: &cwsv1.InstanceTenantStatus{
					State: cwsv1.TenantState_READY,
				},
			},
		}

		if i == 1 {
			ctrlIns.Metadata = &cwsv1.Metadata{
				Name:        "Test Instance 1",
				Description: "Test description",
				Labels: []*cwsv1.Label{
					{
						Key:   "west1",
						Value: db.GetStrPtr("gpu1"),
					},
				},
			}
		}
		pagedCtrlIns = append(pagedCtrlIns, ctrlIns)
	}

	site3 := util.TestBuildSite(t, dbSession, ip, "test-site-3", cdbm.SiteStatusRegistered, nil, ipu)
	vpc3 := util.TestBuildVpc(t, dbSession, ip, site3, tenant, "test-vpc-3")

	machine12 := util.TestBuildMachine(t, dbSession, ip.ID, site2.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)

	allocation3 := util.TestBuildAllocation(t, dbSession, ip, tenant, site3, "test-allocation-3")
	instanceType3 := util.TestBuildInstanceType(t, dbSession, ip, site, "test-instance-type-3")
	_ = util.TestBuildAllocationContraints(t, dbSession, allocation3, cdbm.AllocationResourceTypeInstanceType, instanceType3.ID, cdbm.AllocationConstraintTypeReserved, 1, ipu)

	instance12, err := instanceDAO.Create(
		ctx, nil,
		cdbm.InstanceCreateInput{
			Name:                     "test-instance-12",
			Description:              cdb.GetStrPtr("Test description"),
			TenantID:                 tenant.ID,
			InfrastructureProviderID: ip.ID,
			SiteID:                   site3.ID,
			InstanceTypeID:           &instanceType3.ID,
			VpcID:                    vpc3.ID,
			MachineID:                &machine12.ID,
			ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
			Hostname:                 cdb.GetStrPtr("test.com"),
			OperatingSystemID:        cdb.GetUUIDPtr(operatingSystem.ID),
			IpxeScript:               cdb.GetStrPtr("ipxe"),
			AlwaysBootWithCustomIpxe: true,
			UserData:                 cdb.GetStrPtr("userdata"),
			Labels:                   map[string]string{},
			Status:                   cdbm.InstanceStatusTerminating,
			CreatedBy:                tnu.ID,
		},
	)
	assert.NoError(t, err)
	// Update creation timestamp to be earlier than inventory processing interval
	_, err = dbSession.DB.Exec("UPDATE instance SET created = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), instance12.ID.String())
	assert.NoError(t, err)

	// --- Site 4: NVLink Interface deletion strategy test scenarios ---
	site4 := util.TestBuildSite(t, dbSession, ip, "test-site-4", cdbm.SiteStatusRegistered, nil, ipu)
	vpc4 := util.TestBuildVpc(t, dbSession, ip, site4, tenant, "test-vpc-4")
	subnet4 := util.TestBuildSubnet(t, dbSession, tenant, vpc4, "testSubnet-4", cdbm.SubnetStatusPending, cdb.GetUUIDPtr(uuid.New()))

	nvllPartition4 := util.TestBuildNVLinkLogicalPartition(t, dbSession, "test-nvlinklpartition-4", nil, site4, tenant, cdbm.NVLinkLogicalPartitionStatusReady, false)

	gpuGuidDel1 := "gpu-guid-nvlink-del-1"
	gpuGuidDel2 := "gpu-guid-nvlink-del-2"
	gpuGuidDel3 := "gpu-guid-nvlink-del-3"
	gpuGuidDel4 := "gpu-guid-nvlink-del-4"
	gpuGuidDel5 := "gpu-guid-nvlink-del-5"

	// Instance A: Deleting NVLink Interface whose GPU GUID/Partition combo is NOT reported in controller status (should be deleted)
	machineNvlA := util.TestBuildMachine(t, dbSession, ip.ID, site4.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	nvlinkDelInstA, err := instanceDAO.Create(ctx, nil, cdbm.InstanceCreateInput{
		Name: "test-instance-nvlink-A", TenantID: tenant.ID, InfrastructureProviderID: ip.ID, SiteID: site4.ID,
		InstanceTypeID: &instanceType.ID, VpcID: vpc4.ID, MachineID: &machineNvlA.ID, ControllerInstanceID: cdb.GetUUIDPtr(uuid.New()),
		Hostname: cdb.GetStrPtr("test.com"), OperatingSystemID: cdb.GetUUIDPtr(operatingSystem.ID),
		Labels: map[string]string{}, Status: cdbm.InstanceStatusProvisioning, CreatedBy: tnu.ID,
	})
	assert.Nil(t, err)
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlinkDelInstA.ID.String())
	assert.NoError(t, err)
	_ = util.TestBuildInterface(t, dbSession, &nvlinkDelInstA.ID, &subnet4.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)

	nvlifcDelA1 := util.TestBuildNVLinkInterface(t, dbSession, nvlinkDelInstA.ID, site4.ID, nvllPartition4.ID, cdb.GetStrPtr(""), 0, cdb.GetStrPtr(gpuGuidDel1), nil, cdbm.NVLinkInterfaceStatusDeleting)
	_, err = dbSession.DB.Exec("UPDATE nvlink_interface SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlifcDelA1.ID.String())
	assert.NoError(t, err)

	nvlifcDelA2 := util.TestBuildNVLinkInterface(t, dbSession, nvlinkDelInstA.ID, site4.ID, nvllPartition4.ID, cdb.GetStrPtr(""), 1, cdb.GetStrPtr(gpuGuidDel2), nil, cdbm.NVLinkInterfaceStatusPending)
	assert.NotNil(t, nvlifcDelA2)

	// Instance B: Deleting NVLink Interface combo IS reported AND a Pending duplicate exists (should be deleted)
	machineNvlB := util.TestBuildMachine(t, dbSession, ip.ID, site4.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	nvlinkDelInstB, err := instanceDAO.Create(ctx, nil, cdbm.InstanceCreateInput{
		Name: "test-instance-nvlink-B", TenantID: tenant.ID, InfrastructureProviderID: ip.ID, SiteID: site4.ID,
		InstanceTypeID: &instanceType.ID, VpcID: vpc4.ID, MachineID: &machineNvlB.ID, ControllerInstanceID: cdb.GetUUIDPtr(uuid.New()),
		Hostname: cdb.GetStrPtr("test.com"), OperatingSystemID: cdb.GetUUIDPtr(operatingSystem.ID),
		Labels: map[string]string{}, Status: cdbm.InstanceStatusProvisioning, CreatedBy: tnu.ID,
	})
	assert.Nil(t, err)
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlinkDelInstB.ID.String())
	assert.NoError(t, err)
	_ = util.TestBuildInterface(t, dbSession, &nvlinkDelInstB.ID, &subnet4.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)

	nvlifcDelB1 := util.TestBuildNVLinkInterface(t, dbSession, nvlinkDelInstB.ID, site4.ID, nvllPartition4.ID, cdb.GetStrPtr(""), 0, cdb.GetStrPtr(gpuGuidDel3), nil, cdbm.NVLinkInterfaceStatusDeleting)
	_, err = dbSession.DB.Exec("UPDATE nvlink_interface SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlifcDelB1.ID.String())
	assert.NoError(t, err)

	nvlifcDelB2 := util.TestBuildNVLinkInterface(t, dbSession, nvlinkDelInstB.ID, site4.ID, nvllPartition4.ID, cdb.GetStrPtr(""), 1, cdb.GetStrPtr(gpuGuidDel3), nil, cdbm.NVLinkInterfaceStatusPending)
	assert.NotNil(t, nvlifcDelB2)

	// Instance C: Last deleting NVLink Interface, Site won't report GPUConfig or Status, should be deleted
	machineNvlC := util.TestBuildMachine(t, dbSession, ip.ID, site4.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	nvlinkDelInstC, err := instanceDAO.Create(ctx, nil, cdbm.InstanceCreateInput{
		Name: "test-instance-nvlink-C", TenantID: tenant.ID, InfrastructureProviderID: ip.ID, SiteID: site4.ID,
		InstanceTypeID: &instanceType.ID, VpcID: vpc4.ID, MachineID: &machineNvlC.ID, ControllerInstanceID: cdb.GetUUIDPtr(uuid.New()),
		Hostname: cdb.GetStrPtr("test.com"), OperatingSystemID: cdb.GetUUIDPtr(operatingSystem.ID),
		Labels: map[string]string{}, Status: cdbm.InstanceStatusProvisioning, CreatedBy: tnu.ID,
	})
	assert.Nil(t, err)
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlinkDelInstC.ID.String())
	assert.NoError(t, err)
	_ = util.TestBuildInterface(t, dbSession, &nvlinkDelInstC.ID, &subnet4.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)

	nvlifcDelC1 := util.TestBuildNVLinkInterface(t, dbSession, nvlinkDelInstC.ID, site4.ID, nvllPartition4.ID, cdb.GetStrPtr(""), 0, cdb.GetStrPtr(gpuGuidDel4), nil, cdbm.NVLinkInterfaceStatusDeleting)
	_, err = dbSession.DB.Exec("UPDATE nvlink_interface SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlifcDelC1.ID.String())
	assert.NoError(t, err)
	nvlifcDelC1.Instance = nvlinkDelInstC

	// Instance D: Deleting NVLink Interface with stale inventory (recently updated, should NOT be deleted)
	machineNvlD := util.TestBuildMachine(t, dbSession, ip.ID, site4.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	nvlinkDelInstD, err := instanceDAO.Create(ctx, nil, cdbm.InstanceCreateInput{
		Name: "test-instance-nvlink-D", TenantID: tenant.ID, InfrastructureProviderID: ip.ID, SiteID: site4.ID,
		InstanceTypeID: &instanceType.ID, VpcID: vpc4.ID, MachineID: &machineNvlD.ID, ControllerInstanceID: cdb.GetUUIDPtr(uuid.New()),
		Hostname: cdb.GetStrPtr("test.com"), OperatingSystemID: cdb.GetUUIDPtr(operatingSystem.ID),
		Labels: map[string]string{}, Status: cdbm.InstanceStatusProvisioning, CreatedBy: tnu.ID,
	})
	assert.Nil(t, err)
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlinkDelInstD.ID.String())
	assert.NoError(t, err)
	_ = util.TestBuildInterface(t, dbSession, &nvlinkDelInstD.ID, &subnet4.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)

	// NVLink Interface D1: NOT setting updated to old time - Instance stale guard should block deletion
	nvlifcDelD1 := util.TestBuildNVLinkInterface(t, dbSession, nvlinkDelInstD.ID, site4.ID, nvllPartition4.ID, cdb.GetStrPtr(""), 0, cdb.GetStrPtr(gpuGuidDel5), nil, cdbm.NVLinkInterfaceStatusDeleting)
	assert.NotNil(t, nvlifcDelD1)
	nvlifcDelD1.Instance = nvlinkDelInstD

	// Instance E: Deleting NVLink Interface when configs are NOT synced (should NOT be deleted)
	machineNvlE := util.TestBuildMachine(t, dbSession, ip.ID, site4.ID, nil, cdb.GetBoolPtr(true), cdbm.MachineStatusReady)
	nvlinkDelInstE, err := instanceDAO.Create(ctx, nil, cdbm.InstanceCreateInput{
		Name: "test-instance-nvlink-E", TenantID: tenant.ID, InfrastructureProviderID: ip.ID, SiteID: site4.ID,
		InstanceTypeID: &instanceType.ID, VpcID: vpc4.ID, MachineID: &machineNvlE.ID, ControllerInstanceID: cdb.GetUUIDPtr(uuid.New()),
		Hostname: cdb.GetStrPtr("test.com"), OperatingSystemID: cdb.GetUUIDPtr(operatingSystem.ID),
		Labels: map[string]string{}, Status: cdbm.InstanceStatusProvisioning, CreatedBy: tnu.ID,
	})
	assert.Nil(t, err)
	_, err = dbSession.DB.Exec("UPDATE instance SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlinkDelInstE.ID.String())
	assert.NoError(t, err)
	_ = util.TestBuildInterface(t, dbSession, &nvlinkDelInstE.ID, &subnet4.ID, nil, true, nil, nil, nil, &tnu.ID, cdbm.InterfaceStatusPending)

	nvlifcDelE1 := util.TestBuildNVLinkInterface(t, dbSession, nvlinkDelInstE.ID, site4.ID, nvllPartition4.ID, cdb.GetStrPtr(""), 0, cdb.GetStrPtr(gpuGuidDel1), nil, cdbm.NVLinkInterfaceStatusDeleting)
	_, err = dbSession.DB.Exec("UPDATE nvlink_interface SET updated = ? WHERE id = ?", time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval)*2), nvlifcDelE1.ID.String())
	assert.NoError(t, err)
	nvlifcDelE1.Instance = nvlinkDelInstE

	nvlinkDelMacAddress := "2F-FC-34-AE-9C-2B"
	nvlinkDelInventory := &cwsv1.InstanceInventory{
		Instances: []*cwsv1.Instance{
			{
				Id: &cwsv1.InstanceId{Value: nvlinkDelInstA.ID.String()},
				Config: &cwsv1.InstanceConfig{
					Network: &cwsv1.InstanceNetworkConfig{
						Interfaces: []*cwsv1.InstanceInterfaceConfig{
							{FunctionType: cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION, NetworkSegmentId: &cwsv1.NetworkSegmentId{Value: subnet4.ControllerNetworkSegmentID.String()}},
						},
					},
					Nvlink: &cwsv1.InstanceNVLinkConfig{
						GpuConfigs: []*cwsv1.InstanceNVLinkGpuConfig{
							{DeviceInstance: 1, LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition4.ID.String()}},
						},
					},
				},
				Status: &cwsv1.InstanceStatus{
					Tenant:  &cwsv1.InstanceTenantStatus{State: cwsv1.TenantState_READY},
					Network: &cwsv1.InstanceNetworkStatus{Interfaces: []*cwsv1.InstanceInterfaceStatus{{MacAddress: &nvlinkDelMacAddress}}, ConfigsSynced: cwsv1.SyncState_SYNCED},
					Nvlink: &cwsv1.InstanceNVLinkStatus{
						GpuStatuses: []*cwsv1.InstanceNVLinkGpuStatus{
							{GpuGuid: cdb.GetStrPtr(gpuGuidDel2), LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition4.ID.String()}},
						},
						ConfigsSynced: cwsv1.SyncState_SYNCED,
					},
				},
			},
			{
				Id: &cwsv1.InstanceId{Value: nvlinkDelInstB.ID.String()},
				Config: &cwsv1.InstanceConfig{
					Network: &cwsv1.InstanceNetworkConfig{
						Interfaces: []*cwsv1.InstanceInterfaceConfig{
							{FunctionType: cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION, NetworkSegmentId: &cwsv1.NetworkSegmentId{Value: subnet4.ControllerNetworkSegmentID.String()}},
						},
					},
					Nvlink: &cwsv1.InstanceNVLinkConfig{
						GpuConfigs: []*cwsv1.InstanceNVLinkGpuConfig{
							{DeviceInstance: 1, LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition4.ID.String()}},
						},
					},
				},
				Status: &cwsv1.InstanceStatus{
					Tenant:  &cwsv1.InstanceTenantStatus{State: cwsv1.TenantState_READY},
					Network: &cwsv1.InstanceNetworkStatus{Interfaces: []*cwsv1.InstanceInterfaceStatus{{MacAddress: &nvlinkDelMacAddress}}, ConfigsSynced: cwsv1.SyncState_SYNCED},
					Nvlink: &cwsv1.InstanceNVLinkStatus{
						GpuStatuses: []*cwsv1.InstanceNVLinkGpuStatus{
							{GpuGuid: cdb.GetStrPtr(gpuGuidDel3), LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition4.ID.String()}},
						},
						ConfigsSynced: cwsv1.SyncState_SYNCED,
					},
				},
			},
			{
				Id: &cwsv1.InstanceId{Value: nvlinkDelInstC.ID.String()},
				Config: &cwsv1.InstanceConfig{
					Network: &cwsv1.InstanceNetworkConfig{
						Interfaces: []*cwsv1.InstanceInterfaceConfig{
							{FunctionType: cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION, NetworkSegmentId: &cwsv1.NetworkSegmentId{Value: subnet4.ControllerNetworkSegmentID.String()}},
						},
					},
					Nvlink: &cwsv1.InstanceNVLinkConfig{},
				},
				Status: &cwsv1.InstanceStatus{
					Tenant:  &cwsv1.InstanceTenantStatus{State: cwsv1.TenantState_READY},
					Network: &cwsv1.InstanceNetworkStatus{Interfaces: []*cwsv1.InstanceInterfaceStatus{{MacAddress: &nvlinkDelMacAddress}}, ConfigsSynced: cwsv1.SyncState_SYNCED},
					Nvlink:  &cwsv1.InstanceNVLinkStatus{},
				},
			},
			{
				Id: &cwsv1.InstanceId{Value: nvlinkDelInstD.ID.String()},
				Config: &cwsv1.InstanceConfig{
					Network: &cwsv1.InstanceNetworkConfig{
						Interfaces: []*cwsv1.InstanceInterfaceConfig{
							{FunctionType: cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION, NetworkSegmentId: &cwsv1.NetworkSegmentId{Value: subnet4.ControllerNetworkSegmentID.String()}},
						},
					},
					Nvlink: &cwsv1.InstanceNVLinkConfig{
						GpuConfigs: []*cwsv1.InstanceNVLinkGpuConfig{
							{DeviceInstance: 0, LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition4.ID.String()}},
						},
					},
				},
				Status: &cwsv1.InstanceStatus{
					Tenant:  &cwsv1.InstanceTenantStatus{State: cwsv1.TenantState_READY},
					Network: &cwsv1.InstanceNetworkStatus{Interfaces: []*cwsv1.InstanceInterfaceStatus{{MacAddress: &nvlinkDelMacAddress}}, ConfigsSynced: cwsv1.SyncState_SYNCED},
					Nvlink: &cwsv1.InstanceNVLinkStatus{
						GpuStatuses:   []*cwsv1.InstanceNVLinkGpuStatus{},
						ConfigsSynced: cwsv1.SyncState_SYNCED,
					},
				},
			},
			{
				Id: &cwsv1.InstanceId{Value: nvlinkDelInstE.ID.String()},
				Config: &cwsv1.InstanceConfig{
					Network: &cwsv1.InstanceNetworkConfig{
						Interfaces: []*cwsv1.InstanceInterfaceConfig{
							{FunctionType: cwsv1.InterfaceFunctionType_PHYSICAL_FUNCTION, NetworkSegmentId: &cwsv1.NetworkSegmentId{Value: subnet4.ControllerNetworkSegmentID.String()}},
						},
					},
					Nvlink: &cwsv1.InstanceNVLinkConfig{
						GpuConfigs: []*cwsv1.InstanceNVLinkGpuConfig{
							{DeviceInstance: 0, LogicalPartitionId: &cwsv1.NVLinkLogicalPartitionId{Value: nvllPartition4.ID.String()}},
						},
					},
				},
				Status: &cwsv1.InstanceStatus{
					Tenant:  &cwsv1.InstanceTenantStatus{State: cwsv1.TenantState_READY},
					Network: &cwsv1.InstanceNetworkStatus{Interfaces: []*cwsv1.InstanceInterfaceStatus{{MacAddress: &nvlinkDelMacAddress}}, ConfigsSynced: cwsv1.SyncState_SYNCED},
					Nvlink: &cwsv1.InstanceNVLinkStatus{
						GpuStatuses:   []*cwsv1.InstanceNVLinkGpuStatus{},
						ConfigsSynced: cwsv1.SyncState_PENDING,
					},
				},
			},
		},
	}

	tSiteClientPool := testTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	ifcDAO := cdbm.NewInterfaceDAO(dbSession)
	ibifcDAO := cdbm.NewInfiniBandInterfaceDAO(dbSession)
	nvifcDAO := cdbm.NewNVLinkInterfaceDAO(dbSession)
	mDAO := cdbm.NewMachineDAO(dbSession)
	skgiaDAO := cdbm.NewSSHKeyGroupInstanceAssociationDAO(dbSession)

	// Mock UpdateInstance workflow from site-agent
	wrun := &tmocks.WorkflowRun{}
	wid := "test-workflow-id"
	wrun.On("GetID").Return(wid)

	workflowOptions1 := client.StartWorkflowOptions{
		ID:        "site-instance-update-metadata-" + instance1.ID.String(),
		TaskQueue: queue.SiteTaskQueue,
	}

	workflowOptions2 := client.StartWorkflowOptions{
		ID:        "site-instance-update-metadata-" + pagedIns[1].ID.String(),
		TaskQueue: queue.SiteTaskQueue,
	}

	mtc1 := &tmocks.Client{}
	mtc1.Mock.On("ExecuteWorkflow", context.Background(), workflowOptions1, "UpdateInstance",
		mock.Anything).Return(wrun, nil)

	mtc3 := &tmocks.Client{}
	mtc3.Mock.On("ExecuteWorkflow", context.Background(), workflowOptions2, "UpdateInstance",
		mock.Anything).Return(wrun, nil)

	mtc4 := &tmocks.Client{}

	assert.NotNil(t, tSiteClientPool)

	wtc := &tmocks.Client{}

	cfg := config.GetTestConfig()

	tests := []struct {
		name                                  string
		siteID                                uuid.UUID
		clientPoolSiteID                      string
		clientPoolClient                      *tmocks.Client
		instanceInventory                     *cwsv1.InstanceInventory
		updatedInstance                       *cdbm.Instance
		updatedVpcPrefixInstance              *cdbm.Instance
		updatedMultiDPUInstance               *cdbm.Instance
		nsgPropagationDetailsClearedInstances []*cdbm.Instance
		readyInstances                        []*cdbm.Instance
		deletingInstance                      *cdbm.Instance
		deletedInstances                      []*cdbm.Instance
		missingInstances                      []*cdbm.Instance
		restoredInstance                      *cdbm.Instance
		unpairedInstances                     []*cdbm.Instance
		bootCompletedInstances                []*cdbm.Instance
		unchangedInstances                    []*cdbm.Instance
		deletingInterfaces                    []*cdbm.Interface
		readyInterfaces                       []*cdbm.Interface
		clearedRequestedIpInterfaces          []*cdbm.Interface
		clearedInlineRoutingProfileInterfaces []*cdbm.Interface
		vpcPrefixInterfaces                   []*cdbm.Interface
		multiDPUInterfaces                    []*cdbm.Interface
		deletedInfiniBandInterfaces           []*cdbm.InfiniBandInterface
		readyInfiniBandInterfaces             []*cdbm.InfiniBandInterface
		updatedDpuExtServiceDeployments       []*cdbm.DpuExtensionServiceDeployment
		deletedDpuExtServiceDeployments       []*cdbm.DpuExtensionServiceDeployment
		readyNVLinkInterfaces                 []*cdbm.NVLinkInterface
		deletedNVLinkInterfaces               []*cdbm.NVLinkInterface
		deletingNVLinkInterfaces              []*cdbm.NVLinkInterface
		requiredMetadataUpdate                bool
		metadataInstanceUpdate                *cdbm.Instance
		tpmCertificateUpdatedInstance         *cdbm.Instance
		expectErr                             bool
	}{
		{
			name:              "test Instance inventory processing error, non-existent site",
			siteID:            uuid.New(),
			instanceInventory: instanceInventory,
			expectErr:         true,
		},
		{
			name:                                  "test Instance inventory processing success including VPC prefix interfaces",
			siteID:                                site.ID,
			clientPoolSiteID:                      site.ID.String(),
			clientPoolClient:                      mtc1,
			instanceInventory:                     instanceInventory,
			updatedVpcPrefixInstance:              instance11,
			updatedInstance:                       instance1,
			deletingInstance:                      instance5,
			updatedMultiDPUInstance:               instance11,
			deletedInstances:                      []*cdbm.Instance{instance2, instance8},
			missingInstances:                      []*cdbm.Instance{instance3, instance4, instance10},
			restoredInstance:                      instance6,
			unpairedInstances:                     []*cdbm.Instance{instance7},
			bootCompletedInstances:                []*cdbm.Instance{instance9},
			unchangedInstances:                    []*cdbm.Instance{instance13, instance14},
			deletingInterfaces:                    []*cdbm.Interface{ifcvpc_deleting},
			readyInterfaces:                       []*cdbm.Interface{ifcvpc_pending},
			clearedRequestedIpInterfaces:          []*cdbm.Interface{ifcvpc_pending},
			clearedInlineRoutingProfileInterfaces: []*cdbm.Interface{ifcvpc_pending},
			deletedInfiniBandInterfaces:           []*cdbm.InfiniBandInterface{ibInterface3, ibInterface18_1, ibInterface18_2, ibInterface18_3},
			readyInfiniBandInterfaces:             []*cdbm.InfiniBandInterface{ibInterface1, ibInterface2},
			multiDPUInterfaces:                    []*cdbm.Interface{ifcvpc0, ifcvpc1, ifcvpc0_1, ifcvpc1_1},
			vpcPrefixInterfaces:                   []*cdbm.Interface{ifcvpc0, ifcvpc1, ifcvpc0_1, ifcvpc1_1},
			updatedDpuExtServiceDeployments:       []*cdbm.DpuExtensionServiceDeployment{dpuExtServiceDeployment1},
			deletedDpuExtServiceDeployments:       []*cdbm.DpuExtensionServiceDeployment{dpuExtServiceDeployment2},
			readyNVLinkInterfaces:                 []*cdbm.NVLinkInterface{nvlinkInterface1, nvlinkInterface2},
			deletedNVLinkInterfaces:               []*cdbm.NVLinkInterface{nvlinkInterface3},
			tpmCertificateUpdatedInstance:         instance16,
			expectErr:                             false,
		},
		{
			name:             "test Instance inventory processing success with nil TPM certificate update",
			siteID:           site.ID,
			clientPoolSiteID: site.ID.String(),
			clientPoolClient: mtc1,
			instanceInventory: &cwsv1.InstanceInventory{
				Instances: []*cwsv1.Instance{
					{
						Id:               &cwsv1.InstanceId{Value: instance17.ControllerInstanceID.String()},
						Config:           &cwsv1.InstanceConfig{},
						TpmEkCertificate: &tpmEKCertBase64,
						Status: &cwsv1.InstanceStatus{
							Tenant: &cwsv1.InstanceTenantStatus{
								State: cwsv1.TenantState_READY,
							},
						},
					},
				},
			},
			tpmCertificateUpdatedInstance: instance17,
			expectErr:                     false,
		},
		{
			name:             "test paged Instance inventory processing, empty inventory",
			siteID:           site3.ID,
			clientPoolSiteID: site3.ID.String(),
			clientPoolClient: mtc3,
			instanceInventory: &cwsv1.InstanceInventory{
				Instances:       []*cwsv1.Instance{},
				Timestamp:       timestamppb.Now(),
				InventoryStatus: cwsv1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
				InventoryPage: &cwsv1.InventoryPage{
					CurrentPage: 1,
					PageSize:    25,
				},
			},
			deletedInstances: []*cdbm.Instance{instance12},
		},
		{
			name:             "test paged Instance inventory processing, first page",
			siteID:           site2.ID,
			clientPoolSiteID: site2.ID.String(),
			clientPoolClient: mtc3,
			instanceInventory: &cwsv1.InstanceInventory{
				Instances: pagedCtrlIns[0:10],
				Timestamp: timestamppb.Now(),
				InventoryPage: &cwsv1.InventoryPage{
					CurrentPage: 1,
					TotalPages:  4,
					PageSize:    10,
					TotalItems:  34,
					ItemIds:     pagedInvIds[0:34],
				},
			},
			readyInstances: pagedIns[0:34],
		},
		{
			name:             "test paged Instance inventory processing, last page",
			siteID:           site2.ID,
			clientPoolSiteID: site2.ID.String(),
			clientPoolClient: mtc3,
			instanceInventory: &cwsv1.InstanceInventory{
				Instances: pagedCtrlIns[30:34],
				Timestamp: timestamppb.Now(),
				InventoryPage: &cwsv1.InventoryPage{
					CurrentPage: 4,
					TotalPages:  4,
					PageSize:    10,
					TotalItems:  34,
					ItemIds:     pagedInvIds[0:34],
				},
			},
			readyInstances:   pagedIns[0:34],
			missingInstances: pagedIns[34:38],
		},
		{
			name:             "test paged Instance inventory processing success with initiation of Instance metadata update workflow, label value mismatched",
			siteID:           site2.ID,
			clientPoolSiteID: site2.ID.String(),
			clientPoolClient: mtc3,
			instanceInventory: &cwsv1.InstanceInventory{
				Instances: pagedCtrlIns[0:10],
				Timestamp: timestamppb.Now(),
				InventoryPage: &cwsv1.InventoryPage{
					CurrentPage: 1,
					TotalPages:  4,
					PageSize:    10,
					TotalItems:  34,
					ItemIds:     pagedInvIds[0:34],
				},
			},
			readyInstances:         pagedIns[0:34],
			requiredMetadataUpdate: true,
			metadataInstanceUpdate: pagedIns[1],
		},
		{
			name:                     "test NVLink Interface deletion strategy with synced/unsynced configs and stale inventory",
			siteID:                   site4.ID,
			clientPoolSiteID:         site4.ID.String(),
			clientPoolClient:         mtc4,
			instanceInventory:        nvlinkDelInventory,
			deletedNVLinkInterfaces:  []*cdbm.NVLinkInterface{nvlifcDelA1, nvlifcDelB1, nvlifcDelC1},
			readyNVLinkInterfaces:    []*cdbm.NVLinkInterface{nvlifcDelA2, nvlifcDelB2},
			deletingNVLinkInterfaces: []*cdbm.NVLinkInterface{nvlifcDelD1, nvlifcDelE1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			ms := NewManageInstance(dbSession, tSiteClientPool, wtc, cfg)
			ms.siteClientPool.IDClientMap[tc.clientPoolSiteID] = tc.clientPoolClient

			_, err := ms.UpdateInstancesInDB(ctx, tc.siteID, tc.instanceInventory)
			assert.Equal(t, tc.expectErr, err != nil)

			if tc.expectErr {
				return
			}

			for _, inst := range tc.nsgPropagationDetailsClearedInstances {
				// If the VPC should not have propagation details according to the site
				// make sure the DB agrees.
				updatedInstance, _ := instanceDAO.GetByID(ctx, nil, inst.ID, nil)
				assert.Nil(t, updatedInstance.NetworkSecurityGroupPropagationDetails)
			}

			if tc.updatedInstance != nil {
				// Check that Instance status, Instance Subnet status and attributes were updated in DB for Instance 1
				updatedInstance, err := instanceDAO.GetByID(ctx, nil, tc.updatedInstance.ID, nil)
				assert.Nil(t, err)
				assert.Equal(t, cdbm.InstanceStatusReady, updatedInstance.Status)

				// Instance Interfaces
				_, totalIfcs, err := ifcDAO.GetAll(ctx, nil, cdbm.InterfaceFilterInput{InstanceIDs: []uuid.UUID{updatedInstance.ID}}, paginator.PageInput{}, nil)
				assert.Nil(t, err)
				assert.Equal(t, 3, totalIfcs)

				ifc1, err := ifcDAO.GetByID(ctx, nil, interface1.ID, nil)
				assert.Nil(t, err)
				if ifc1.SubnetID != nil {
					assert.Equal(t, subnet1.ID, *ifc1.SubnetID)
				}
				assert.True(t, ifc1.IsPhysical)
				assert.Equal(t, macAddress, *ifc1.MacAddress)
				assert.Equal(t, ipAddresses, ifc1.IPAddresses)
				assert.Equal(t, cdbm.InterfaceStatusReady, ifc1.Status)

				ifc2, err := ifcDAO.GetByID(ctx, nil, interface2.ID, nil)
				assert.Nil(t, err)
				if ifc2.SubnetID != nil {
					assert.Equal(t, subnet2.ID, *ifc2.SubnetID)
				}
				assert.False(t, ifc2.IsPhysical)
				assert.Equal(t, int(vfID), *ifc2.VirtualFunctionID)
				assert.Equal(t, macAddress, *ifc2.MacAddress)
				assert.Equal(t, ipAddresses, ifc2.IPAddresses)
				assert.Equal(t, cdbm.InterfaceStatusReady, ifc2.Status)

				ifc3, err := ifcDAO.GetByID(ctx, nil, interface3.ID, nil)
				assert.Nil(t, err)
				assert.Equal(t, cdbm.InterfaceStatusError, ifc3.Status)

				// Instance IB Interfaces
				_, totalIbIfcs, err := ibifcDAO.GetAll(
					ctx,
					nil,
					cdbm.InfiniBandInterfaceFilterInput{
						InstanceIDs: []uuid.UUID{updatedInstance.ID},
					},
					paginator.PageInput{},
					nil,
				)
				assert.Nil(t, err)
				assert.Equal(t, 2, totalIbIfcs)

				ibIfc1, err := ibifcDAO.GetByID(ctx, nil, ibInterface1.ID, nil)
				assert.Nil(t, err)

				assert.Equal(t, partition1.ID, ibIfc1.InfiniBandPartitionID)
				assert.Equal(t, cdbm.InfiniBandInterfaceStatusReady, ibIfc1.Status)
				assert.True(t, ibIfc1.IsPhysical)
				assert.Equal(t, tc.instanceInventory.Instances[0].Status.Infiniband.IbInterfaces[0].PfGuid, ibIfc1.PhysicalGUID)
				assert.Equal(t, tc.instanceInventory.Instances[0].Status.Infiniband.IbInterfaces[0].Guid, ibIfc1.GUID)

				ibIfc2, err := ibifcDAO.GetByID(ctx, nil, ibInterface2.ID, nil)
				assert.Nil(t, err)

				assert.Equal(t, partition1.ID, ibIfc2.InfiniBandPartitionID)
				assert.Equal(t, cdbm.InfiniBandInterfaceStatusReady, ibIfc2.Status)
				assert.True(t, ibIfc2.IsPhysical)
				assert.Equal(t, tc.instanceInventory.Instances[0].Status.Infiniband.IbInterfaces[1].PfGuid, ibIfc2.PhysicalGUID)
				assert.Equal(t, tc.instanceInventory.Instances[0].Status.Infiniband.IbInterfaces[1].Guid, ibIfc2.GUID)

				if len(tc.instanceInventory.Instances) > 0 && tc.instanceInventory.Instances[0].Status.Update != nil {
					assert.Equal(t, !tc.instanceInventory.Instances[0].Status.Update.UserApprovalReceived, updatedInstance.IsUpdatePending)
				}

				// Instance NVLink Interfaces
				_, totalNvIfcs, err := nvifcDAO.GetAll(ctx, nil, cdbm.NVLinkInterfaceFilterInput{InstanceIDs: []uuid.UUID{updatedInstance.ID}}, paginator.PageInput{}, nil)
				assert.Nil(t, err)
				assert.Equal(t, 3, totalNvIfcs)

				nvIfc1, err := nvifcDAO.GetByID(ctx, nil, nvlinkInterface1.ID, nil)
				assert.Nil(t, err)
				assert.Equal(t, nvllPartition1.ID, nvIfc1.NVLinkLogicalPartitionID)
				assert.Equal(t, cdbm.NVLinkInterfaceStatusReady, nvIfc1.Status)

				nvIfc2, err := nvifcDAO.GetByID(ctx, nil, nvlinkInterface2.ID, nil)
				assert.Nil(t, err)
				assert.Equal(t, nvllPartition1.ID, nvIfc2.NVLinkLogicalPartitionID)
				assert.Equal(t, cdbm.NVLinkInterfaceStatusReady, nvIfc2.Status)
			}

			if tc.updatedVpcPrefixInstance != nil {
				// Check that Instance status, Instance VpcPrefix status and attributes were updated in DB for Instance 1
				updatedVpInstance, err := instanceDAO.GetByID(ctx, nil, tc.updatedVpcPrefixInstance.ID, nil)
				assert.Nil(t, err)
				assert.Equal(t, cdbm.InstanceStatusReady, updatedVpInstance.Status)

				_, totalIfcs, err := ifcDAO.GetAll(ctx, nil, cdbm.InterfaceFilterInput{InstanceIDs: []uuid.UUID{updatedVpInstance.ID}}, paginator.PageInput{}, nil)
				assert.Nil(t, err)
				assert.Equal(t, len(tc.vpcPrefixInterfaces), totalIfcs)

				ifcvpc, err := ifcDAO.GetByID(ctx, nil, tc.vpcPrefixInterfaces[0].ID, nil)
				assert.Nil(t, err)
				if ifcvpc.VpcPrefixID != nil {
					assert.Equal(t, vpcPrefix1.ID, *ifcvpc.VpcPrefixID)
				}
				assert.True(t, ifcvpc.IsPhysical)
				require.NotNil(t, ifcvpc.RequestedIpAddress)
				assert.Equal(t, requestedIpAddress, *ifcvpc.RequestedIpAddress)
				require.NotNil(t, ifcvpc.InlineRoutingProfile)
				assert.Equal(t, routingProfilePrefixes, ifcvpc.InlineRoutingProfile.AllowedAnycastPrefixes)
				assert.Equal(t, macAddress, *ifcvpc.MacAddress)
				assert.Equal(t, ipAddresses, ifcvpc.IPAddresses)
				assert.Equal(t, cdbm.InterfaceStatusReady, ifcvpc.Status)
			}

			if tc.updatedMultiDPUInstance != nil {
				// Check that Instance status, Instance VpcPrefix status and attributes were updated in DB for Instance 1
				updatedMultiDPUInstance, err := instanceDAO.GetByID(ctx, nil, tc.updatedMultiDPUInstance.ID, nil)
				assert.Nil(t, err)
				assert.Equal(t, cdbm.InstanceStatusReady, updatedMultiDPUInstance.Status)

				_, totalIfcs, err := ifcDAO.GetAll(ctx, nil, cdbm.InterfaceFilterInput{InstanceIDs: []uuid.UUID{updatedMultiDPUInstance.ID}}, paginator.PageInput{}, nil)
				assert.Nil(t, err)
				assert.Equal(t, len(tc.multiDPUInterfaces), totalIfcs)

				for _, ifc := range tc.multiDPUInterfaces {
					uifc, err := ifcDAO.GetByID(ctx, nil, ifc.ID, nil)
					assert.Nil(t, err)
					assert.Equal(t, cdbm.InterfaceStatusReady, uifc.Status)
					if uifc.Device != nil {
						assert.Equal(t, *uifc.Device, *ifc.Device)

						if ifc.DeviceInstance != nil {
							assert.Equal(t, *uifc.DeviceInstance, *ifc.DeviceInstance)
						} else {
							assert.Equal(t, *uifc.DeviceInstance, 0)
						}
					}
					if ifc.VirtualFunctionID != nil {
						assert.Equal(t, *uifc.VirtualFunctionID, *ifc.VirtualFunctionID)
					}
					assert.Equal(t, uifc.IsPhysical, ifc.IsPhysical)
					assert.Equal(t, *uifc.VpcPrefixID, *ifc.VpcPrefixID)
				}
			}

			for _, instPropStatus := range tc.instanceInventory.NetworkSecurityGroupPropagations {
				updatedInstance, _ := instanceDAO.GetByID(ctx, nil, uuid.MustParse(instPropStatus.Id), nil)

				// Prop details should not be nil
				assert.NotNil(t, updatedInstance.NetworkSecurityGroupPropagationDetails)

				// The details should match
				assert.Equal(
					t,
					updatedInstance.NetworkSecurityGroupPropagationDetails.NetworkSecurityGroupPropagationObjectStatus,
					instPropStatus,
					"\n%+v \n != \n %+v\n",
					updatedInstance.NetworkSecurityGroupPropagationDetails.NetworkSecurityGroupPropagationObjectStatus,
					instPropStatus,
				)
			}

			if tc.deletingInstance != nil {
				// Check that Instance 5, which was in Terminating state, DID get its state changed to Ready if Site inventory reports it as Ready
				ui, serr := instanceDAO.GetByID(ctx, nil, tc.deletingInstance.ID, nil)
				assert.NoError(t, serr)
				assert.Equal(t, cdbm.InstanceStatusReady, ui.Status)
			}

			for _, instance := range tc.readyInstances {
				ui, serr := instanceDAO.GetByID(ctx, nil, instance.ID, nil)
				assert.NoError(t, serr)
				assert.Equal(t, cdbm.InstanceStatusReady, ui.Status)
			}

			for _, instance := range tc.deletedInstances {
				// Check that Instance was deleted as it was in Terminating state and missing from Inventory
				_, err = instanceDAO.GetByID(ctx, nil, instance.ID, nil)
				require.Equal(t, cdb.ErrDoesNotExist, err, fmt.Sprintf("Instance %s was not deleted", instance.Name))
				// Check Instance Subnets were deleted for Instance 2
				_, ifcCnt, err := ifcDAO.GetAll(ctx, nil, cdbm.InterfaceFilterInput{InstanceIDs: []uuid.UUID{instance.ID}}, paginator.PageInput{}, nil)
				assert.Nil(t, err)
				assert.Equal(t, 0, ifcCnt)

				// Check that the machine isAssigned is set to false for Machine 2
				uMachine, err := mDAO.GetByID(ctx, nil, *instance.MachineID, nil, false)
				assert.Nil(t, err)
				assert.Equal(t, false, uMachine.IsAssigned)

				// Check that SSH Key Group Instance associations were deleted
				_, skgiaCnt, err := skgiaDAO.GetAll(ctx, nil, nil, nil, []uuid.UUID{instance.ID}, nil, nil, nil, nil)
				assert.Nil(t, err)
				assert.Equal(t, 0, skgiaCnt)
			}

			for _, instance := range tc.missingInstances {
				// Check that Instance has missing flag set
				ui, serr := instanceDAO.GetByID(ctx, nil, instance.ID, nil)
				assert.Nil(t, serr)

				if ui.ControllerInstanceID != nil {
					assert.True(t, ui.IsMissingOnSite)
					assert.Equal(t, cdbm.InstanceStatusError, ui.Status)

					sds, _, err := sdDAO.GetAllByEntityID(ctx, nil, instance.ID.String(), nil, nil, nil)
					assert.Nil(t, err)
					assert.Equal(t, 1, len(sds), instance.Name)
				} else {
					assert.False(t, ui.IsMissingOnSite)
				}
			}

			if tc.restoredInstance != nil {
				// Check that Instance status is set to Ready
				ui, err := instanceDAO.GetByID(ctx, nil, tc.restoredInstance.ID, nil)
				assert.Nil(t, err)
				assert.False(t, ui.IsMissingOnSite)
				assert.Equal(t, cdbm.InstanceStatusReady, ui.Status)
			}

			for _, instance := range tc.unpairedInstances {
				// Check that Instance has controller ID set
				ui, serr := instanceDAO.GetByID(ctx, nil, instance.ID, nil)
				assert.Nil(t, serr)
				assert.NotNil(t, ui.ControllerInstanceID)
			}

			for _, instance := range tc.bootCompletedInstances {
				// Check that Instance power status is set to BootCompleted
				ui, serr := instanceDAO.GetByID(ctx, nil, instance.ID, nil)
				assert.Nil(t, serr)
				assert.Equal(t, cdbm.InstancePowerStatusBootCompleted, *ui.PowerStatus)
			}

			for _, instance := range tc.unchangedInstances {
				// Check that no new status detail has been created for Instance
				sds, _, err := sdDAO.GetAllByEntityID(ctx, nil, instance.ID.String(), nil, nil, nil)
				assert.Nil(t, err)
				assert.Equal(t, 1, len(sds))
			}

			if tc.requiredMetadataUpdate {
				assert.True(t, len(tc.clientPoolClient.Calls) > 0)
				assert.Equal(t, len(tc.clientPoolClient.Calls[0].Arguments), 4)

				scReq := tc.clientPoolClient.Calls[0].Arguments[3].(*cwsv1.InstanceConfigUpdateRequest)
				assert.Equal(t, tc.metadataInstanceUpdate.ControllerInstanceID.String(), scReq.InstanceId.Value)
			}

			if tc.tpmCertificateUpdatedInstance != nil {
				// Verify that the TPM EK certificate was updated from nil to the base64 encoded value
				updatedInstance, err := instanceDAO.GetByID(ctx, nil, tc.tpmCertificateUpdatedInstance.ID, nil)
				assert.Nil(t, err)
				assert.NotNil(t, updatedInstance.TpmEkCertificate)
				assert.Equal(t, tpmEKCertBase64, *updatedInstance.TpmEkCertificate)
			}

			// Make sure the deleting interfaces are deleted
			for _, ifc := range tc.deletingInterfaces {
				_, err := ifcDAO.GetByID(ctx, nil, ifc.ID, nil)
				assert.NotNil(t, err)
				assert.Equal(t, cdb.ErrDoesNotExist, err)
			}

			for _, ifc := range tc.readyInterfaces {
				inteface, err := ifcDAO.GetByID(ctx, nil, ifc.ID, nil)
				assert.Nil(t, err)
				assert.Equal(t, cdbm.InterfaceStatusReady, inteface.Status)
			}

			for _, ifc := range tc.clearedRequestedIpInterfaces {
				inteface, err := ifcDAO.GetByID(ctx, nil, ifc.ID, nil)
				assert.Nil(t, err)
				assert.Nil(t, inteface.RequestedIpAddress)
			}

			for _, ifc := range tc.clearedInlineRoutingProfileInterfaces {
				inteface, err := ifcDAO.GetByID(ctx, nil, ifc.ID, nil)
				assert.Nil(t, err)
				assert.Nil(t, inteface.InlineRoutingProfile)
			}

			if tc.deletedInfiniBandInterfaces != nil {
				for _, ibfc := range tc.deletedInfiniBandInterfaces {
					_, err := ibifcDAO.GetByID(ctx, nil, ibfc.ID, nil)
					assert.Equal(t, cdb.ErrDoesNotExist, err)
				}
			}

			if tc.readyInfiniBandInterfaces != nil {
				for _, ibfc := range tc.readyInfiniBandInterfaces {
					ibIfc, err := ibifcDAO.GetByID(ctx, nil, ibfc.ID, nil)
					assert.Nil(t, err)
					assert.Equal(t, cdbm.InfiniBandInterfaceStatusReady, ibIfc.Status)
				}
			}

			// Verify DPU Extension Service Deployment updates
			if tc.updatedDpuExtServiceDeployments != nil {
				desdDAO := cdbm.NewDpuExtensionServiceDeploymentDAO(dbSession)
				for _, desd := range tc.updatedDpuExtServiceDeployments {
					updatedDesd, err := desdDAO.GetByID(ctx, nil, desd.ID, nil)
					assert.Nil(t, err)
					assert.Equal(t, cdbm.DpuExtensionServiceDeploymentStatusRunning, updatedDesd.Status)
				}
			}

			// Verify DPU Extension Service Deployment deletions
			if tc.deletedDpuExtServiceDeployments != nil {
				desdDAO := cdbm.NewDpuExtensionServiceDeploymentDAO(dbSession)
				for _, desd := range tc.deletedDpuExtServiceDeployments {
					_, err := desdDAO.GetByID(ctx, nil, desd.ID, nil)
					assert.Equal(t, cdb.ErrDoesNotExist, err, fmt.Sprintf("DPU Extension Service Deployment %s should have been deleted", desd.ID.String()))
				}
			}

			if tc.readyNVLinkInterfaces != nil {
				for _, nvIfc := range tc.readyNVLinkInterfaces {
					unvIfc, err := nvifcDAO.GetByID(ctx, nil, nvIfc.ID, nil)
					assert.Nil(t, err)
					assert.Equal(t, cdbm.NVLinkInterfaceStatusReady, unvIfc.Status)
					assert.Equal(t, nvIfc.DeviceInstance, unvIfc.DeviceInstance)
				}
			}

			if tc.deletedNVLinkInterfaces != nil {
				for _, nvIfc := range tc.deletedNVLinkInterfaces {
					_, err := nvifcDAO.GetByID(ctx, nil, nvIfc.ID, nil)
					assert.Equal(t, cdb.ErrDoesNotExist, err)
				}
			}

			if tc.deletingNVLinkInterfaces != nil {
				for _, nvIfc := range tc.deletingNVLinkInterfaces {
					unvIfc, err := nvifcDAO.GetByID(ctx, nil, nvIfc.ID, []string{cdbm.InstanceRelationName})
					require.NoError(t, err, "NVLink Interface: %s for Instance: %s should still exist", nvIfc.ID.String(), nvIfc.Instance.Name)
					assert.Equal(t, cdbm.NVLinkInterfaceStatusDeleting, unvIfc.Status)
				}
			}
		})
	}
}

// Metrics tests with various statusDetails scenarios

// Test Instance Metrics - CREATE operations
func Test_InstanceMetrics_Create_PendingToReady(t *testing.T) {
	// Case 1: pending -> ready (should emit metric with duration t2-t1)
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()
	util.TestSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageInstanceLifecycleMetrics(reg, dbSession)
	testInstanceID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour) // Use past time to avoid conflicts
	t1 := baseTime
	t2 := baseTime.Add(100 * time.Millisecond)
	expectedDuration := t2.Sub(t1)

	// t1: pending
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusPending, nil, t1)

	// t2: ready
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusReady, nil, t2)

	// Process create event
	ctx := context.Background()
	err := lifecycleMetrics.RecordInstanceStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testInstanceID, Created: &t2},
	})
	assert.NoError(t, err)

	// Verify metric was emitted with correct duration
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_instance_operation_latency_seconds", 1, map[string]string{
		"operation_type": "create",
		"from_status":    cdbm.InstanceStatusPending,
		"to_status":      cdbm.InstanceStatusReady,
	}, expectedDuration)
}

func Test_InstanceMetrics_Create_PendingErrorReady(t *testing.T) {
	// Case 2: pending -> error -> ready (should emit metric with duration t3-t1)
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()
	util.TestSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageInstanceLifecycleMetrics(reg, dbSession)
	testInstanceID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime                             // pending
	t2 := baseTime.Add(50 * time.Millisecond)  // error
	t3 := baseTime.Add(100 * time.Millisecond) // ready
	expectedDuration := t3.Sub(t1)             // t3-t1

	// t1: pending
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusPending, nil, t1)

	// t2: error
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusError, nil, t2)

	// t3: ready
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusReady, nil, t3)

	// Process create event
	ctx := context.Background()
	err := lifecycleMetrics.RecordInstanceStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testInstanceID, Created: &t3},
	})
	assert.NoError(t, err)

	// Verify metric was emitted with correct duration
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_instance_operation_latency_seconds", 1, map[string]string{
		"operation_type": "create",
		"from_status":    cdbm.InstanceStatusPending,
		"to_status":      cdbm.InstanceStatusReady,
	}, expectedDuration)
}

func Test_InstanceMetrics_Create_ReadyErrorReady(t *testing.T) {
	// Case 3: pending -> ready -> error -> ready (should NOT emit metric - duplicate ready)
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()
	util.TestSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageInstanceLifecycleMetrics(reg, dbSession)
	testInstanceID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime                             // pending (initial state)
	t2 := baseTime.Add(50 * time.Millisecond)  // ready
	t3 := baseTime.Add(100 * time.Millisecond) // error
	t4 := baseTime.Add(150 * time.Millisecond) // ready (duplicate)

	// t1: pending (initial state)
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusPending, nil, t1)

	// t2: ready
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusReady, nil, t2)

	// t3: error
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusError, nil, t3)

	// t4: ready (duplicate)
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusReady, nil, t4)

	// Process create event
	ctx := context.Background()
	err := lifecycleMetrics.RecordInstanceStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testInstanceID, Created: &t4},
	})
	assert.NoError(t, err)

	// Verify NO metric was emitted (duplicate ready status)
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_instance_operation_latency_seconds", 0, nil, 0)
}

// Test Instance Metrics - DELETE operations
func Test_InstanceMetrics_Delete_TerminatingOnly(t *testing.T) {
	// Case 1: terminating (should emit metric with duration now-t1)
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()
	util.TestSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageInstanceLifecycleMetrics(reg, dbSession)
	testInstanceID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime                                     // terminating started
	deleteTime := baseTime.Add(200 * time.Millisecond) // delete happened 200ms later
	expectedDuration := deleteTime.Sub(t1)

	// t1: terminating
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusTerminating, nil, t1)

	// Process delete event
	ctx := context.Background()
	err := lifecycleMetrics.RecordInstanceStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testInstanceID, Deleted: &deleteTime},
	})
	assert.NoError(t, err)

	// Verify metric was emitted with correct duration
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_instance_operation_latency_seconds", 1, map[string]string{
		"operation_type": "delete",
		"from_status":    cdbm.InstanceStatusTerminating,
		"to_status":      cdbm.InstanceStatusTerminated,
	}, expectedDuration)
}

func Test_InstanceMetrics_Delete_MultipleTerminating(t *testing.T) {
	// Case 2: terminating -> terminating -> terminating (should emit metric with duration now-t1)
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()
	util.TestSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageInstanceLifecycleMetrics(reg, dbSession)
	testInstanceID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime                                     // first terminating
	t2 := baseTime.Add(50 * time.Millisecond)          // second terminating
	t3 := baseTime.Add(100 * time.Millisecond)         // third terminating
	deleteTime := baseTime.Add(300 * time.Millisecond) // delete happened
	expectedDuration := deleteTime.Sub(t1)             // should use first terminating timestamp

	// t1: terminating
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusTerminating, nil, t1)

	// t2: terminating
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusTerminating, nil, t2)

	// t3: terminating
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusTerminating, nil, t3)

	// Process delete event
	ctx := context.Background()
	err := lifecycleMetrics.RecordInstanceStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testInstanceID, Deleted: &deleteTime},
	})
	assert.NoError(t, err)

	// Verify metric was emitted (should use first terminating timestamp, duration 300ms)
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_instance_operation_latency_seconds", 1, map[string]string{
		"operation_type": "delete",
		"from_status":    cdbm.InstanceStatusTerminating,
		"to_status":      cdbm.InstanceStatusTerminated,
	}, expectedDuration)
}

func Test_InstanceMetrics_Delete_NoTerminating(t *testing.T) {
	// Case 3: ready (no terminating, should NOT emit metric)
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()
	util.TestSetupSchema(t, dbSession)

	site := util.TestSetupSite(t, dbSession)
	reg := prometheus.NewRegistry()
	lifecycleMetrics := NewManageInstanceLifecycleMetrics(reg, dbSession)
	testInstanceID := uuid.New()

	// Set precise timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	t1 := baseTime
	deleteTime := baseTime.Add(100 * time.Millisecond)

	// t1: ready (no terminating status)
	util.TestBuildStatusDetailWithTime(t, dbSession, testInstanceID.String(), cdbm.InstanceStatusReady, nil, t1)

	// Process delete event
	ctx := context.Background()
	err := lifecycleMetrics.RecordInstanceStatusTransitionMetrics(ctx, site.ID, []cwm.InventoryObjectLifecycleEvent{
		{ObjectID: testInstanceID, Deleted: &deleteTime},
	})
	assert.NoError(t, err)

	// Verify NO metric was emitted (no terminating status found)
	util.TestAssertMetricExistsTimes(t, reg, "cloud_workflow_instance_operation_latency_seconds", 0, nil, 0)
}
