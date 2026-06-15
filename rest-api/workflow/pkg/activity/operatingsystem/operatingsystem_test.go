// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operatingsystem

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	sc "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/client/site"
	"github.com/stretchr/testify/assert"

	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller/rest-api/workflow/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/util"
	"google.golang.org/protobuf/types/known/timestamppb"

	tmocks "go.temporal.io/sdk/mocks"

	"go.temporal.io/sdk/testsuite"
)

func TestManageOperatingSystem_UpdateOsImageInDB(t *testing.T) {
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := util.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)

	tnOrg := "test-tenant-org"
	tnRoles := []string{"FORGE_TENANT_ADMIN"}

	tnu := util.TestBuildUser(t, dbSession, uuid.NewString(), []string{tnOrg}, tnRoles)

	tn := util.TestBuildTenant(t, dbSession, "test-tenant", tnOrg, nil, tnu)
	assert.NotNil(t, tn)

	st1 := util.TestBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, st1)

	st2 := util.TestBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, st2)

	st3 := util.TestBuildSite(t, dbSession, ip, "test-site-3", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, st3)

	st4 := util.TestBuildSite(t, dbSession, ip, "test-site-4", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, st4)

	st5 := util.TestBuildSite(t, dbSession, ip, "test-site-5", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, st5)

	// Build OsImage1
	os1 := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, &tn.ID, "test-OsImage-1", tnOrg, nil, cdbm.OperatingSystemStatusSyncing)
	assert.NotNil(t, os1)

	// Build OperatingSystemSiteAssociation1
	ossa1 := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, os1.ID, st1.ID, cdbm.OperatingSystemSiteAssociationStatusSyncing, "12312312434233425", true)
	assert.NotNil(t, ossa1)

	// Build OsImage3
	os3 := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, &tn.ID, "test-OsImage-3", tnOrg, nil, cdbm.OperatingSystemStatusSyncing)
	assert.NotNil(t, os1)

	// Build OperatingSystemSiteAssociation3
	ossa3 := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, os3.ID, st1.ID, cdbm.OperatingSystemSiteAssociationStatusSyncing, "123123112d2434233425", true)
	assert.NotNil(t, ossa3)

	// Build OsImage5
	os5 := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, &tn.ID, "test-OsImage-5", tnOrg, nil, cdbm.OperatingSystemStatusDeleting)
	assert.NotNil(t, os5)

	// Build OperatingSystemSiteAssociation5
	ossa5 := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, os5.ID, st1.ID, cdbm.OperatingSystemSiteAssociationStatusDeleting, "123123112d24342as33425", true)
	assert.NotNil(t, ossa5)

	// Build OsImage9
	os9 := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, &tn.ID, "test-OsImage-9", tnOrg, nil, cdbm.OperatingSystemStatusDeleting)
	assert.NotNil(t, os9)

	// Build OperatingSystemSiteAssociation9
	ossa9 := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, os9.ID, st1.ID, cdbm.OperatingSystemSiteAssociationStatusDeleting, "123123112d24782as33425", true)
	assert.NotNil(t, ossa9)

	// Build OsImage7
	os7 := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, &tn.ID, "test-OsImage-7", tnOrg, nil, cdbm.OperatingSystemStatusSyncing)
	assert.NotNil(t, os7)

	// Build OperatingSystemSiteAssociation7
	ossa7 := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, os7.ID, st1.ID, cdbm.OperatingSystemSiteAssociationStatusSyncing, "123123112d24342as33425234", false)
	assert.NotNil(t, ossa7)

	// Build OsImage2
	os2 := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, &tn.ID, "test-OsImage-2", tnOrg, nil, cdbm.OperatingSystemStatusReady)
	assert.NotNil(t, os1)

	// Build OperatingSystemSiteAssociation2
	ossa2 := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, os2.ID, st2.ID, cdbm.OperatingSystemSiteAssociationStatusSynced, "12312312434awsdq212", true)
	assert.NotNil(t, ossa2)

	// Build OsImage4
	os4 := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, &tn.ID, "test-OsImage-4", tnOrg, nil, cdbm.OperatingSystemStatusDeleting)
	assert.NotNil(t, os1)

	// Build OperatingSystemSiteAssociation4
	ossa4 := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, os4.ID, st2.ID, cdbm.OperatingSystemSiteAssociationStatusDeleting, "12312312434awsdq212", true)
	assert.NotNil(t, ossa4)

	tSiteClientPool := util.TestTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	temporalsuit := testsuite.WorkflowTestSuite{}
	env := temporalsuit.NewTestWorkflowEnvironment()

	type fields struct {
		dbSession      *cdb.Session
		siteClientPool *sc.ClientPool
		env            *testsuite.TestWorkflowEnvironment
	}

	type args struct {
		ctx              context.Context
		osImageInventory *cwssaws.OsImageInventory
		readyoss         []uuid.UUID
		deletedoss       []uuid.UUID
		erroross         []uuid.UUID
		site             *cdbm.Site
	}

	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "test OS Image inventory return success status",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx: context.Background(),
				osImageInventory: &cwssaws.OsImageInventory{
					OsImages: []*cwssaws.OsImage{
						{
							Attributes: &cwssaws.OsImageAttributes{
								Id: &cwssaws.UUID{Value: ossa1.OperatingSystemID.String()},
							},
							Status: cwssaws.OsImageStatus_ImageReady,
						},
						{
							Attributes: &cwssaws.OsImageAttributes{
								Id: &cwssaws.UUID{Value: ossa3.OperatingSystemID.String()},
							},
							Status: cwssaws.OsImageStatus_ImageReady,
						},
						{
							Attributes: &cwssaws.OsImageAttributes{
								Id: &cwssaws.UUID{Value: ossa7.OperatingSystemID.String()},
							},
							Status: cwssaws.OsImageStatus_ImageReady,
						},
					},
					Timestamp: timestamppb.Now(),
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 1,
						TotalPages:  1,
						PageSize:    1,
						TotalItems:  3,
						ItemIds:     []string{os1.ID.String(), os3.ID.String(), os7.ID.String()},
					},
				},
				site: st1,
				readyoss: []uuid.UUID{
					os1.ID,
					os3.ID,
					os7.ID,
				},
				deletedoss: []uuid.UUID{
					os5.ID,
				},
			},
		},
		{
			name: "test OS Image inventory return nil successfully delete os image",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx: context.Background(),
				osImageInventory: &cwssaws.OsImageInventory{
					OsImages:  []*cwssaws.OsImage{},
					Timestamp: timestamppb.Now(),
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 1,
						TotalPages:  0,
						PageSize:    25,
						TotalItems:  0,
						ItemIds:     []string{},
					},
				},
				site:     st1,
				readyoss: []uuid.UUID{},
				deletedoss: []uuid.UUID{
					os9.ID,
				},
			},
		},
		{
			name: "test OS Image inventory returned failed status",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx: context.Background(),
				osImageInventory: &cwssaws.OsImageInventory{
					OsImages: []*cwssaws.OsImage{
						{
							Attributes: &cwssaws.OsImageAttributes{
								Id: &cwssaws.UUID{Value: ossa2.OperatingSystemID.String()},
							},
							Status: cwssaws.OsImageStatus_ImageFailed,
						},
						{
							Attributes: &cwssaws.OsImageAttributes{
								Id: &cwssaws.UUID{Value: ossa4.OperatingSystemID.String()},
							},
							Status: cwssaws.OsImageStatus_ImageFailed,
						},
					},
				},
				deletedoss: []uuid.UUID{
					os4.ID,
				},
				erroross: []uuid.UUID{
					os2.ID,
				},
				site: st2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mv := ManageOperatingSystem{
				dbSession:      tt.fields.dbSession,
				siteClientPool: tSiteClientPool,
			}

			mtc := &tmocks.Client{}
			mv.siteClientPool.IDClientMap[tt.args.site.ID.String()] = mtc

			_, err := mv.UpdateOsImagesInDB(tt.args.ctx, tt.args.site.ID, tt.args.osImageInventory)
			assert.NoError(t, err)

			ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dbSession)
			if tt.args.readyoss != nil {
				readyossa, _, err := ossaDAO.GetAll(
					tt.args.ctx,
					nil,
					cdbm.OperatingSystemSiteAssociationFilterInput{
						OperatingSystemIDs: tt.args.readyoss,
						SiteIDs:            []uuid.UUID{tt.args.site.ID},
					},
					paginator.PageInput{},
					nil,
				)
				assert.Nil(t, err)
				for _, ossa := range readyossa {
					assert.Equal(t, ossa.Status, cdbm.OperatingSystemSiteAssociationStatusSynced)
				}
			}

			if tt.args.deletedoss != nil {
				deleteossa, _, err := ossaDAO.GetAll(
					tt.args.ctx,
					nil,
					cdbm.OperatingSystemSiteAssociationFilterInput{
						OperatingSystemIDs: tt.args.deletedoss,
						SiteIDs:            []uuid.UUID{tt.args.site.ID},
					},
					paginator.PageInput{},
					nil,
				)
				assert.Nil(t, err)
				assert.Equal(t, len(deleteossa), 0)
			}

			if tt.args.erroross != nil {
				errorossa, _, err := ossaDAO.GetAll(
					tt.args.ctx,
					nil,
					cdbm.OperatingSystemSiteAssociationFilterInput{
						OperatingSystemIDs: tt.args.erroross,
						SiteIDs:            []uuid.UUID{tt.args.site.ID},
					},
					paginator.PageInput{},
					nil,
				)
				assert.Nil(t, err)
				for _, ossa := range errorossa {
					assert.Equal(t, ossa.Status, cdbm.OperatingSystemSiteAssociationStatusError)
				}
			}
		})
	}
}

func TestManageOperatingSystemSync_UpdateOperatingSystemsInDB(t *testing.T) {
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}
	ipu := util.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)

	tnOrg := "test-tenant-org"
	tnRoles := []string{"FORGE_TENANT_ADMIN"}
	tnu := util.TestBuildUser(t, dbSession, uuid.NewString(), []string{tnOrg}, tnRoles)
	tn := util.TestBuildTenant(t, dbSession, "test-tenant", tnOrg, nil, tnu)

	st := util.TestBuildSite(t, dbSession, ip, "sync-site", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, st)

	util.TestBuildTenantSiteAssociation(t, dbSession, tnOrg, tn.ID, st.ID, ipu.ID)

	tSiteClientPool := util.TestTemporalSiteClientPool(t)
	operatingSystemManager := NewManageOperatingSystem(dbSession, tSiteClientPool)

	t.Run("nil inventory returns error", func(t *testing.T) {
		err := operatingSystemManager.UpdateOperatingSystemsInDB(context.Background(), st.ID, nil)
		assert.Error(t, err)
	})

	t.Run("failed inventory status is skipped", func(t *testing.T) {
		inv := &cwssaws.OperatingSystemInventory{
			InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED,
		}
		err := operatingSystemManager.UpdateOperatingSystemsInDB(context.Background(), st.ID, inv)
		assert.NoError(t, err)
	})

	t.Run("creates new OS from core inventory", func(t *testing.T) {
		newID := uuid.New()
		now := timestamppb.Now()
		inv := &cwssaws.OperatingSystemInventory{
			InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			Timestamp:       now,
			OperatingSystems: []*cwssaws.OperatingSystem{
				{
					Id:                   &cwssaws.OperatingSystemId{Value: newID.String()},
					Name:                 "core-os-create-test",
					TenantOrganizationId: tnOrg,
					Type:                 cwssaws.OperatingSystemType_OS_TYPE_IPXE,
					Status:               cwssaws.TenantState_READY,
					IsActive:             true,
					AllowOverride:        true,
					PhoneHomeEnabled:     false,
					Created:              now.AsTime().Format("2006-01-02T15:04:05Z07:00"),
					Updated:              now.AsTime().Format("2006-01-02T15:04:05Z07:00"),
				},
			},
		}
		err := operatingSystemManager.UpdateOperatingSystemsInDB(context.Background(), st.ID, inv)
		assert.NoError(t, err)

		osDAO := cdbm.NewOperatingSystemDAO(dbSession)
		created, getErr := osDAO.GetByID(context.Background(), nil, newID, nil)
		assert.NoError(t, getErr)
		assert.Equal(t, "core-os-create-test", created.Name)
		assert.Equal(t, cdbm.OperatingSystemStatusReady, created.Status)
		assert.NotNil(t, created.InfrastructureProviderID)
		assert.Equal(t, ip.ID, *created.InfrastructureProviderID)
		assert.Nil(t, created.TenantID)
		assert.NotNil(t, created.IpxeOsScope)
		assert.Equal(t, cdbm.OperatingSystemScopeLocal, *created.IpxeOsScope)

		// Verify site association was created for the reporting site.
		ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dbSession)
		createdOssa, ossaGetErr := ossaDAO.GetByOperatingSystemIDAndSiteID(context.Background(), nil, newID, st.ID, nil)
		assert.NoError(t, ossaGetErr)
		assert.NotNil(t, createdOssa)
		assert.Equal(t, cdbm.OperatingSystemSiteAssociationStatusSynced, createdOssa.Status)
	})

	t.Run("updates existing OS when core is newer", func(t *testing.T) {
		existingID := uuid.New()
		existingOS := &cdbm.OperatingSystem{
			ID:                       existingID,
			Name:                     "existing-os-old",
			Org:                      tnOrg,
			InfrastructureProviderID: &ip.ID,
			Type:                     cdbm.OperatingSystemTypeIPXE,
			Status:                   cdbm.OperatingSystemStatusProvisioning,
			IsActive:                 true,
			CreatedBy:                ipu.ID,
		}
		_, err := dbSession.DB.NewInsert().Model(existingOS).Exec(context.Background())
		assert.NoError(t, err)

		futureTime := timestamppb.Now()
		inv := &cwssaws.OperatingSystemInventory{
			InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			Timestamp:       futureTime,
			OperatingSystems: []*cwssaws.OperatingSystem{
				{
					Id:                   &cwssaws.OperatingSystemId{Value: existingID.String()},
					Name:                 "existing-os-updated",
					TenantOrganizationId: tnOrg,
					Type:                 cwssaws.OperatingSystemType_OS_TYPE_IPXE,
					Status:               cwssaws.TenantState_READY,
					IsActive:             true,
					AllowOverride:        true,
					PhoneHomeEnabled:     true,
					Created:              futureTime.AsTime().Format("2006-01-02T15:04:05Z07:00"),
					Updated:              futureTime.AsTime().Add(1 * time.Second).Format("2006-01-02T15:04:05Z07:00"),
				},
			},
		}
		err = operatingSystemManager.UpdateOperatingSystemsInDB(context.Background(), st.ID, inv)
		assert.NoError(t, err)

		osDAO := cdbm.NewOperatingSystemDAO(dbSession)
		updated, getErr := osDAO.GetByID(context.Background(), nil, existingID, nil)
		assert.NoError(t, getErr)
		assert.Equal(t, "existing-os-updated", updated.Name)
		assert.Equal(t, cdbm.OperatingSystemStatusReady, updated.Status)
		assert.True(t, updated.PhoneHomeEnabled)

		// Verify OSSA was backfilled for the existing OS.
		ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dbSession)
		backfilledOssa, ossaGetErr := ossaDAO.GetByOperatingSystemIDAndSiteID(context.Background(), nil, existingID, st.ID, nil)
		assert.NoError(t, ossaGetErr)
		assert.NotNil(t, backfilledOssa)
		assert.Equal(t, cdbm.OperatingSystemSiteAssociationStatusSynced, backfilledOssa.Status)
	})

	t.Run("skips global-scoped OS definition update but records core status", func(t *testing.T) {
		globalID := uuid.New()
		scopeGlobal := cdbm.OperatingSystemScopeGlobal
		globalOS := &cdbm.OperatingSystem{
			ID:                       globalID,
			Name:                     "global-os-original",
			Org:                      tnOrg,
			InfrastructureProviderID: &ip.ID,
			Type:                     cdbm.OperatingSystemTypeIPXE,
			Status:                   cdbm.OperatingSystemStatusProvisioning,
			IsActive:                 true,
			IpxeOsScope:              &scopeGlobal,
			CreatedBy:                ipu.ID,
		}
		_, err := dbSession.DB.NewInsert().Model(globalOS).Exec(context.Background())
		assert.NoError(t, err)

		ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dbSession)
		_, ossaErr := ossaDAO.Create(context.Background(), nil, cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: globalID,
			SiteID:            st.ID,
			Status:            cdbm.OperatingSystemStatusProvisioning,
			CreatedBy:         ipu.ID,
		})
		assert.NoError(t, ossaErr)

		futureTime := timestamppb.Now()
		inv := &cwssaws.OperatingSystemInventory{
			InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			Timestamp:       futureTime,
			OperatingSystems: []*cwssaws.OperatingSystem{
				{
					Id:                   &cwssaws.OperatingSystemId{Value: globalID.String()},
					Name:                 "global-os-changed-in-core",
					TenantOrganizationId: tnOrg,
					Type:                 cwssaws.OperatingSystemType_OS_TYPE_IPXE,
					Status:               cwssaws.TenantState_READY,
					IsActive:             true,
					Created:              futureTime.AsTime().Format("2006-01-02T15:04:05Z07:00"),
					Updated:              futureTime.AsTime().Add(1 * time.Second).Format("2006-01-02T15:04:05Z07:00"),
				},
			},
		}
		err = operatingSystemManager.UpdateOperatingSystemsInDB(context.Background(), st.ID, inv)
		assert.NoError(t, err)

		osDAO := cdbm.NewOperatingSystemDAO(dbSession)
		unchanged, getErr := osDAO.GetByID(context.Background(), nil, globalID, nil)
		assert.NoError(t, getErr)
		assert.Equal(t, "global-os-original", unchanged.Name, "global OS name should not be overwritten by core")
		assert.Equal(t, cdbm.OperatingSystemStatusReady, unchanged.Status, "aggregate status should be updated to READY")
	})

	t.Run("soft-deletes local OS absent from core inventory", func(t *testing.T) {
		absentID := uuid.New()
		absentOS := &cdbm.OperatingSystem{
			ID:                       absentID,
			Name:                     "absent-os",
			Org:                      tnOrg,
			InfrastructureProviderID: &ip.ID,
			Type:                     cdbm.OperatingSystemTypeIPXE,
			Status:                   cdbm.OperatingSystemStatusReady,
			IsActive:                 true,
			CreatedBy:                ipu.ID,
		}
		_, err := dbSession.DB.NewInsert().Model(absentOS).Exec(context.Background())
		assert.NoError(t, err)

		inv := &cwssaws.OperatingSystemInventory{
			InventoryStatus:  cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			Timestamp:        timestamppb.Now(),
			OperatingSystems: []*cwssaws.OperatingSystem{},
		}
		err = operatingSystemManager.UpdateOperatingSystemsInDB(context.Background(), st.ID, inv)
		assert.NoError(t, err)

		osDAO := cdbm.NewOperatingSystemDAO(dbSession)
		_, getErr := osDAO.GetByID(context.Background(), nil, absentID, nil)
		assert.Error(t, getErr, "absent OS should be soft-deleted and not found")
	})

	t.Run("does NOT soft-delete global-scoped OS absent from core inventory", func(t *testing.T) {
		globalAbsentID := uuid.New()
		scopeGlobal := cdbm.OperatingSystemScopeGlobal
		globalAbsentOS := &cdbm.OperatingSystem{
			ID:                       globalAbsentID,
			Name:                     "global-absent-os",
			Org:                      tnOrg,
			InfrastructureProviderID: &ip.ID,
			Type:                     cdbm.OperatingSystemTypeIPXE,
			Status:                   cdbm.OperatingSystemStatusReady,
			IsActive:                 true,
			IpxeOsScope:              &scopeGlobal,
			CreatedBy:                ipu.ID,
		}
		_, err := dbSession.DB.NewInsert().Model(globalAbsentOS).Exec(context.Background())
		assert.NoError(t, err)

		inv := &cwssaws.OperatingSystemInventory{
			InventoryStatus:  cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			Timestamp:        timestamppb.Now(),
			OperatingSystems: []*cwssaws.OperatingSystem{},
		}
		err = operatingSystemManager.UpdateOperatingSystemsInDB(context.Background(), st.ID, inv)
		assert.NoError(t, err)

		osDAO := cdbm.NewOperatingSystemDAO(dbSession)
		stillExists, getErr := osDAO.GetByID(context.Background(), nil, globalAbsentID, nil)
		assert.NoError(t, getErr, "global-scoped OS must NOT be deleted by reconciliation-by-absence")
		assert.Equal(t, "global-absent-os", stillExists.Name)
	})

	t.Run("does not restore soft-deleted OS even if core reports it", func(t *testing.T) {
		deletedID := uuid.New()
		deletedTime := time.Now().Add(-1 * time.Hour)
		deletedOS := &cdbm.OperatingSystem{
			ID:                       deletedID,
			Name:                     "already-deleted-os",
			Org:                      tnOrg,
			InfrastructureProviderID: &ip.ID,
			Type:                     cdbm.OperatingSystemTypeIPXE,
			Status:                   cdbm.OperatingSystemStatusReady,
			IsActive:                 true,
			Deleted:                  &deletedTime,
			CreatedBy:                ipu.ID,
		}
		_, err := dbSession.DB.NewInsert().Model(deletedOS).Exec(context.Background())
		assert.NoError(t, err)

		futureTime := timestamppb.Now()
		inv := &cwssaws.OperatingSystemInventory{
			InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			Timestamp:       futureTime,
			OperatingSystems: []*cwssaws.OperatingSystem{
				{
					Id:                   &cwssaws.OperatingSystemId{Value: deletedID.String()},
					Name:                 "already-deleted-os",
					TenantOrganizationId: tnOrg,
					Type:                 cwssaws.OperatingSystemType_OS_TYPE_IPXE,
					Status:               cwssaws.TenantState_READY,
					IsActive:             true,
					Created:              futureTime.AsTime().Format("2006-01-02T15:04:05Z07:00"),
					Updated:              futureTime.AsTime().Format("2006-01-02T15:04:05Z07:00"),
				},
			},
		}
		err = operatingSystemManager.UpdateOperatingSystemsInDB(context.Background(), st.ID, inv)
		assert.NoError(t, err)

		osDAO := cdbm.NewOperatingSystemDAO(dbSession)
		_, getErr := osDAO.GetByID(context.Background(), nil, deletedID, nil)
		assert.Error(t, getErr, "soft-deleted OS should remain deleted even when core reports it active")
	})
}

func TestManageOperatingSystem_UpdateOperatingSystemStatusInDB(t *testing.T) {
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := util.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)

	tnOrg := "test-tenant-org"
	tnRoles := []string{"FORGE_TENANT_ADMIN"}

	tnu := util.TestBuildUser(t, dbSession, uuid.NewString(), []string{tnOrg}, tnRoles)

	tn := util.TestBuildTenant(t, dbSession, "test-tenant", tnOrg, nil, tnu)
	assert.NotNil(t, tn)

	st1 := util.TestBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, st1)

	st2 := util.TestBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, st2)

	// Build OsImage1
	os1 := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, &tn.ID, "test-OsImage-1", tnOrg, nil, cdbm.OperatingSystemStatusSyncing)
	assert.NotNil(t, os1)

	// Build OperatingSystemSiteAssociation1
	ossa1 := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, os1.ID, st1.ID, cdbm.OperatingSystemSiteAssociationStatusSyncing, "12312312434233425", false)
	assert.NotNil(t, ossa1)

	// Build OsImage2
	os2 := util.TestBuildImageOperatingSystem(t, dbSession, &ip.ID, &tn.ID, "test-OsImage-2", tnOrg, nil, cdbm.OperatingSystemStatusError)
	assert.NotNil(t, os1)

	// Build OperatingSystemSiteAssociation2
	ossa2 := util.TestBuildImageOperatingSystemSiteAssociation(t, dbSession, os2.ID, st2.ID, cdbm.OperatingSystemSiteAssociationStatusSynced, "12312312434awsdq212", false)
	assert.NotNil(t, ossa2)

	tSiteClientPool := util.TestTemporalSiteClientPool(t)
	assert.NotNil(t, tSiteClientPool)

	temporalsuit := testsuite.WorkflowTestSuite{}
	env := temporalsuit.NewTestWorkflowEnvironment()

	type fields struct {
		dbSession      *cdb.Session
		siteClientPool *sc.ClientPool
		env            *testsuite.TestWorkflowEnvironment
	}

	type args struct {
		ctx   context.Context
		ossas *cdbm.OperatingSystemSiteAssociation
		os    *cdbm.OperatingSystem
		site  *cdbm.Site
	}

	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "test update os status syncing when os site association still syncing",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:   context.Background(),
				ossas: ossa1,
				os:    os1,
				site:  st1,
			},
		},
		{
			name: "test update os status ready when os site association synced",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:   context.Background(),
				ossas: ossa2,
				os:    os2,
				site:  st2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mv := ManageOperatingSystem{
				dbSession:      tt.fields.dbSession,
				siteClientPool: tSiteClientPool,
			}

			mtc := &tmocks.Client{}
			mv.siteClientPool.IDClientMap[tt.args.site.ID.String()] = mtc

			err := mv.UpdateOperatingSystemStatusInDB(tt.args.ctx, tt.args.os.ID)
			assert.NoError(t, err)

			osDAO := cdbm.NewOperatingSystemDAO(dbSession)
			uos, err := osDAO.GetByID(context.Background(), nil, tt.args.os.ID, nil)
			assert.Nil(t, err)

			if tt.args.ossas.Status == cdbm.OperatingSystemSiteAssociationStatusSyncing {
				assert.Equal(t, uos.Status, cdbm.OperatingSystemStatusSyncing)
			}

			if tt.args.ossas.Status == cdbm.OperatingSystemSiteAssociationStatusError {
				assert.Equal(t, uos.Status, cdbm.OperatingSystemStatusError)
			}

			if tt.args.ossas.Status == cdbm.OperatingSystemSiteAssociationStatusSynced {
				assert.Equal(t, uos.Status, cdbm.OperatingSystemStatusReady)
			}

		})
	}
}
func TestNewManageOperatingSystem(t *testing.T) {
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
		want ManageOperatingSystem
	}{
		{
			name: "test new ManageOperatingSystem instantiation",
			args: args{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
			want: ManageOperatingSystem{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewManageOperatingSystem(tt.args.dbSession, tt.args.siteClientPool); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewManageOperatingSystem() = %v, want %v", got, tt.want)
			}
		})
	}
}
