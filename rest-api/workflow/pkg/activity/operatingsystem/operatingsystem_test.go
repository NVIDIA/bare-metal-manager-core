// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operatingsystem

import (
	"context"
	"reflect"
	"testing"
	"time"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	sc "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/client/site"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller/rest-api/workflow/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/util"
	"google.golang.org/protobuf/types/known/timestamppb"

	"os"

	tmocks "go.temporal.io/sdk/mocks"

	"go.temporal.io/sdk/testsuite"
)

func TestManageOsImage_UpdateOsImageInDB(t *testing.T) {
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
		osImageInventory *corev1.OsImageInventory
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
				osImageInventory: &corev1.OsImageInventory{
					OsImages: []*corev1.OsImage{
						{
							Attributes: &corev1.OsImageAttributes{
								Id: &corev1.UUID{Value: ossa1.OperatingSystemID.String()},
							},
							Status: corev1.OsImageStatus_ImageReady,
						},
						{
							Attributes: &corev1.OsImageAttributes{
								Id: &corev1.UUID{Value: ossa3.OperatingSystemID.String()},
							},
							Status: corev1.OsImageStatus_ImageReady,
						},
						{
							Attributes: &corev1.OsImageAttributes{
								Id: &corev1.UUID{Value: ossa7.OperatingSystemID.String()},
							},
							Status: corev1.OsImageStatus_ImageReady,
						},
					},
					Timestamp: timestamppb.Now(),
					InventoryPage: &corev1.InventoryPage{
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
				osImageInventory: &corev1.OsImageInventory{
					OsImages:  []*corev1.OsImage{},
					Timestamp: timestamppb.Now(),
					InventoryPage: &corev1.InventoryPage{
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
				osImageInventory: &corev1.OsImageInventory{
					OsImages: []*corev1.OsImage{
						{
							Attributes: &corev1.OsImageAttributes{
								Id: &corev1.UUID{Value: ossa2.OperatingSystemID.String()},
							},
							Status: corev1.OsImageStatus_ImageFailed,
						},
						{
							Attributes: &corev1.OsImageAttributes{
								Id: &corev1.UUID{Value: ossa4.OperatingSystemID.String()},
							},
							Status: corev1.OsImageStatus_ImageFailed,
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
			mv := ManageOsImage{
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

func TestManageOsImage_UpdateOperatingSystemStatusInDB(t *testing.T) {
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
			mv := ManageOsImage{
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

// TestManageOsImage_UpdateOperatingSystemsInDB exercises the Operating System
// inventory reconciliation performed for iPXE / Templated iPXE Operating Systems
// pushed from nico-core: creation of provider-owned Local records, skipping of
// Templated iPXE records whose template is not available at the Site, and
// deletion-by-absence of Local records no longer reported by the Site.
//
// The suite uses a distinct Infrastructure Provider (and Site) per scenario so
// the provider-scoped deletion reconciliation of one scenario cannot affect the
// records created by another.
func TestManageOsImage_UpdateOperatingSystemsInDB(t *testing.T) {
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ctx := context.Background()

	ipOrg := "test-provider-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}
	ipu := util.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)

	osDAO := cdbm.NewOperatingSystemDAO(dbSession)
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dbSession)
	templateDAO := cdbm.NewIpxeTemplateDAO(dbSession)
	itsaDAO := cdbm.NewIpxeTemplateSiteAssociationDAO(dbSession)

	newManageOsImage := func() ManageOsImage {
		return ManageOsImage{dbSession: dbSession, siteClientPool: util.TestTemporalSiteClientPool(t)}
	}

	t.Run("creates provider-owned Local Templated iPXE OS reported by Site", func(t *testing.T) {
		ip := util.TestBuildInfrastructureProvider(t, dbSession, "provider-create", "provider-create-org", ipu)
		st := util.TestBuildSite(t, dbSession, ip, "site-create", cdbm.SiteStatusRegistered, nil, ipu)

		tmpl, err := templateDAO.Create(ctx, nil, cdbm.IpxeTemplateCreateInput{
			ID:         uuid.New(),
			Name:       "tmpl-create",
			Template:   "#!ipxe\n",
			Visibility: "Public",
		})
		require.NoError(t, err)
		_, err = itsaDAO.Create(ctx, nil, cdbm.IpxeTemplateSiteAssociationCreateInput{IpxeTemplateID: tmpl.ID, SiteID: st.ID})
		require.NoError(t, err)

		osID := uuid.New()
		inventory := &corev1.OperatingSystemInventory{
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			OperatingSystems: []*corev1.OperatingSystem{
				{
					Id:             &corev1.OperatingSystemId{Value: osID.String()},
					Name:           "reported-templated-os",
					Type:           corev1.OperatingSystemType_OS_TYPE_TEMPLATED_IPXE,
					Status:         corev1.TenantState_READY,
					IsActive:       true,
					IpxeTemplateId: &corev1.IpxeTemplateId{Value: tmpl.ID.String()},
					Updated:        time.Now().Format(time.RFC3339),
				},
			},
			Timestamp: timestamppb.Now(),
		}

		err = newManageOsImage().UpdateOperatingSystemsInDB(ctx, st.ID, inventory)
		require.NoError(t, err)

		created, err := osDAO.GetByID(ctx, nil, osID, nil)
		require.NoError(t, err)
		require.NotNil(t, created)
		assert.Equal(t, cdbm.OperatingSystemTypeTemplatedIPXE, created.Type)
		require.NotNil(t, created.InfrastructureProviderID)
		assert.Equal(t, ip.ID, *created.InfrastructureProviderID)
		assert.Nil(t, created.TenantID, "OSes originating from a Site are provider-owned, not tenant-owned")
		require.NotNil(t, created.IpxeOsScope)
		assert.Equal(t, cdbm.OperatingSystemScopeLocal, *created.IpxeOsScope)
		assert.Equal(t, cdbm.OperatingSystemStatusReady, created.Status)

		ossa, err := ossaDAO.GetByOperatingSystemIDAndSiteID(ctx, nil, osID, st.ID, nil)
		require.NoError(t, err)
		require.NotNil(t, ossa)
		assert.Equal(t, cdbm.OperatingSystemSiteAssociationStatusSynced, ossa.Status)
	})

	t.Run("skips Templated iPXE OS whose template is not available at Site", func(t *testing.T) {
		ip := util.TestBuildInfrastructureProvider(t, dbSession, "provider-skip", "provider-skip-org", ipu)
		st := util.TestBuildSite(t, dbSession, ip, "site-skip", cdbm.SiteStatusRegistered, nil, ipu)

		// Template exists but has no association with this Site.
		tmpl, err := templateDAO.Create(ctx, nil, cdbm.IpxeTemplateCreateInput{
			ID:         uuid.New(),
			Name:       "tmpl-skip",
			Template:   "#!ipxe\n",
			Visibility: "Public",
		})
		require.NoError(t, err)

		osID := uuid.New()
		inventory := &corev1.OperatingSystemInventory{
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			OperatingSystems: []*corev1.OperatingSystem{
				{
					Id:             &corev1.OperatingSystemId{Value: osID.String()},
					Name:           "reported-templated-os-skip",
					Type:           corev1.OperatingSystemType_OS_TYPE_TEMPLATED_IPXE,
					Status:         corev1.TenantState_READY,
					IsActive:       true,
					IpxeTemplateId: &corev1.IpxeTemplateId{Value: tmpl.ID.String()},
					Updated:        time.Now().Format(time.RFC3339),
				},
			},
			Timestamp: timestamppb.Now(),
		}

		err = newManageOsImage().UpdateOperatingSystemsInDB(ctx, st.ID, inventory)
		require.NoError(t, err)

		_, err = osDAO.GetByID(ctx, nil, osID, nil)
		assert.ErrorIs(t, err, cdb.ErrDoesNotExist, "OS should not be created when its template is not available at the Site")
	})

	t.Run("does not overwrite existing Local Templated iPXE OS when reported template is unavailable at Site", func(t *testing.T) {
		ip := util.TestBuildInfrastructureProvider(t, dbSession, "provider-noverwrite", "provider-noverwrite-org", ipu)
		st := util.TestBuildSite(t, dbSession, ip, "site-noverwrite", cdbm.SiteStatusRegistered, nil, ipu)

		// Template associated with the Site (the current, valid reference).
		tmplA, err := templateDAO.Create(ctx, nil, cdbm.IpxeTemplateCreateInput{
			ID: uuid.New(), Name: "tmpl-noverwrite-a", Template: "#!ipxe\n", Visibility: "Public",
		})
		require.NoError(t, err)
		_, err = itsaDAO.Create(ctx, nil, cdbm.IpxeTemplateSiteAssociationCreateInput{IpxeTemplateID: tmplA.ID, SiteID: st.ID})
		require.NoError(t, err)

		// Template NOT associated with the Site (an unavailable reference).
		tmplB, err := templateDAO.Create(ctx, nil, cdbm.IpxeTemplateCreateInput{
			ID: uuid.New(), Name: "tmpl-noverwrite-b", Template: "#!ipxe\n", Visibility: "Public",
		})
		require.NoError(t, err)

		osID := uuid.New()
		_, err = osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
			ID:                       osID,
			Name:                     "existing-templated-os",
			Org:                      st.Org,
			InfrastructureProviderID: &ip.ID,
			OsType:                   cdbm.OperatingSystemTypeTemplatedIPXE,
			IpxeTemplateId:           cutil.GetPtr(tmplA.ID.String()),
			IpxeOsScope:              cutil.GetPtr(cdbm.OperatingSystemScopeLocal),
			Status:                   cdbm.OperatingSystemStatusReady,
			CreatedBy:                ipu.ID,
		})
		require.NoError(t, err)
		_, err = ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: osID, SiteID: st.ID, Status: cdbm.OperatingSystemSiteAssociationStatusSynced, CreatedBy: ipu.ID,
		})
		require.NoError(t, err)

		// Site reports the OS with a newer timestamp but referencing a template
		// that is not associated with the Site. The definition update must be
		// skipped so the existing (valid) template reference is preserved.
		inventory := &corev1.OperatingSystemInventory{
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			OperatingSystems: []*corev1.OperatingSystem{
				{
					Id:             &corev1.OperatingSystemId{Value: osID.String()},
					Name:           "renamed-should-not-apply",
					Type:           corev1.OperatingSystemType_OS_TYPE_TEMPLATED_IPXE,
					Status:         corev1.TenantState_READY,
					IsActive:       true,
					IpxeTemplateId: &corev1.IpxeTemplateId{Value: tmplB.ID.String()},
					Updated:        time.Now().Add(time.Hour).Format(time.RFC3339),
				},
			},
			Timestamp: timestamppb.Now(),
		}

		err = newManageOsImage().UpdateOperatingSystemsInDB(ctx, st.ID, inventory)
		require.NoError(t, err)

		unchanged, err := osDAO.GetByID(ctx, nil, osID, nil)
		require.NoError(t, err)
		require.NotNil(t, unchanged)
		assert.Equal(t, "existing-templated-os", unchanged.Name, "definition must not be overwritten with an unavailable template")
		require.NotNil(t, unchanged.IpxeTemplateId)
		assert.Equal(t, tmplA.ID.String(), *unchanged.IpxeTemplateId, "template reference must be preserved")
	})

	t.Run("does not re-home a Local iPXE OS that anomalously has a tenant_id", func(t *testing.T) {
		// A Local-scoped OS is provider-owned by definition and must never carry a
		// tenant_id. Such a row is a data-integrity anomaly that no correct path can
		// produce, so the reconcile must flag and skip it -- NOT silently clear the
		// tenant and reassign ownership to the provider (which would hide the upstream
		// error and irreversibly change ownership).
		ip := util.TestBuildInfrastructureProvider(t, dbSession, "provider-anomaly", "provider-anomaly-org", ipu)
		st := util.TestBuildSite(t, dbSession, ip, "site-anomaly", cdbm.SiteStatusRegistered, nil, ipu)

		tnOrg := "tenant-anomaly-org"
		tnu := util.TestBuildUser(t, dbSession, uuid.NewString(), []string{tnOrg}, []string{"FORGE_TENANT_ADMIN"})
		tn := util.TestBuildTenant(t, dbSession, "tenant-anomaly", tnOrg, nil, tnu)

		osID := uuid.New()
		_, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
			ID:          osID,
			Name:        "anomalous-local-os",
			Org:         tnOrg,
			TenantID:    &tn.ID,
			OsType:      cdbm.OperatingSystemTypeIPXE,
			IpxeScript:  cutil.GetPtr("#!ipxe\n"),
			IpxeOsScope: cutil.GetPtr(cdbm.OperatingSystemScopeLocal),
			Status:      cdbm.OperatingSystemStatusReady,
			CreatedBy:   tnu.ID,
		})
		require.NoError(t, err)

		// Site reports the OS with a newer timestamp and a new name. Without the guard
		// this would overwrite the definition, set the provider, and clear the tenant.
		inventory := &corev1.OperatingSystemInventory{
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			OperatingSystems: []*corev1.OperatingSystem{
				{
					Id:       &corev1.OperatingSystemId{Value: osID.String()},
					Name:     "renamed-should-not-apply",
					Type:     corev1.OperatingSystemType_OS_TYPE_IPXE,
					Status:   corev1.TenantState_READY,
					IsActive: true,
					Updated:  time.Now().Add(time.Hour).Format(time.RFC3339),
				},
			},
			Timestamp: timestamppb.Now(),
		}

		err = newManageOsImage().UpdateOperatingSystemsInDB(ctx, st.ID, inventory)
		require.NoError(t, err)

		unchanged, err := osDAO.GetByID(ctx, nil, osID, nil)
		require.NoError(t, err)
		require.NotNil(t, unchanged)
		assert.Equal(t, "anomalous-local-os", unchanged.Name, "anomalous record must not be overwritten")
		require.NotNil(t, unchanged.TenantID, "tenant_id must be preserved, not silently cleared")
		assert.Equal(t, tn.ID, *unchanged.TenantID)
		assert.Nil(t, unchanged.InfrastructureProviderID, "ownership must not be reassigned to the provider")
	})

	t.Run("skips timestamp-based update when reported Updated is invalid", func(t *testing.T) {
		// A missing/invalid Updated from the Site must not drive a definition update:
		// coreUpdated.After(...) stays false and, with no other reconciliation reason,
		// the existing definition is preserved (a warning is logged for visibility).
		ip := util.TestBuildInfrastructureProvider(t, dbSession, "provider-badts", "provider-badts-org", ipu)
		st := util.TestBuildSite(t, dbSession, ip, "site-badts", cdbm.SiteStatusRegistered, nil, ipu)

		osID := uuid.New()
		_, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
			ID:                       osID,
			Name:                     "existing-badts-os",
			Org:                      st.Org,
			InfrastructureProviderID: &ip.ID,
			OsType:                   cdbm.OperatingSystemTypeIPXE,
			IpxeScript:               cutil.GetPtr("#!ipxe\n"),
			IpxeOsScope:              cutil.GetPtr(cdbm.OperatingSystemScopeLocal),
			Status:                   cdbm.OperatingSystemStatusReady,
			CreatedBy:                ipu.ID,
		})
		require.NoError(t, err)
		_, err = ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: osID, SiteID: st.ID, Status: cdbm.OperatingSystemSiteAssociationStatusSynced, CreatedBy: ipu.ID,
		})
		require.NoError(t, err)

		// Report the OS with a new name but an invalid Updated timestamp. The provider,
		// org and is_active already match, so no other reconciliation reason applies and
		// the rename must be ignored.
		inventory := &corev1.OperatingSystemInventory{
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			OperatingSystems: []*corev1.OperatingSystem{
				{
					Id:       &corev1.OperatingSystemId{Value: osID.String()},
					Name:     "renamed-should-not-apply",
					Type:     corev1.OperatingSystemType_OS_TYPE_IPXE,
					Status:   corev1.TenantState_READY,
					IsActive: true,
					Updated:  "not-a-timestamp",
				},
			},
			Timestamp: timestamppb.Now(),
		}

		err = newManageOsImage().UpdateOperatingSystemsInDB(ctx, st.ID, inventory)
		require.NoError(t, err)

		unchanged, err := osDAO.GetByID(ctx, nil, osID, nil)
		require.NoError(t, err)
		require.NotNil(t, unchanged)
		assert.Equal(t, "existing-badts-os", unchanged.Name, "invalid Updated must not drive a definition update")
	})

	t.Run("soft-deletes Local iPXE OS absent from Site inventory", func(t *testing.T) {
		ip := util.TestBuildInfrastructureProvider(t, dbSession, "provider-delete", "provider-delete-org", ipu)
		st := util.TestBuildSite(t, dbSession, ip, "site-delete", cdbm.SiteStatusRegistered, nil, ipu)

		osID := uuid.New()
		_, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
			ID:                       osID,
			Name:                     "provider-owned-local-os",
			Org:                      st.Org,
			InfrastructureProviderID: &ip.ID,
			OsType:                   cdbm.OperatingSystemTypeIPXE,
			IpxeScript:               cutil.GetPtr("#!ipxe\n"),
			IpxeOsScope:              cutil.GetPtr(cdbm.OperatingSystemScopeLocal),
			Status:                   cdbm.OperatingSystemStatusReady,
			CreatedBy:                ipu.ID,
		})
		require.NoError(t, err)
		_, err = ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: osID,
			SiteID:            st.ID,
			Status:            cdbm.OperatingSystemSiteAssociationStatusSynced,
			CreatedBy:         ipu.ID,
		})
		require.NoError(t, err)

		// Empty inventory: the Site no longer reports the OS, so it must be soft-deleted.
		inventory := &corev1.OperatingSystemInventory{
			InventoryStatus:  corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			OperatingSystems: []*corev1.OperatingSystem{},
			Timestamp:        timestamppb.Now(),
		}

		err = newManageOsImage().UpdateOperatingSystemsInDB(ctx, st.ID, inventory)
		require.NoError(t, err)

		_, err = osDAO.GetByID(ctx, nil, osID, nil)
		assert.ErrorIs(t, err, cdb.ErrDoesNotExist, "Local OS absent from Site inventory should be soft-deleted")
	})

	t.Run("does not soft-delete a provider's Local OS associated with a different Site", func(t *testing.T) {
		ip := util.TestBuildInfrastructureProvider(t, dbSession, "provider-multisite", "provider-multisite-org", ipu)
		stReporting := util.TestBuildSite(t, dbSession, ip, "site-reporting", cdbm.SiteStatusRegistered, nil, ipu)
		stOther := util.TestBuildSite(t, dbSession, ip, "site-other", cdbm.SiteStatusRegistered, nil, ipu)

		// A Local OS that lives at stOther (same provider), associated only with stOther.
		otherOSID := uuid.New()
		_, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
			ID:                       otherOSID,
			Name:                     "other-site-local-os",
			Org:                      stOther.Org,
			InfrastructureProviderID: &ip.ID,
			OsType:                   cdbm.OperatingSystemTypeIPXE,
			IpxeScript:               cutil.GetPtr("#!ipxe\n"),
			IpxeOsScope:              cutil.GetPtr(cdbm.OperatingSystemScopeLocal),
			Status:                   cdbm.OperatingSystemStatusReady,
			CreatedBy:                ipu.ID,
		})
		require.NoError(t, err)
		_, err = ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: otherOSID,
			SiteID:            stOther.ID,
			Status:            cdbm.OperatingSystemSiteAssociationStatusSynced,
			CreatedBy:         ipu.ID,
		})
		require.NoError(t, err)

		// stReporting reports an empty inventory. Deletion reconciliation must be
		// scoped to stReporting and leave the OS that belongs to stOther intact.
		inventory := &corev1.OperatingSystemInventory{
			InventoryStatus:  corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			OperatingSystems: []*corev1.OperatingSystem{},
			Timestamp:        timestamppb.Now(),
		}

		err = newManageOsImage().UpdateOperatingSystemsInDB(ctx, stReporting.ID, inventory)
		require.NoError(t, err)

		survivor, err := osDAO.GetByID(ctx, nil, otherOSID, nil)
		require.NoError(t, err, "OS associated with a different Site must not be soft-deleted")
		require.NotNil(t, survivor)
	})

	t.Run("paged inventory only reconciles deletions on the final page using ItemIds", func(t *testing.T) {
		ip := util.TestBuildInfrastructureProvider(t, dbSession, "provider-paged", "provider-paged-org", ipu)
		st := util.TestBuildSite(t, dbSession, ip, "site-paged", cdbm.SiteStatusRegistered, nil, ipu)

		// Three provider-owned Local raw iPXE OSes, each associated with the reporting Site.
		mkOS := func(name string) uuid.UUID {
			id := uuid.New()
			_, err := osDAO.Create(ctx, nil, cdbm.OperatingSystemCreateInput{
				ID:                       id,
				Name:                     name,
				Org:                      st.Org,
				InfrastructureProviderID: &ip.ID,
				OsType:                   cdbm.OperatingSystemTypeIPXE,
				IpxeScript:               cutil.GetPtr("#!ipxe\n"),
				IpxeOsScope:              cutil.GetPtr(cdbm.OperatingSystemScopeLocal),
				Status:                   cdbm.OperatingSystemStatusReady,
				CreatedBy:                ipu.ID,
			})
			require.NoError(t, err)
			_, err = ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
				OperatingSystemID: id, SiteID: st.ID, Status: cdbm.OperatingSystemSiteAssociationStatusSynced, CreatedBy: ipu.ID,
			})
			require.NoError(t, err)
			return id
		}
		osA := mkOS("paged-os-a")
		osB := mkOS("paged-os-b")
		osC := mkOS("paged-os-c") // absent from the reported set: must be deleted, but only after the final page

		reportedProto := func(id uuid.UUID, name string) *corev1.OperatingSystem {
			return &corev1.OperatingSystem{
				Id:         &corev1.OperatingSystemId{Value: id.String()},
				Name:       name,
				Type:       corev1.OperatingSystemType_OS_TYPE_IPXE,
				Status:     corev1.TenantState_READY,
				IsActive:   true,
				IpxeScript: cutil.GetPtr("#!ipxe\n"),
				Updated:    time.Now().Format(time.RFC3339),
			}
		}

		// The full reported set (spans both pages) travels in every page's ItemIds.
		itemIDs := []string{osA.String(), osB.String()}

		// Page 1 of 2 reports only osA, but ItemIds carries the full set {osA, osB}.
		page1 := &corev1.OperatingSystemInventory{
			InventoryStatus:  corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			OperatingSystems: []*corev1.OperatingSystem{reportedProto(osA, "paged-os-a")},
			Timestamp:        timestamppb.Now(),
			InventoryPage:    &corev1.InventoryPage{CurrentPage: 1, TotalPages: 2, PageSize: 1, TotalItems: 2, ItemIds: itemIDs},
		}
		require.NoError(t, newManageOsImage().UpdateOperatingSystemsInDB(ctx, st.ID, page1))

		// After page 1, no deletion may have run: osC (absent from ItemIds) and osB
		// (absent from page 1's OperatingSystems) must both still exist.
		_, err := osDAO.GetByID(ctx, nil, osC, nil)
		require.NoError(t, err, "osC must not be deleted before the final page")
		_, err = osDAO.GetByID(ctx, nil, osB, nil)
		require.NoError(t, err, "osB must not be deleted by an earlier page that omits it from OperatingSystems")

		// Page 2 of 2 (final) reports osB; ItemIds still carries the full set {osA, osB}.
		page2 := &corev1.OperatingSystemInventory{
			InventoryStatus:  corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			OperatingSystems: []*corev1.OperatingSystem{reportedProto(osB, "paged-os-b")},
			Timestamp:        timestamppb.Now(),
			InventoryPage:    &corev1.InventoryPage{CurrentPage: 2, TotalPages: 2, PageSize: 1, TotalItems: 2, ItemIds: itemIDs},
		}
		require.NoError(t, newManageOsImage().UpdateOperatingSystemsInDB(ctx, st.ID, page2))

		// Final page: deletion runs against the full ItemIds set. osA and osB survive; osC is gone.
		_, err = osDAO.GetByID(ctx, nil, osA, nil)
		require.NoError(t, err, "osA reported in ItemIds must survive")
		_, err = osDAO.GetByID(ctx, nil, osB, nil)
		require.NoError(t, err, "osB reported in ItemIds must survive")
		_, err = osDAO.GetByID(ctx, nil, osC, nil)
		assert.ErrorIs(t, err, cdb.ErrDoesNotExist, "osC absent from the full reported set must be soft-deleted on the final page")
	})

	t.Run("returns error for nil inventory", func(t *testing.T) {
		ip := util.TestBuildInfrastructureProvider(t, dbSession, "provider-nil", "provider-nil-org", ipu)
		st := util.TestBuildSite(t, dbSession, ip, "site-nil", cdbm.SiteStatusRegistered, nil, ipu)

		err := newManageOsImage().UpdateOperatingSystemsInDB(ctx, st.ID, nil)
		assert.Error(t, err)
	})
}

func TestNewManageOsImage(t *testing.T) {
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
		want ManageOsImage
	}{
		{
			name: "test new ManageOsImage instantiation",
			args: args{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
			want: ManageOsImage{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewManageOsImage(tt.args.dbSession, tt.args.siteClientPool); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewManageOsImage() = %v, want %v", got, tt.want)
			}
		})
	}
}
