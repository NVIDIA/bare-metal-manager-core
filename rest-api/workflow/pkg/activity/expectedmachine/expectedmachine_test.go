// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package expectedmachine

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller-rest/workflow/pkg/util"
	"go.temporal.io/sdk/testsuite"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun/extra/bundebug"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	cdbu "github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	"github.com/NVIDIA/infra-controller-rest/workflow/internal/config"
	sc "github.com/NVIDIA/infra-controller-rest/workflow/pkg/client/site"
	cwu "github.com/NVIDIA/infra-controller-rest/workflow/pkg/util"

	cwutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
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

func testExpectedMachineInitDB(t *testing.T) *cdb.Session {
	dbSession := cdbu.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("BUNDEBUG"),
	))
	return dbSession
}

func testExpectedMachineSetupSchema(t *testing.T, dbSession *cdb.Session) {
	// create Infrastructure Provider table
	err := dbSession.DB.ResetModel(context.Background(), (*cdbm.InfrastructureProvider)(nil))
	assert.Nil(t, err)
	// create Site table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.Site)(nil))
	assert.Nil(t, err)
	// create SKU table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.SKU)(nil))
	assert.Nil(t, err)
	// create ExpectedMachine table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.ExpectedMachine)(nil))
	assert.Nil(t, err)
	// create User table
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil))
	assert.Nil(t, err)
}

func TestManageExpectedMachine_UpdateExpectedMachinesInDB(t *testing.T) {
	ctx := context.Background()

	dbSession := testExpectedMachineInitDB(t)
	defer dbSession.Close()

	testExpectedMachineSetupSchema(t, dbSession)

	ipOrg := "test-provider-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := cwu.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)
	ip := cwu.TestBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)

	// Build Sites
	st := cwu.TestBuildSite(t, dbSession, ip, "test-site", cdbm.SiteStatusRegistered, nil, ipu)
	st2 := cwu.TestBuildSite(t, dbSession, ip, "test-site-2", cdbm.SiteStatusRegistered, nil, ipu)
	st3 := cwu.TestBuildSite(t, dbSession, ip, "test-site-3", cdbm.SiteStatusRegistered, nil, ipu)

	// Build ExpectedMachine inventory that is paginated
	// Generate data for 34 ExpectedMachines reported from Site Agent while Cloud has 38 ExpectedMachines
	pagedExpectedMachines := []*cdbm.ExpectedMachine{}
	pagedInvIds := []string{}

	emDAO := cdbm.NewExpectedMachineDAO(dbSession)
	for i := 0; i < 38; i++ {
		emID := uuid.New()
		// Add labels to some machines to test label handling
		var labels map[string]string
		if i%5 == 0 {
			labels = map[string]string{
				"rack":     fmt.Sprintf("rack-%d", i/5),
				"position": fmt.Sprintf("pos-%d", i),
			}
		}
		em, cerr := emDAO.Create(ctx, nil, cdbm.ExpectedMachineCreateInput{
			ExpectedMachineID:        emID,
			SiteID:                   st.ID,
			BmcMacAddress:            fmt.Sprintf("00:11:22:33:44:%02d", i),
			ChassisSerialNumber:      fmt.Sprintf("SN-%d", i),
			SkuID:                    nil,
			FallbackDpuSerialNumbers: []string{fmt.Sprintf("DPU-%d", i)},
			Labels:                   labels,
			CreatedBy:                ipu.ID,
		})
		assert.NoError(t, cerr)

		// Update creation and update timestamp to be earlier than inventory processing interval
		_, uerr := dbSession.DB.Exec("UPDATE expected_machine SET created = ?, updated = ? WHERE id = ?",
			time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval*2)),
			time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval*2)),
			em.ID.String())
		assert.NoError(t, uerr)

		pagedExpectedMachines = append(pagedExpectedMachines, em)
		pagedInvIds = append(pagedInvIds, em.ID.String())
	}

	expectedMachinesToUpdate := []*cdbm.ExpectedMachine{}
	pagedCtrlExpectedMachines := []*cwssaws.ExpectedMachine{}

	for i := 0; i < 34; i++ {
		ctrlExpectedMachine := &cwssaws.ExpectedMachine{
			Id:                       &cwssaws.UUID{Value: pagedExpectedMachines[i].ID.String()},
			BmcMacAddress:            pagedExpectedMachines[i].BmcMacAddress,
			ChassisSerialNumber:      pagedExpectedMachines[i].ChassisSerialNumber,
			SkuId:                    pagedExpectedMachines[i].SkuID,
			FallbackDpuSerialNumbers: pagedExpectedMachines[i].FallbackDpuSerialNumbers,
		}

		// Add labels to controller expected machines
		if i%5 == 0 {
			ctrlExpectedMachine.Metadata = &cwssaws.Metadata{
				Labels: []*cwssaws.Label{
					{Key: "rack", Value: cdb.GetStrPtr(fmt.Sprintf("rack-%d", i/5))},
					{Key: "position", Value: cdb.GetStrPtr(fmt.Sprintf("pos-%d", i))},
				},
			}
		}

		// Have entries that need updates
		if i%3 == 0 {
			if i < 20 {
				ctrlExpectedMachine.BmcMacAddress = fmt.Sprintf("00:11:22:33:55:%02d", i) // Changed MAC
				expectedMachinesToUpdate = append(expectedMachinesToUpdate, pagedExpectedMachines[i])
			}
		}

		// Test label updates: add/modify labels for some machines
		if i == 1 {
			// Add labels to a machine that didn't have them before
			ctrlExpectedMachine.Metadata = &cwssaws.Metadata{
				Labels: []*cwssaws.Label{
					{Key: "new-label", Value: cdb.GetStrPtr("new-value")},
				},
			}
			expectedMachinesToUpdate = append(expectedMachinesToUpdate, pagedExpectedMachines[i])
		} else if i == 5 {
			// Modify existing labels
			ctrlExpectedMachine.Metadata = &cwssaws.Metadata{
				Labels: []*cwssaws.Label{
					{Key: "rack", Value: cdb.GetStrPtr(fmt.Sprintf("rack-updated-%d", i/5))},
					{Key: "position", Value: cdb.GetStrPtr(fmt.Sprintf("pos-%d", i))},
					{Key: "status", Value: cdb.GetStrPtr("active")},
				},
			}
			expectedMachinesToUpdate = append(expectedMachinesToUpdate, pagedExpectedMachines[i])
		} else if i == 10 {
			// Remove labels (set to empty labels array)
			ctrlExpectedMachine.Metadata = &cwssaws.Metadata{
				Labels: []*cwssaws.Label{},
			}
			expectedMachinesToUpdate = append(expectedMachinesToUpdate, pagedExpectedMachines[i])
		} else if i == 15 {
			// Remove labels (set metadata to nil)
			ctrlExpectedMachine.Metadata = nil
			expectedMachinesToUpdate = append(expectedMachinesToUpdate, pagedExpectedMachines[i])
		}

		pagedCtrlExpectedMachines = append(pagedCtrlExpectedMachines, ctrlExpectedMachine)
	}

	expectedMachinesToDelete := pagedExpectedMachines[34:38]

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
		ctx                      context.Context
		siteID                   uuid.UUID
		expectedMachineInventory *cwssaws.ExpectedMachineInventory
	}

	tests := []struct {
		name                     string
		fields                   fields
		args                     args
		expectedMachinesToUpdate []*cdbm.ExpectedMachine
		expectedMachinesToDelete []*cdbm.ExpectedMachine
		wantErr                  bool
	}{
		{
			name: "test ExpectedMachine inventory processing error, nil inventory",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:                      ctx,
				siteID:                   st.ID,
				expectedMachineInventory: nil,
			},
			wantErr: true,
		},
		{
			name: "test ExpectedMachine inventory processing error, non-existent Site",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: uuid.New(),
				expectedMachineInventory: &cwssaws.ExpectedMachineInventory{
					ExpectedMachines: []*cwssaws.ExpectedMachine{},
				},
			},
			wantErr: true,
		},
		{
			name: "test ExpectedMachine inventory processing, failed inventory status",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st.ID,
				expectedMachineInventory: &cwssaws.ExpectedMachineInventory{
					ExpectedMachines: []*cwssaws.ExpectedMachine{},
					Timestamp:        timestamppb.Now(),
					InventoryStatus:  cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED,
				},
			},
			wantErr: false,
		},
		{
			name: "test paged ExpectedMachine inventory processing, empty inventory",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st2.ID,
				expectedMachineInventory: &cwssaws.ExpectedMachineInventory{
					ExpectedMachines: []*cwssaws.ExpectedMachine{},
					Timestamp:        timestamppb.Now(),
					InventoryStatus:  cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
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
			name: "test paged ExpectedMachine inventory processing, first page",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st.ID,
				expectedMachineInventory: &cwssaws.ExpectedMachineInventory{
					ExpectedMachines: pagedCtrlExpectedMachines[0:20],
					Timestamp:        timestamppb.Now(),
					InventoryStatus:  cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 1,
						TotalPages:  2,
						PageSize:    20,
						TotalItems:  34,
						ItemIds:     pagedInvIds[0:34],
					},
				},
			},
			expectedMachinesToUpdate: expectedMachinesToUpdate,
			expectedMachinesToDelete: []*cdbm.ExpectedMachine{},
		},
		{
			name: "test paged ExpectedMachine inventory processing, last page",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st.ID,
				expectedMachineInventory: &cwssaws.ExpectedMachineInventory{
					ExpectedMachines: pagedCtrlExpectedMachines[20:34],
					Timestamp:        timestamppb.Now(),
					InventoryStatus:  cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
					InventoryPage: &cwssaws.InventoryPage{
						CurrentPage: 2,
						TotalPages:  2,
						PageSize:    20,
						TotalItems:  34,
						ItemIds:     pagedInvIds[0:34],
					},
				},
			},
			expectedMachinesToUpdate: []*cdbm.ExpectedMachine{},
			expectedMachinesToDelete: expectedMachinesToDelete,
		},
		{
			name: "test non-paged ExpectedMachine inventory processing",
			fields: fields{
				dbSession:      dbSession,
				siteClientPool: tSiteClientPool,
				env:            env,
			},
			args: args{
				ctx:    ctx,
				siteID: st3.ID,
				expectedMachineInventory: &cwssaws.ExpectedMachineInventory{
					ExpectedMachines: []*cwssaws.ExpectedMachine{
						{
							Id:                  &cwssaws.UUID{Value: uuid.New().String()},
							BmcMacAddress:       "00:11:22:33:44:FF",
							ChassisSerialNumber: "SN-NEW-1",
							SkuId:               nil,
							Metadata: &cwssaws.Metadata{
								Labels: []*cwssaws.Label{
									{Key: "environment", Value: cdb.GetStrPtr("test")},
									{Key: "datacenter", Value: cdb.GetStrPtr("dc1")},
								},
							},
						},
					},
					Timestamp:       timestamppb.Now(),
					InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
				},
			},
			expectedMachinesToUpdate: []*cdbm.ExpectedMachine{},
			expectedMachinesToDelete: []*cdbm.ExpectedMachine{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mei := ManageExpectedMachine{
				dbSession:      tt.fields.dbSession,
				siteClientPool: tt.fields.siteClientPool,
			}

			err := mei.UpdateExpectedMachinesInDB(tt.args.ctx, tt.args.siteID, tt.args.expectedMachineInventory)
			assert.Equal(t, tt.wantErr, err != nil)

			if tt.wantErr {
				return
			}

			// Verify updates by fetching all machines for the site
			emDAO := cdbm.NewExpectedMachineDAO(dbSession)
			filterInput := cdbm.ExpectedMachineFilterInput{SiteIDs: []uuid.UUID{tt.args.siteID}}
			allMachines, _, gerr := emDAO.GetAll(ctx, nil, filterInput, cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)}, nil)
			assert.NoError(t, gerr)

			// Build a map of machines by ID for easy lookup
			machinesByID := map[uuid.UUID]*cdbm.ExpectedMachine{}
			for i := range allMachines {
				machinesByID[allMachines[i].ID] = &allMachines[i]
			}

			for _, em := range tt.expectedMachinesToUpdate {
				updated := machinesByID[em.ID]
				assert.NotNil(t, updated, fmt.Sprintf("ExpectedMachine %v should exist", em.ID))
				// Find the corresponding controller machine
				var ctrlEM *cwssaws.ExpectedMachine
				for _, cem := range tt.args.expectedMachineInventory.ExpectedMachines {
					if cem.Id.Value == em.ID.String() {
						ctrlEM = cem
						break
					}
				}
				if ctrlEM != nil {
					assert.Equal(t, ctrlEM.BmcMacAddress, updated.BmcMacAddress,
						fmt.Sprintf("ExpectedMachine %v should have been updated", em.ID))

					// Verify labels are updated correctly
					var expectedLabels cdbm.Labels
					expectedLabels.FromProto(ctrlEM.Metadata.GetLabels())
					// Both nil and empty maps should be treated as equivalent (no labels)
					if len(expectedLabels) == 0 && len(updated.Labels) == 0 {
						// Both are effectively empty, which is correct
					} else {
						assert.Equal(t, expectedLabels, updated.Labels,
							fmt.Sprintf("ExpectedMachine %v labels should match", em.ID))
					}
				}
			}

			// Verify deletions
			for _, em := range tt.expectedMachinesToDelete {
				deleted := machinesByID[em.ID]
				assert.Nil(t, deleted, fmt.Sprintf("ExpectedMachine %v should have been deleted", em.ID))
			}

			// Verify newly created machines have correct labels
			for _, cem := range tt.args.expectedMachineInventory.ExpectedMachines {
				emID, perr := uuid.Parse(cem.Id.Value)
				assert.NoError(t, perr)
				created := machinesByID[emID]
				if created != nil {
					var expectedLabels cdbm.Labels
					expectedLabels.FromProto(cem.Metadata.GetLabels())
					// Both nil and empty maps should be treated as equivalent (no labels)
					if len(expectedLabels) == 0 && len(created.Labels) == 0 {
						// Both are effectively empty, which is correct
					} else {
						assert.Equal(t, expectedLabels, created.Labels,
							fmt.Sprintf("ExpectedMachine %v labels should match on creation", emID))
					}
				}
			}
		})
	}
}

func TestManageExpectedMachine_UpdateExpectedMachinesInDB_RaceCondition(t *testing.T) {
	ctx := context.Background()

	dbSession := testExpectedMachineInitDB(t)
	defer dbSession.Close()

	testExpectedMachineSetupSchema(t, dbSession)

	ipOrg := "test-provider-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := cwu.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)
	ip := cwu.TestBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)
	st := cwu.TestBuildSite(t, dbSession, ip, "test-site-race", cdbm.SiteStatusRegistered, nil, ipu)

	// Create an ExpectedMachine: newly create record will have a timestamp within race condition window
	emDAO := cdbm.NewExpectedMachineDAO(dbSession)
	recentEM, err := emDAO.Create(ctx, nil, cdbm.ExpectedMachineCreateInput{
		ExpectedMachineID:   uuid.New(),
		SiteID:              st.ID,
		BmcMacAddress:       "00:11:22:33:44:AA",
		ChassisSerialNumber: "SN-RECENT",
		CreatedBy:           ipu.ID,
	})
	assert.NoError(t, err)

	tSiteClientPool := testTemporalSiteClientPool(t)

	mei := ManageExpectedMachine{
		dbSession:      dbSession,
		siteClientPool: tSiteClientPool,
	}

	// Send inventory without this machine - it should NOT be deleted due to race condition
	inventory := &cwssaws.ExpectedMachineInventory{
		ExpectedMachines: []*cwssaws.ExpectedMachine{},
		Timestamp:        timestamppb.Now(),
		InventoryStatus:  cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
	}

	err = mei.UpdateExpectedMachinesInDB(ctx, st.ID, inventory)
	assert.NoError(t, err)

	// Verify the machine was NOT deleted
	filterInput := cdbm.ExpectedMachineFilterInput{SiteIDs: []uuid.UUID{st.ID}}
	allMachines, _, gerr := emDAO.GetAll(ctx, nil, filterInput, cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)}, nil)
	assert.NoError(t, gerr)

	// Check if the recent machine still exists
	found := false
	for _, em := range allMachines {
		if em.ID == recentEM.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "Recently updated ExpectedMachine should NOT be deleted due to race condition")
}

func TestNewManageExpectedMachine(t *testing.T) {
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
		want ManageExpectedMachine
	}{
		{
			name: "test new ManageExpectedMachine instantiation",
			args: args{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
			want: ManageExpectedMachine{
				dbSession:      dbSession,
				siteClientPool: scp,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewManageExpectedMachine(tt.args.dbSession, tt.args.siteClientPool)
			assert.Equal(t, tt.want.dbSession, got.dbSession, "dbSession should match")
			assert.Equal(t, tt.want.siteClientPool, got.siteClientPool, "siteClientPool should match")
		})
	}
}

func TestStaleInventoryThresholdCondition(t *testing.T) {
	tests := []struct {
		name       string
		actionTime time.Time
		want       bool
	}{
		{
			name:       "recent action within stale inventory threshold",
			actionTime: time.Now(),
			want:       true,
		},
		{
			name:       "action just outside stale inventory threshold",
			actionTime: time.Now().Add(-time.Duration(cwutil.InventoryReceiptInterval + time.Second*15)),
			want:       false,
		},
		{
			name:       "old action well outside stale inventory threshold",
			actionTime: time.Now().Add(-time.Hour),
			want:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := util.IsTimeWithinStaleInventoryThreshold(tt.actionTime); got != tt.want {
				t.Errorf("IsTimeWithinStaleInventoryThreshold() = %v, want %v", got, tt.want)
			}
		})
	}
}
