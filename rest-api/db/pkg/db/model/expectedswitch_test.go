// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	otrace "go.opentelemetry.io/otel/trace"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
)

func TestExpectedSwitch_FromProto(t *testing.T) {
	id := uuid.New()
	rackID := "rack-1"
	name := "sw-1"
	manufacturer := "ACME"
	model := "SW1"
	description := "primary"
	firmware := "1.2.3"
	var slot, trayIdx, host int32 = 1, 2, 3

	t.Run("nil proto leaves receiver unchanged", func(t *testing.T) {
		es := &ExpectedSwitch{ID: id, BmcMacAddress: "aa:bb"}
		es.FromProto(nil)

		assert.Equal(t, id, es.ID)
		assert.Equal(t, "aa:bb", es.BmcMacAddress)
	})

	t.Run("invalid id leaves es.ID unchanged", func(t *testing.T) {
		es := &ExpectedSwitch{ID: id}
		es.FromProto(&cwssaws.ExpectedSwitch{
			ExpectedSwitchId: &cwssaws.UUID{Value: "not-a-uuid"},
			BmcMacAddress:    "aa:bb",
		})

		assert.Equal(t, id, es.ID)
		assert.Equal(t, "aa:bb", es.BmcMacAddress)
	})

	t.Run("populates all proto fields", func(t *testing.T) {
		es := &ExpectedSwitch{}
		es.FromProto(&cwssaws.ExpectedSwitch{
			ExpectedSwitchId:   &cwssaws.UUID{Value: id.String()},
			BmcMacAddress:      "aa:bb:cc:dd:ee:ff",
			SwitchSerialNumber: "SSN-1",
			BmcIpAddress:       "10.0.0.1",
			RackId:             &cwssaws.RackId{Id: rackID},
			Name:               &name,
			Manufacturer:       &manufacturer,
			Model:              &model,
			Description:        &description,
			FirmwareVersion:    &firmware,
			SlotId:             &slot,
			TrayIdx:            &trayIdx,
			HostId:             &host,
			Metadata: &cwssaws.Metadata{
				Labels: []*cwssaws.Label{
					{Key: "env", Value: db.GetStrPtr("prod")},
				},
			},
		})

		assert.Equal(t, id, es.ID)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", es.BmcMacAddress)
		assert.Equal(t, "SSN-1", es.SwitchSerialNumber)
		if assert.NotNil(t, es.BmcIpAddress) {
			assert.Equal(t, "10.0.0.1", *es.BmcIpAddress)
		}
		if assert.NotNil(t, es.RackID) {
			assert.Equal(t, rackID, *es.RackID)
		}
		assert.Equal(t, &name, es.Name)
		assert.Equal(t, &manufacturer, es.Manufacturer)
		assert.Equal(t, &model, es.Model)
		assert.Equal(t, &description, es.Description)
		assert.Equal(t, &firmware, es.FirmwareVersion)
		assert.Equal(t, &slot, es.SlotID)
		assert.Equal(t, &trayIdx, es.TrayIdx)
		assert.Equal(t, &host, es.HostID)
		assert.Equal(t, Labels{"env": "prod"}, es.Labels)
	})

	t.Run("empty BmcIpAddress yields nil pointer", func(t *testing.T) {
		es := &ExpectedSwitch{BmcIpAddress: db.GetStrPtr("stale")}
		es.FromProto(&cwssaws.ExpectedSwitch{
			ExpectedSwitchId: &cwssaws.UUID{Value: id.String()},
			BmcIpAddress:     "",
		})

		assert.Nil(t, es.BmcIpAddress)
	})

	t.Run("nil RackId clears es.RackID", func(t *testing.T) {
		stale := "stale-rack"
		es := &ExpectedSwitch{RackID: &stale}
		es.FromProto(&cwssaws.ExpectedSwitch{
			ExpectedSwitchId: &cwssaws.UUID{Value: id.String()},
			BmcMacAddress:    "aa:bb",
		})

		assert.Nil(t, es.RackID)
	})
}

// reset the tables needed for ExpectedSwitch tests
func testExpectedSwitchSetupSchema(t *testing.T, dbSession *db.Session) {
	ctx := context.Background()
	// create User table
	err := dbSession.DB.ResetModel(ctx, (*User)(nil))
	assert.Nil(t, err)
	// create InfrastructureProvider table
	err = dbSession.DB.ResetModel(ctx, (*InfrastructureProvider)(nil))
	assert.Nil(t, err)
	// create Site table
	err = dbSession.DB.ResetModel(ctx, (*Site)(nil))
	assert.Nil(t, err)
	// create ExpectedSwitch table
	err = dbSession.DB.ResetModel(ctx, (*ExpectedSwitch)(nil))
	assert.Nil(t, err)
}

func TestExpectedSwitchSQLDAO_Create(t *testing.T) {
	ctx := context.Background()
	dbSession := testInitDB(t)
	defer dbSession.Close()
	testExpectedSwitchSetupSchema(t, dbSession)

	// Create test dependencies
	user := TestBuildUser(t, dbSession, "test-user", "test-org", []string{"admin"})
	ip := TestBuildInfrastructureProvider(t, dbSession, "test-provider", "test-org", user)
	site := TestBuildSite(t, dbSession, ip, "test-site", user)

	essd := NewExpectedSwitchDAO(dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		inputs             []ExpectedSwitchCreateInput
		expectError        bool
		errorContains      string
		verifyChildSpanner bool
	}{
		{
			desc: "create one",
			inputs: []ExpectedSwitchCreateInput{
				{
					ExpectedSwitchID:   uuid.New(),
					SiteID:             site.ID,
					BmcMacAddress:      "00:1B:44:11:3A:B7",
					SwitchSerialNumber: "SWITCH123",
					BmcIpAddress:       db.GetStrPtr("192.168.1.10"),
					Labels: map[string]string{
						"environment": "test",
						"location":    "datacenter1",
					},
					CreatedBy: user.ID,
				},
			},
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc: "create multiple, some with nullable fields",
			inputs: []ExpectedSwitchCreateInput{
				{
					ExpectedSwitchID:   uuid.New(),
					SiteID:             site.ID,
					BmcMacAddress:      "00:1B:44:11:3A:B8",
					SwitchSerialNumber: "SWITCH789",
					Labels: map[string]string{
						"environment": "production",
					},
					CreatedBy: user.ID,
				},
				{
					ExpectedSwitchID:   uuid.New(),
					SiteID:             site.ID,
					BmcMacAddress:      "00:1B:44:11:3A:B9",
					SwitchSerialNumber: "SWITCH456",
					Labels:             nil,
					CreatedBy:          user.ID,
				},
			},
			expectError: false,
		},
		{
			desc: "fail to create with non-existent site",
			inputs: []ExpectedSwitchCreateInput{
				{
					ExpectedSwitchID:   uuid.New(),
					SiteID:             uuid.New(),
					BmcMacAddress:      "00:1B:44:11:3A:C0",
					SwitchSerialNumber: "SWITCH-NOSITE",
					CreatedBy:          user.ID,
				},
			},
			expectError:   true,
			errorContains: "violates foreign key constraint",
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			for _, input := range tc.inputs {
				es, err := essd.Create(ctx, nil, input)
				if err != nil {
					assert.True(t, tc.expectError, "Expected error but got none")
					assert.Nil(t, es)
					if tc.errorContains != "" {
						assert.Contains(t, err.Error(), tc.errorContains, "Error should contain expected substring")
					}
				} else {
					assert.False(t, tc.expectError, "Expected success but got error: %v", err)
					assert.NotNil(t, es)
					assert.Equal(t, input.BmcMacAddress, es.BmcMacAddress)
					assert.Equal(t, input.SwitchSerialNumber, es.SwitchSerialNumber)
					assert.Equal(t, input.BmcIpAddress, es.BmcIpAddress)
					assert.Equal(t, Labels(input.Labels), es.Labels)
				}

				if tc.verifyChildSpanner {
					span := otrace.SpanFromContext(ctx)
					assert.True(t, span.SpanContext().IsValid())
					_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
					assert.True(t, ok)
				}

				if err != nil {
					t.Logf("%s", err.Error())
					return
				}
			}
		})
	}
}

func testExpectedSwitchSQLDAOCreateExpectedSwitches(ctx context.Context, t *testing.T, dbSession *db.Session) (created []ExpectedSwitch) {
	// Create test dependencies
	user := TestBuildUser(t, dbSession, "test-user", "test-org", []string{"admin"})
	ip := TestBuildInfrastructureProvider(t, dbSession, "test-provider", "test-org", user)
	site := TestBuildSite(t, dbSession, ip, "test-site", user)

	var createInputs []ExpectedSwitchCreateInput
	{
		// ExpectedSwitch set 1
		createInputs = append(createInputs, ExpectedSwitchCreateInput{
			ExpectedSwitchID:   uuid.New(),
			SiteID:             site.ID,
			BmcMacAddress:      "00:1B:44:11:3A:B7",
			SwitchSerialNumber: "SWITCH123",
			Labels: map[string]string{
				"environment": "test",
				"location":    "datacenter1",
			},
			CreatedBy: user.ID,
		})

		// ExpectedSwitch set 2
		createInputs = append(createInputs, ExpectedSwitchCreateInput{
			ExpectedSwitchID:   uuid.New(),
			SiteID:             site.ID,
			BmcMacAddress:      "00:1B:44:11:3A:B8",
			SwitchSerialNumber: "SWITCH789",
			Labels: map[string]string{
				"environment": "production",
			},
			CreatedBy: user.ID,
		})

		// ExpectedSwitch set 3
		createInputs = append(createInputs, ExpectedSwitchCreateInput{
			ExpectedSwitchID:   uuid.New(),
			SiteID:             site.ID,
			BmcMacAddress:      "00:1B:44:11:3A:B9",
			SwitchSerialNumber: "SWITCH456",
			Labels:             nil,
			CreatedBy:          user.ID,
		})
	}

	essd := NewExpectedSwitchDAO(dbSession)

	// ExpectedSwitch created
	for _, input := range createInputs {
		esCre, _ := essd.Create(ctx, nil, input)
		assert.NotNil(t, esCre)
		created = append(created, *esCre)
	}

	return
}

func TestExpectedSwitchSQLDAO_GetByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testInitDB(t)
	defer dbSession.Close()
	testExpectedSwitchSetupSchema(t, dbSession)

	essExp := testExpectedSwitchSQLDAOCreateExpectedSwitches(ctx, t, dbSession)
	essd := NewExpectedSwitchDAO(dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		es                 ExpectedSwitch
		expectError        bool
		expectedErrVal     error
		verifyChildSpanner bool
	}{
		{
			desc:               "GetById success when ExpectedSwitch exists on [0]",
			es:                 essExp[0],
			expectError:        false,
			verifyChildSpanner: true,
		},
		{
			desc:        "GetById success when ExpectedSwitch exists on [1]",
			es:          essExp[1],
			expectError: false,
		},
		{
			desc: "GetById success when ExpectedSwitch not found",
			es: ExpectedSwitch{
				ID: uuid.New(),
			},
			expectError:    true,
			expectedErrVal: db.ErrDoesNotExist,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			tmp, err := essd.Get(ctx, nil, tc.es.ID, nil, false)
			assert.Equal(t, tc.expectError, err != nil)
			if tc.expectError {
				assert.Equal(t, tc.expectedErrVal, err)
			}
			if err == nil {
				assert.Equal(t, tc.es.ID, tmp.ID)
				assert.Equal(t, tc.es.BmcMacAddress, tmp.BmcMacAddress)
				assert.Equal(t, tc.es.SwitchSerialNumber, tmp.SwitchSerialNumber)
				assert.Equal(t, tc.es.Labels, tmp.Labels)
			} else {
				t.Logf("%s", err.Error())
			}

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestExpectedSwitchSQLDAO_Get_includeRelations(t *testing.T) {
	ctx := context.Background()
	dbSession := testInitDB(t)
	defer dbSession.Close()
	testExpectedSwitchSetupSchema(t, dbSession)

	created := testExpectedSwitchSQLDAOCreateExpectedSwitches(ctx, t, dbSession)
	req := NewExpectedSwitchDAO(dbSession)

	got, err := req.Get(ctx, nil, created[1].ID, []string{SiteRelationName}, false)
	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.NotNil(t, got.Site)
}

func TestExpectedSwitchSQLDAO_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := testInitDB(t)
	defer dbSession.Close()
	testExpectedSwitchSetupSchema(t, dbSession)

	essd := NewExpectedSwitchDAO(dbSession)

	// Create test data
	created := testExpectedSwitchSQLDAOCreateExpectedSwitches(ctx, t, dbSession)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		filter             ExpectedSwitchFilterInput
		pageInput          paginator.PageInput
		expectedCount      int
		expectedTotal      *int
		expectedError      bool
		verifyChildSpanner bool
	}{
		{
			desc:               "GetAll with no filters returns all objects",
			expectedCount:      3,
			expectedTotal:      db.GetIntPtr(3),
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc: "GetAll with SiteIDs filter returns objects",
			filter: ExpectedSwitchFilterInput{
				SiteIDs: []uuid.UUID{created[0].SiteID},
			},
			expectedCount: 3,
			expectedError: false,
		},
		{
			desc: "GetAll with BmcMacAddresses filter returns objects",
			filter: ExpectedSwitchFilterInput{
				BmcMacAddresses: []string{created[0].BmcMacAddress},
			},
			expectedCount: 1,
			expectedError: false,
		},
		{
			desc: "GetAll with SwitchSerialNumbers filter returns objects",
			filter: ExpectedSwitchFilterInput{
				SwitchSerialNumbers: []string{created[0].SwitchSerialNumber},
			},
			expectedCount: 1,
			expectedError: false,
		},
		{
			desc: "GetAll with search query filter returns objects",
			filter: ExpectedSwitchFilterInput{
				SearchQuery: db.GetStrPtr("SWITCH123"),
			},
			expectedCount: 1,
			expectedError: false,
		},
		{
			desc: "GetAll with ExpectedSwitchIDs filter returns objects",
			filter: ExpectedSwitchFilterInput{
				ExpectedSwitchIDs: []uuid.UUID{created[0].ID, created[2].ID},
			},
			expectedCount: 2,
			expectedError: false,
		},
		{
			desc: "GetAll with limit returns objects",
			pageInput: paginator.PageInput{
				Offset: db.GetIntPtr(0),
				Limit:  db.GetIntPtr(2),
			},
			expectedCount: 2,
			expectedTotal: db.GetIntPtr(3),
			expectedError: false,
		},
		{
			desc: "GetAll with offset returns objects",
			pageInput: paginator.PageInput{
				Offset: db.GetIntPtr(1),
			},
			expectedCount: 2,
			expectedTotal: db.GetIntPtr(3),
			expectedError: false,
		},
		{
			desc: "GetAll with order by returns objects",
			pageInput: paginator.PageInput{
				OrderBy: &paginator.OrderBy{
					Field: "created",
					Order: paginator.OrderDescending,
				},
			},
			expectedCount: 3,
			expectedTotal: db.GetIntPtr(3),
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, total, err := essd.GetAll(ctx, nil, tc.filter, tc.pageInput, nil)
			if err != nil {
				t.Logf("%s", err.Error())
			}

			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				assert.Equal(t, nil, got)
			} else {
				assert.Equal(t, tc.expectedCount, len(got))
			}

			if tc.expectedTotal != nil {
				assert.Equal(t, *tc.expectedTotal, total)
			}

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestExpectedSwitchSQLDAO_GetAll_includeRelations(t *testing.T) {
	ctx := context.Background()
	dbSession := testInitDB(t)
	defer dbSession.Close()
	testExpectedSwitchSetupSchema(t, dbSession)

	req := NewExpectedSwitchDAO(dbSession)
	_ = testExpectedSwitchSQLDAOCreateExpectedSwitches(ctx, t, dbSession)

	got, _, err := req.GetAll(ctx, nil, ExpectedSwitchFilterInput{}, paginator.PageInput{}, []string{SiteRelationName})
	assert.NoError(t, err)
	assert.Equal(t, 3, len(got))

	for _, es := range got {
		assert.NotNil(t, es.Site)
	}
}

func TestExpectedSwitchSQLDAO_Update(t *testing.T) {
	ctx := context.Background()
	dbSession := testInitDB(t)
	defer dbSession.Close()
	testExpectedSwitchSetupSchema(t, dbSession)

	essExp := testExpectedSwitchSQLDAOCreateExpectedSwitches(ctx, t, dbSession)
	essd := NewExpectedSwitchDAO(dbSession)
	assert.NotNil(t, essd)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		input              ExpectedSwitchUpdateInput
		expectedError      bool
		verifyChildSpanner bool
	}{
		{
			desc: "Update BMC MAC address",
			input: ExpectedSwitchUpdateInput{
				ExpectedSwitchID: essExp[0].ID,
				BmcMacAddress:    db.GetStrPtr("00:1B:44:11:3A:C1"),
			},
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc: "Update switch serial number",
			input: ExpectedSwitchUpdateInput{
				ExpectedSwitchID:   essExp[1].ID,
				SwitchSerialNumber: db.GetStrPtr("NEWSWITCH789"),
			},
			expectedError: false,
		},
		{
			desc: "Update labels",
			input: ExpectedSwitchUpdateInput{
				ExpectedSwitchID: essExp[0].ID,
				Labels: map[string]string{
					"environment": "staging",
					"owner":       "team-alpha",
				},
			},
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := essd.Update(ctx, nil, tc.input)
			assert.Equal(t, tc.expectedError, err != nil)
			if err != nil {
				t.Logf("%s", err.Error())
			}
			if !tc.expectedError {
				assert.Nil(t, err)
				assert.NotNil(t, got)
				if tc.input.BmcMacAddress != nil {
					assert.Equal(t, *tc.input.BmcMacAddress, got.BmcMacAddress)
				}
				if tc.input.SwitchSerialNumber != nil {
					assert.Equal(t, *tc.input.SwitchSerialNumber, got.SwitchSerialNumber)
				}
				if tc.input.Labels != nil {
					assert.Equal(t, Labels(tc.input.Labels), got.Labels)
				}

				if tc.verifyChildSpanner {
					span := otrace.SpanFromContext(ctx)
					assert.True(t, span.SpanContext().IsValid())
					_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
					assert.True(t, ok)
				}
			}
		})
	}
}

func TestExpectedSwitchSQLDAO_Clear(t *testing.T) {
	ctx := context.Background()
	dbSession := testInitDB(t)
	defer dbSession.Close()
	testExpectedSwitchSetupSchema(t, dbSession)

	essExp := testExpectedSwitchSQLDAOCreateExpectedSwitches(ctx, t, dbSession)
	essd := NewExpectedSwitchDAO(dbSession)
	assert.NotNil(t, essd)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		es                 ExpectedSwitch
		input              ExpectedSwitchClearInput
		expectedUpdate     bool
		verifyChildSpanner bool
	}{
		{
			desc: "can clear Labels",
			es:   essExp[0],
			input: ExpectedSwitchClearInput{
				Labels: true,
			},
			expectedUpdate: true,
		},
		{
			desc:           "nop when no cleared fields are specified",
			es:             essExp[2],
			input:          ExpectedSwitchClearInput{},
			expectedUpdate: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			tc.input.ExpectedSwitchID = tc.es.ID
			tmp, err := essd.Clear(ctx, nil, tc.input)
			assert.Nil(t, err)
			assert.NotNil(t, tmp)
			if tc.input.Labels {
				assert.Nil(t, tmp.Labels)
			}

			if tc.expectedUpdate {
				assert.True(t, tmp.Updated.After(tc.es.Updated))
			}

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestExpectedSwitchSQLDAO_Delete(t *testing.T) {
	ctx := context.Background()
	dbSession := testInitDB(t)
	defer dbSession.Close()
	testExpectedSwitchSetupSchema(t, dbSession)

	essExp := testExpectedSwitchSQLDAOCreateExpectedSwitches(ctx, t, dbSession)
	essd := NewExpectedSwitchDAO(dbSession)
	assert.NotNil(t, essd)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		esID               uuid.UUID
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			desc:               "can delete existing object success",
			esID:               essExp[1].ID,
			wantErr:            false,
			verifyChildSpanner: true,
		},
		{
			desc:    "delete non-existent object success",
			esID:    uuid.New(),
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := essd.Delete(ctx, nil, tc.esID)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			var res ExpectedSwitch

			err = dbSession.DB.NewSelect().Model(&res).Where("es.id = ?", tc.esID).Scan(ctx)
			assert.ErrorIs(t, err, sql.ErrNoRows)

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}
