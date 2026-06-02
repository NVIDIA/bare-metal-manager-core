// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otrace "go.opentelemetry.io/otel/trace"
)

func TestTenantSQLDAO_GetByID(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}

	type args struct {
		ctx context.Context
		id  uuid.UUID
	}

	// Create test DB
	dbSession := util.GetTestDBSession(t, false)
	defer dbSession.Close()

	// Create Tenant table
	err := dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	if err != nil {
		t.Fatal(err)
	}

	tncfg := &TenantConfig{
		EnableSSHAccess: true,
	}

	tn := &Tenant{
		ID:             uuid.New(),
		Name:           "test",
		DisplayName:    db.GetStrPtr("test"),
		Org:            "test-org",
		OrgDisplayName: db.GetStrPtr("Test Org"),
		Config:         tncfg,
		CreatedBy:      uuid.New(),
	}

	_, err = dbSession.DB.NewInsert().Model(tn).Exec(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		want               *Tenant
		wantConfig         *TenantConfig
		wantErr            bool
		wantErrVal         error
		verifyChildSpanner bool
	}{
		{
			name: "retrieve a Tenant by ID",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: ctx,
				id:  tn.ID,
			},
			want:               tn,
			wantConfig:         tncfg,
			wantErr:            false,
			verifyChildSpanner: true,
		},
		{
			name: "error retrieving a Tenant by ID",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: context.Background(),
				id:  uuid.New(),
			},
			want:       nil,
			wantErr:    true,
			wantErrVal: db.ErrDoesNotExist,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tsd := TenantSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			got, err := tsd.GetByID(tt.args.ctx, nil, tt.args.id, nil)
			if !tt.wantErr {
				require.NoError(t, err)
			} else {
				assert.Equal(t, tt.wantErrVal, err)
				return
			}

			require.NoError(t, err)

			assert.Equal(t, tt.want.ID, got.ID)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, *tt.want.DisplayName, *got.DisplayName)
			assert.Equal(t, tt.want.Org, got.Org)
			assert.Equal(t, *tt.want.OrgDisplayName, *got.OrgDisplayName)
			if tt.wantConfig != nil {
				assert.Equal(t, *tt.wantConfig, *got.Config)
			}

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestTenantSQLDAO_GetAllByOrg(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx context.Context
		org string
	}

	// Create test DB
	dbSession := util.GetTestDBSession(t, false)
	defer dbSession.Close()

	// Create Tenant table
	err := dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	if err != nil {
		t.Fatal(err)
	}

	org := "test-org"
	orgDisplayName := "Test Org"

	tn1 := Tenant{
		ID:             uuid.New(),
		Name:           "test-tenant-1",
		DisplayName:    db.GetStrPtr("Test Tenant 1"),
		Org:            org,
		OrgDisplayName: db.GetStrPtr(orgDisplayName),
		CreatedBy:      uuid.New(),
	}

	tn2 := Tenant{
		ID:             uuid.New(),
		Name:           "test-tenant-2",
		DisplayName:    db.GetStrPtr("Test Tenant 2"),
		Org:            org,
		OrgDisplayName: db.GetStrPtr(orgDisplayName),
		CreatedBy:      uuid.New(),
	}

	tns := []Tenant{tn1, tn2}

	_, err = dbSession.DB.NewInsert().Model(&tns).Exec(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		want               []Tenant
		verifyChildSpanner bool
	}{
		{
			name: "retrieve all Tenant by org ID",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: ctx,
				org: org,
			},
			want:               tns,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipsd := TenantSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			got, err := ipsd.GetAllByOrg(tt.args.ctx, nil, tt.args.org, nil)
			assert.NoError(t, err)

			for i, tn := range tt.want {
				assert.Equal(t, tn.ID, got[i].ID)
				assert.Equal(t, tn.Name, got[i].Name)
				assert.Equal(t, *tn.DisplayName, *got[i].DisplayName)
				assert.Equal(t, tn.Org, got[i].Org)
				assert.Equal(t, *tn.OrgDisplayName, *got[i].OrgDisplayName)
				assert.Equal(t, tn.CreatedBy, got[i].CreatedBy)
			}

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestTenantSQLDAO_CreateFromParams(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx            context.Context
		name           string
		displayName    *string
		org            string
		orgDisplayName *string
		config         *TenantConfig
		createdBy      *User
	}

	// Create test DB
	dbSession := util.GetTestDBSession(t, false)
	defer dbSession.Close()

	// Create Tenant table
	err := dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	if err != nil {
		t.Fatal(err)
	}

	defaultcfg := &TenantConfig{}

	tncfg := &TenantConfig{
		EnableSSHAccess: true,
	}

	tn := &Tenant{
		Name:           "test",
		DisplayName:    db.GetStrPtr("test"),
		Org:            "test-org",
		OrgDisplayName: db.GetStrPtr("Test Org"),
		Config:         tncfg,
		CreatedBy:      uuid.New(),
	}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		want               *Tenant
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "create a Tenant with explicit config",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:            ctx,
				name:           tn.Name,
				displayName:    tn.DisplayName,
				org:            tn.Org,
				orgDisplayName: tn.OrgDisplayName,
				config:         tncfg,
				createdBy: &User{
					ID: tn.CreatedBy,
				},
			},
			want:               tn,
			wantErr:            false,
			verifyChildSpanner: true,
		},
		{
			name: "create a Tenant with default config",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:            context.Background(),
				name:           tn.Name,
				displayName:    tn.DisplayName,
				org:            tn.Org,
				orgDisplayName: tn.OrgDisplayName,
				createdBy: &User{
					ID: tn.CreatedBy,
				},
			},
			want: &Tenant{
				Name:           tn.Name,
				DisplayName:    tn.DisplayName,
				Org:            tn.Org,
				OrgDisplayName: tn.OrgDisplayName,
				Config:         defaultcfg,
				CreatedBy:      tn.CreatedBy,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipsd := TenantSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			got, err := ipsd.CreateFromParams(tt.args.ctx, nil, tt.args.name, tt.args.displayName, tt.args.org, tt.args.orgDisplayName, tt.args.config, tt.args.createdBy)
			if (err != nil) != tt.wantErr {
				t.Errorf("TenantSQLDAO.CreateFromParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, *tt.want.DisplayName, *got.DisplayName)
			assert.Equal(t, tt.want.Org, got.Org)
			assert.Equal(t, *tt.want.OrgDisplayName, *got.OrgDisplayName)
			if tt.want.Config != nil {
				assert.NotNil(t, got.Config, "Tenant Config was expected to be set")
				assert.Equal(t, *tt.want.Config, *got.Config)
			}
			assert.Equal(t, tt.want.CreatedBy, got.CreatedBy)

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestTenantSQLDAO_UpdateFromParams(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx            context.Context
		id             uuid.UUID
		name           *string
		displayName    *string
		orgDisplayName *string
		config         *TenantConfig
	}

	// Create test DB
	dbSession := util.GetTestDBSession(t, false)

	// Create Tenant table
	err := dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	if err != nil {
		t.Fatal(err)
	}

	// Create Tenant
	tn := &Tenant{
		ID:             uuid.New(),
		Name:           "test",
		DisplayName:    db.GetStrPtr("Test"),
		Org:            "test-org",
		OrgDisplayName: db.GetStrPtr("Test Org"),
		CreatedBy:      uuid.New(),
	}

	_, err = dbSession.DB.NewInsert().Model(tn).Exec(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	tncfg := &TenantConfig{
		EnableSSHAccess: true,
	}

	// Updated Tenant
	utn := &Tenant{
		ID:             tn.ID,
		Name:           "test2",
		DisplayName:    db.GetStrPtr("Test 2"),
		Org:            tn.Org,
		OrgDisplayName: db.GetStrPtr("Test Org Updated"),
		Config:         tncfg,
		CreatedBy:      tn.CreatedBy,
	}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		want               *Tenant
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "update a Tenant",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx:            ctx,
				id:             tn.ID,
				name:           db.GetStrPtr(utn.Name),
				displayName:    utn.DisplayName,
				orgDisplayName: utn.OrgDisplayName,
				config:         tncfg,
			},
			want:               utn,
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipsd := TenantSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			got, err := ipsd.UpdateFromParams(tt.args.ctx, nil, tt.args.id, tt.args.name, tt.args.displayName, tt.args.orgDisplayName, tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("TenantSQLDAO.UpdateFromParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, *tt.want.DisplayName, *got.DisplayName)
			assert.Equal(t, tt.want.Org, got.Org)
			assert.Equal(t, *tt.want.OrgDisplayName, *got.OrgDisplayName)
			assert.Equal(t, tt.want.Config, got.Config)
			assert.NotEqual(t, tt.want.Updated.String(), got.Updated.String())

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestTenantSQLDAO_DeleteByID(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx context.Context
		id  uuid.UUID
	}

	// Create test DB
	dbSession := util.GetTestDBSession(t, false)

	// Create Tenant table
	err := dbSession.DB.ResetModel(context.Background(), (*Tenant)(nil))
	if err != nil {
		t.Fatal(err)
	}

	ip := &Tenant{
		ID:          uuid.New(),
		Name:        "test",
		DisplayName: db.GetStrPtr("test"),
		Org:         "test",
	}

	_, err = dbSession.DB.NewInsert().Model(ip).Exec(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// OTEL Spanner configuration
	_, _, ctx := testCommonTraceProviderSetup(t, context.Background())

	tests := []struct {
		name               string
		fields             fields
		args               args
		wantErr            bool
		verifyChildSpanner bool
	}{
		{
			name: "delete Tenant by ID",
			fields: fields{
				dbSession: dbSession,
			},
			args: args{
				ctx: ctx,
				id:  ip.ID,
			},
			wantErr:            false,
			verifyChildSpanner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipsd := TenantSQLDAO{
				dbSession: tt.fields.dbSession,
			}
			if err := ipsd.DeleteByID(tt.args.ctx, nil, tt.args.id); (err != nil) != tt.wantErr {
				t.Errorf("TenantSQLDAO.DeleteByID() error = %v, wantErr %v", err, tt.wantErr)
			}

			dip := &Tenant{}
			err := dbSession.DB.NewSelect().Model(dip).WhereDeleted().Where("id = ?", ip.ID).Scan(context.Background())
			if err != nil {
				t.Fatal(err)
			}

			if dip.Deleted == nil {
				t.Errorf("Failed to soft-delete Tenant")
			}

			if tt.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}
