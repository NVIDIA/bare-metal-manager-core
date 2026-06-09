// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"testing"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	stracer "github.com/NVIDIA/infra-controller/rest-api/db/pkg/tracer"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/util"
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
		DisplayName:    cutil.GetPtr("test"),
		Org:            "test-org",
		OrgDisplayName: cutil.GetPtr("Test Org"),
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
		DisplayName:    cutil.GetPtr("Test Tenant 1"),
		Org:            org,
		OrgDisplayName: cutil.GetPtr(orgDisplayName),
		CreatedBy:      uuid.New(),
	}

	tn2 := Tenant{
		ID:             uuid.New(),
		Name:           "test-tenant-2",
		DisplayName:    cutil.GetPtr("Test Tenant 2"),
		Org:            org,
		OrgDisplayName: cutil.GetPtr(orgDisplayName),
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

func TestTenantSQLDAO_Create(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx   context.Context
		input TenantCreateInput
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
		DisplayName:    cutil.GetPtr("test"),
		Org:            "test-org",
		OrgDisplayName: cutil.GetPtr("Test Org"),
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
				ctx: ctx,
				input: TenantCreateInput{
					Name:           tn.Name,
					DisplayName:    tn.DisplayName,
					Org:            tn.Org,
					OrgDisplayName: tn.OrgDisplayName,
					Config:         tncfg,
					CreatedBy:      tn.CreatedBy,
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
				ctx: context.Background(),
				input: TenantCreateInput{
					Name:           tn.Name,
					DisplayName:    tn.DisplayName,
					Org:            tn.Org,
					OrgDisplayName: tn.OrgDisplayName,
					Config:         defaultcfg,
					CreatedBy:      tn.CreatedBy,
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
			got, err := ipsd.Create(tt.args.ctx, nil, tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("TenantSQLDAO.Create() error = %v, wantErr %v", err, tt.wantErr)
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

func TestTenantSQLDAO_Update(t *testing.T) {
	type fields struct {
		dbSession *db.Session
	}
	type args struct {
		ctx   context.Context
		input TenantUpdateInput
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
		DisplayName:    cutil.GetPtr("Test"),
		Org:            "test-org",
		OrgDisplayName: cutil.GetPtr("Test Org"),
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
		DisplayName:    cutil.GetPtr("Test 2"),
		Org:            tn.Org,
		OrgDisplayName: cutil.GetPtr("Test Org Updated"),
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
				ctx: ctx,
				input: TenantUpdateInput{
					TenantID:       tn.ID,
					Name:           cutil.GetPtr(utn.Name),
					DisplayName:    utn.DisplayName,
					OrgDisplayName: utn.OrgDisplayName,
					Config:         tncfg,
				},
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
			got, err := ipsd.Update(tt.args.ctx, nil, tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("TenantSQLDAO.Update() error = %v, wantErr %v", err, tt.wantErr)
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

func TestTenantSQLDAO_Delete(t *testing.T) {
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
		DisplayName: cutil.GetPtr("test"),
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
			if err := ipsd.Delete(tt.args.ctx, nil, tt.args.id); (err != nil) != tt.wantErr {
				t.Errorf("TenantSQLDAO.Delete() error = %v, wantErr %v", err, tt.wantErr)
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
