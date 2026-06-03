// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"

	"github.com/uptrace/bun"
)

const (
	// TenantRelationName is the relation name for the Tenant model
	TenantRelationName = "Tenant"
)

// TenantConfig is a data structure to capture configuration and capabilities for a Tenant
// TODO: EnableSSHAccess is deprecated and should be removed.
type TenantConfig struct {
	EnableSSHAccess          bool `json:"enableSshAccess"`
	TargetedInstanceCreation bool `json:"targetedInstanceCreation"`
}

// Tenant represents entries in the tenant table
type Tenant struct {
	bun.BaseModel `bun:"table:tenant,alias:tn"`

	ID             uuid.UUID     `bun:"type:uuid,pk"`
	Name           string        `bun:"name,notnull"`
	DisplayName    *string       `bun:"display_name"`
	Org            string        `bun:"org,notnull"`
	OrgDisplayName *string       `bun:"org_display_name"`
	Config         *TenantConfig `bun:"config,type:jsonb,notnull,default:'{}'::jsonb"`
	Created        time.Time     `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated        time.Time     `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted        *time.Time    `bun:"deleted,soft_delete"`
	CreatedBy      uuid.UUID     `bun:"type:uuid,notnull"`
}

// ToCreateRequestProto builds a CreateTenantRequest proto for sending this Tenant
// to a Site. Falls back to Org for the metadata Name when OrgDisplayName
// isn't set.
func (tn *Tenant) ToCreateRequestProto() *cwssaws.CreateTenantRequest {
	name := tn.Org
	if tn.OrgDisplayName != nil {
		name = *tn.OrgDisplayName
	}
	return &cwssaws.CreateTenantRequest{
		OrganizationId: tn.Org,
		Metadata: &cwssaws.Metadata{
			Name: name,
		},
	}
}

// ToUpdateRequestProto builds an UpdateTenantRequest proto for sending this Tenant
// to a Site.
func (tn *Tenant) ToUpdateRequestProto() *cwssaws.UpdateTenantRequest {
	name := tn.Org
	if tn.OrgDisplayName != nil {
		name = *tn.OrgDisplayName
	}
	return &cwssaws.UpdateTenantRequest{
		OrganizationId: tn.Org,
		Metadata: &cwssaws.Metadata{
			Name: name,
		},
	}
}

var _ bun.BeforeAppendModelHook = (*Tenant)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (tn *Tenant) BeforeAppendModel(_ context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		tn.Created = db.GetCurTime()
		tn.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		tn.Updated = db.GetCurTime()
	}
	return nil
}

// TenantDAO is the data access interface for Tenant
type TenantDAO interface {
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*Tenant, error)
	//
	GetAllByOrg(ctx context.Context, tx *db.Tx, org string, includeRelations []string) ([]Tenant, error)
	//
	CreateFromParams(ctx context.Context, tx *db.Tx, name string, displayName *string, org string, orgDisplayName *string, config *TenantConfig, createdBy *User) (*Tenant, error)
	//
	UpdateFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID, name *string, displayName *string, orgDisplayName *string, config *TenantConfig) (*Tenant, error)
	//
	DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// TenantSQLDAO implements TenantDAO interface for SQL
type TenantSQLDAO struct {
	dbSession  *db.Session
	tracerSpan *stracer.TracerSpan
}

// GetByID returns a Tenant by ID
func (tsd TenantSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*Tenant, error) {
	// Create a child span and set the attributes for current request
	ctx, tnDAOSpan := tsd.tracerSpan.CreateChildInCurrentContext(ctx, "TenantDAO.GetByID")
	if tnDAOSpan != nil {
		defer tnDAOSpan.End()

		tsd.tracerSpan.SetAttribute(tnDAOSpan, "id", id.String())
	}

	tn := &Tenant{}

	query := db.GetIDB(tx, tsd.dbSession).NewSelect().Model(tn).Where("id = ?", id)

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	err := query.Scan(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, db.ErrDoesNotExist
		}
		return nil, err
	}

	return tn, nil
}

// GetAllByOrg returns all Tenants for an Org
func (tsd TenantSQLDAO) GetAllByOrg(ctx context.Context, tx *db.Tx, org string, includeRelations []string) ([]Tenant, error) {
	// Create a child span and set the attributes for current request
	ctx, tnDAOSpan := tsd.tracerSpan.CreateChildInCurrentContext(ctx, "TenantDAO.GetAllByOrg")
	if tnDAOSpan != nil {
		defer tnDAOSpan.End()

		tsd.tracerSpan.SetAttribute(tnDAOSpan, "org", org)
	}

	tns := []Tenant{}

	query := db.GetIDB(tx, tsd.dbSession).NewSelect().Model(&tns).Where("tn.org = ?", org)

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	err := query.Scan(ctx)
	if err != nil {
		return nil, err
	}

	return tns, nil
}

// CreateFromParams creates a new Tenant from parameters
func (tsd TenantSQLDAO) CreateFromParams(ctx context.Context, tx *db.Tx, name string, displayName *string, org string, orgDisplayName *string, config *TenantConfig, createdBy *User) (*Tenant, error) {
	// Create a child span and set the attributes for current request
	ctx, tnDAOSpan := tsd.tracerSpan.CreateChildInCurrentContext(ctx, "TenantDAO.CreateFromParams")
	if tnDAOSpan != nil {
		defer tnDAOSpan.End()

		tsd.tracerSpan.SetAttribute(tnDAOSpan, "name", name)
	}

	tn := &Tenant{
		ID:             uuid.New(),
		Name:           name,
		DisplayName:    displayName,
		Org:            org,
		OrgDisplayName: orgDisplayName,
		Config:         config,
		CreatedBy:      createdBy.ID,
	}

	_, err := db.GetIDB(tx, tsd.dbSession).NewInsert().Model(tn).Exec(ctx)
	if err != nil {
		return nil, err
	}

	ntn, err := tsd.GetByID(ctx, tx, tn.ID, nil)
	if err != nil {
		return nil, err
	}

	return ntn, nil
}

// UpdateFromParams updates the InfrastructureProvider with the given parameters
func (tsd TenantSQLDAO) UpdateFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID, name *string, displayName *string, orgDisplayName *string, config *TenantConfig) (*Tenant, error) {
	// Create a child span and set the attributes for current request
	ctx, tnDAOSpan := tsd.tracerSpan.CreateChildInCurrentContext(ctx, "TenantDAO.UpdateFromParams")
	if tnDAOSpan != nil {
		defer tnDAOSpan.End()

		tsd.tracerSpan.SetAttribute(tnDAOSpan, "id", id.String())
	}

	tn := &Tenant{
		ID: id,
	}

	updatedFields := []string{}

	if name != nil {
		tn.Name = *name
		updatedFields = append(updatedFields, "name")
		tsd.tracerSpan.SetAttribute(tnDAOSpan, "name", *name)
	}

	if displayName != nil {
		tn.DisplayName = displayName
		updatedFields = append(updatedFields, "display_name")
		tsd.tracerSpan.SetAttribute(tnDAOSpan, "display_name", *displayName)
	}

	if orgDisplayName != nil {
		tn.OrgDisplayName = orgDisplayName
		updatedFields = append(updatedFields, "org_display_name")
		tsd.tracerSpan.SetAttribute(tnDAOSpan, "org_display_name", *orgDisplayName)
	}

	if config != nil {
		tn.Config = config
		updatedFields = append(updatedFields, "config")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, tsd.dbSession).NewUpdate().Model(tn).Where("id = ?", id).Column(updatedFields...).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	utn, err := tsd.GetByID(ctx, tx, id, nil)
	if err != nil {
		return nil, err
	}

	return utn, nil
}

// DeleteByID deletes a Tenant by ID
func (tsd TenantSQLDAO) DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, tnDAOSpan := tsd.tracerSpan.CreateChildInCurrentContext(ctx, "TenantDAO.DeleteByID")
	if tnDAOSpan != nil {
		defer tnDAOSpan.End()

		tsd.tracerSpan.SetAttribute(tnDAOSpan, "id", id.String())
	}

	_, err := db.GetIDB(tx, tsd.dbSession).NewDelete().Model((*Tenant)(nil)).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewTenantDAO creates and returns a new data access object for Tenant
func NewTenantDAO(dbSession *db.Session) TenantDAO {
	return TenantSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
