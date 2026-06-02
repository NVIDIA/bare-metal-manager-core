// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	"github.com/google/uuid"

	"github.com/uptrace/bun"
)

const (
	// InfrastructureProviderRelationName is the relation name for the InfrastructureProvider model
	InfrastructureProviderRelationName = "InfrastructureProvider"
)

// InfrastructureProvider is the object for the infrastructure_provider table
type InfrastructureProvider struct {
	bun.BaseModel `bun:"table:infrastructure_provider,alias:ip"`

	ID             uuid.UUID  `bun:"type:uuid,pk"`
	Name           string     `bun:"name,notnull"`
	DisplayName    *string    `bun:"display_name"`
	Org            string     `bun:"org,notnull"`
	OrgDisplayName *string    `bun:"org_display_name"`
	Created        time.Time  `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated        time.Time  `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted        *time.Time `bun:"deleted,soft_delete"`
	CreatedBy      uuid.UUID  `bun:"type:uuid,notnull"`
}

var _ bun.BeforeAppendModelHook = (*InfrastructureProvider)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (ip *InfrastructureProvider) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		ip.Created = db.GetCurTime()
		ip.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		ip.Updated = db.GetCurTime()
	}
	return nil
}

// InfrastructureProviderDAO is the data access interface for InfrastructureProvider
type InfrastructureProviderDAO interface {
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*InfrastructureProvider, error)
	//
	GetAllByOrg(ctx context.Context, tx *db.Tx, org string, includeRelations []string) ([]InfrastructureProvider, error)
	//
	CreateFromParams(ctx context.Context, tx *db.Tx, name string, displayName *string, org string, orgDisplayName *string, createdBy *User) (*InfrastructureProvider, error)
	//
	UpdateFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID, name *string, displayName *string, orgDisplayName *string) (*InfrastructureProvider, error)
	//
	DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// InfrastructureProviderSQLDAO implements InfrastructureProviderDAO interface for SQL
type InfrastructureProviderSQLDAO struct {
	dbSession *db.Session
	InfrastructureProviderDAO
	tracerSpan *stracer.TracerSpan
}

// GetByID returns the InfrastructureProvider with the given ID
func (ipsd InfrastructureProviderSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*InfrastructureProvider, error) {
	// Create a child span and set the attributes for current request
	ctx, ipDAOSpan := ipsd.tracerSpan.CreateChildInCurrentContext(ctx, "InfrastructureProviderDAO.GetByID")
	if ipDAOSpan != nil {
		defer ipDAOSpan.End()

		ipsd.tracerSpan.SetAttribute(ipDAOSpan, "id", id.String())
	}

	ip := &InfrastructureProvider{}

	query := db.GetIDB(tx, ipsd.dbSession).NewSelect().Model(ip).Where("id = ?", id)

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

	return ip, nil
}

// GetAllByOrg returns the InfrastructureProviders with the given org
func (ipsd InfrastructureProviderSQLDAO) GetAllByOrg(ctx context.Context, tx *db.Tx, org string, includeRelations []string) ([]InfrastructureProvider, error) {
	// Create a child span and set the attributes for current request
	ctx, ipDAOSpan := ipsd.tracerSpan.CreateChildInCurrentContext(ctx, "InfrastructureProviderDAO.GetAllByOrg")
	if ipDAOSpan != nil {
		defer ipDAOSpan.End()
		ipsd.tracerSpan.SetAttribute(ipDAOSpan, "org", org)
	}

	var ips []InfrastructureProvider

	query := db.GetIDB(tx, ipsd.dbSession).NewSelect().Model(&ips).Where("ip.org = ?", org)

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	err := query.Scan(ctx)

	if err != nil {
		return nil, err
	}

	return ips, nil
}

// CreateFromParams creates a new InfrastructureProvider from the given parameters
func (ipsd InfrastructureProviderSQLDAO) CreateFromParams(ctx context.Context, tx *db.Tx, name string, displayName *string, org string, orgDisplayName *string, createdBy *User) (*InfrastructureProvider, error) {
	// Create a child span and set the attributes for current request
	ctx, ipDAOSpan := ipsd.tracerSpan.CreateChildInCurrentContext(ctx, "InfrastructureProviderDAO.CreateFromParams")
	if ipDAOSpan != nil {
		defer ipDAOSpan.End()
		ipsd.tracerSpan.SetAttribute(ipDAOSpan, "name", name)
	}

	ip := &InfrastructureProvider{
		ID:             uuid.New(),
		Name:           name,
		DisplayName:    displayName,
		Org:            org,
		OrgDisplayName: orgDisplayName,
		CreatedBy:      createdBy.ID,
	}

	_, err := db.GetIDB(tx, ipsd.dbSession).NewInsert().Model(ip).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nip, err := ipsd.GetByID(ctx, tx, ip.ID, nil)
	if err != nil {
		return nil, err
	}

	return nip, nil
}

// UpdateFromParams updates the InfrastructureProvider with the given parameters
func (ipsd InfrastructureProviderSQLDAO) UpdateFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID, name *string, displayName *string, orgDisplayName *string) (*InfrastructureProvider, error) {
	// Create a child span and set the attributes for current request
	ctx, ipDAOSpan := ipsd.tracerSpan.CreateChildInCurrentContext(ctx, "InfrastructureProviderDAO.UpdateFromParams")
	if ipDAOSpan != nil {
		defer ipDAOSpan.End()
	}

	ip := &InfrastructureProvider{
		ID: id,
	}

	updatedFields := []string{}

	if name != nil {
		ip.Name = *name
		updatedFields = append(updatedFields, "name")

		if ipDAOSpan != nil {
			ipsd.tracerSpan.SetAttribute(ipDAOSpan, "name", *name)
		}
	}

	if displayName != nil {
		ip.DisplayName = displayName
		updatedFields = append(updatedFields, "display_name")

		if ipDAOSpan != nil {
			ipsd.tracerSpan.SetAttribute(ipDAOSpan, "display_name", *displayName)
		}
	}

	if orgDisplayName != nil {
		ip.OrgDisplayName = orgDisplayName
		updatedFields = append(updatedFields, "org_display_name")

		if ipDAOSpan != nil {
			ipsd.tracerSpan.SetAttribute(ipDAOSpan, "org_display_name", *orgDisplayName)
		}
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, ipsd.dbSession).NewUpdate().Model(ip).Where("id = ?", id).Column(updatedFields...).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	uip, err := ipsd.GetByID(ctx, tx, ip.ID, nil)
	if err != nil {
		return nil, err
	}

	return uip, nil
}

// DeleteByID deletes the InfrastructureProvider with the given ID
func (ipsd InfrastructureProviderSQLDAO) DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, ipDAOSpan := ipsd.tracerSpan.CreateChildInCurrentContext(ctx, "InfrastructureProviderDAO.DeleteByID")
	if ipDAOSpan != nil {
		defer ipDAOSpan.End()

		ipsd.tracerSpan.SetAttribute(ipDAOSpan, "id", id.String())
	}

	_, err := db.GetIDB(tx, ipsd.dbSession).NewDelete().Model((*InfrastructureProvider)(nil)).Where("id = ?", id).Exec(ctx)

	if err != nil {
		return err
	}

	return nil
}

// NewInfrastructureProviderDAO creates and returns a new data access object for InfrastructureProvider
func NewInfrastructureProviderDAO(dbSession *db.Session) InfrastructureProviderDAO {
	return InfrastructureProviderSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
