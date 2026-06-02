// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

const (
	// FabricRelationName is the relation name for the Fabric model
	FabricRelationName = "Fabric"
)

const (
	// FabricStatusPending indicates that the Fabric request was received but not yet processed
	FabricStatusPending = "Pending"
	// FabricStatusReady indicates that the Fabric is ready on the Site
	FabricStatusReady = "Ready"
	// FabricStatusError is the status of a Fabric that is in error mode
	FabricStatusError = "Error"
	// FabricStatusDeleting indicates that the Fabric is being deleted
	FabricStatusDeleting = "Deleting"

	// FabricOrderByDefault default field to be used for ordering when none specified
	FabricOrderByDefault = "created"
)

var (
	// FabricStatusMap is a list of valid status for the Faric model
	FabricStatusMap = map[string]bool{
		FabricStatusPending:  true,
		FabricStatusReady:    true,
		FabricStatusError:    true,
		FabricStatusDeleting: true,
	}
)

var (
	// FabricOrderByFields is a list of valid order by fields for the Fabric model
	FabricOrderByFields = []string{"id", "status", "created", "updated"}
	// FabricRelatedEntities is a list of valid relation by fields for the Fabric model
	FabricRelatedEntities = map[string]bool{
		SiteRelationName:                   true,
		InfrastructureProviderRelationName: true,
	}
)

// Fabric represents a collection of Fabric
type Fabric struct {
	bun.BaseModel `bun:"table:fabric,alias:fb"`

	ID                       string                  `bun:"id,notnull,pk"`
	Org                      string                  `bun:"org,notnull"`
	SiteID                   uuid.UUID               `bun:"site_id,type:uuid,notnull,pk"`
	Site                     *Site                   `bun:"rel:belongs-to,join:site_id=id"`
	InfrastructureProviderID uuid.UUID               `bun:"infrastructure_provider_id,type:uuid,notnull"`
	InfrastructureProvider   *InfrastructureProvider `bun:"rel:belongs-to,join:infrastructure_provider_id=id"`
	Status                   string                  `bun:"status,notnull"`
	IsMissingOnSite          bool                    `bun:"is_missing_on_site,notnull"`
	Created                  time.Time               `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated                  time.Time               `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted                  *time.Time              `bun:"deleted,soft_delete"`
}

var _ bun.BeforeAppendModelHook = (*Fabric)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (fb *Fabric) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		fb.Created = db.GetCurTime()
		fb.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		fb.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*Fabric)(nil)

// BeforeCreateTable is a hook that is called before the table is created
func (a *Fabric) BeforeCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey(`("site_id") REFERENCES "site" ("id")`).
		ForeignKey(`("infrastructure_provider_id") REFERENCES "infrastructure_provider" ("id")`)
	return nil
}

// FabricDAO is an interface for interacting with the Fabric model
type FabricDAO interface {
	//
	CreateFromParams(ctx context.Context, tx *db.Tx, id string, org string, siteID uuid.UUID, infrastructureProviderID uuid.UUID, status string) (*Fabric, error)
	//
	GetByID(ctx context.Context, tx *db.Tx, id string, siteID uuid.UUID, includeRelations []string) (*Fabric, error)
	//
	GetAll(ctx context.Context, tx *db.Tx, org *string, siteID, infrastructureProviderID *uuid.UUID, status *string, ids []string, searchQuery *string, includeRelations []string, offset *int, limit *int, orderBy *paginator.OrderBy) ([]Fabric, int, error)
	//
	UpdateFromParams(ctx context.Context, tx *db.Tx, id string, siteID uuid.UUID, infrastructureProviderID *uuid.UUID, status *string, isMissingOnSite *bool) (*Fabric, error)
	//
	DeleteByID(ctx context.Context, tx *db.Tx, id string, siteID uuid.UUID) error
	//
	DeleteAll(ctx context.Context, tx *db.Tx, ids []string, siteID *uuid.UUID) error
}

// FabricSQLDAO is an implementation of the FabricDAO interface
type FabricSQLDAO struct {
	dbSession *db.Session
	FabricDAO
	tracerSpan *stracer.TracerSpan
}

// CreateFromParams creates a new Fabric from the given parameters
func (fbsd FabricSQLDAO) CreateFromParams(ctx context.Context, tx *db.Tx, id string, org string, siteID uuid.UUID, infrastructureProviderID uuid.UUID, status string) (*Fabric, error) {
	// Create a child span and set the attributes for current request
	ctx, FabricDAOSpan := fbsd.tracerSpan.CreateChildInCurrentContext(ctx, "FabricDAO.CreateFromParams")
	if FabricDAOSpan != nil {
		defer FabricDAOSpan.End()

		fbsd.tracerSpan.SetAttribute(FabricDAOSpan, "id", id)
	}

	fb := &Fabric{
		ID:                       id,
		Org:                      org,
		SiteID:                   siteID,
		InfrastructureProviderID: infrastructureProviderID,
		Status:                   status,
	}

	_, err := db.GetIDB(tx, fbsd.dbSession).NewInsert().Model(fb).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nfb, err := fbsd.GetByID(ctx, tx, fb.ID, siteID, nil)
	if err != nil {
		return nil, err
	}

	return nfb, nil
}

// GetByID returns a Fabric by ID
// returns db.ErrDoesNotExist error if the record is not found
func (fbsd FabricSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id string, siteID uuid.UUID, includeRelations []string) (*Fabric, error) {
	// Create a child span and set the attributes for current request
	ctx, FabricDAOSpan := fbsd.tracerSpan.CreateChildInCurrentContext(ctx, "FabricDAO.GetByID")
	if FabricDAOSpan != nil {
		defer FabricDAOSpan.End()

		fbsd.tracerSpan.SetAttribute(FabricDAOSpan, "id", id)
	}

	fb := &Fabric{}

	query := db.GetIDB(tx, fbsd.dbSession).NewSelect().Model(fb).Where("fb.id = ?", id).Where("fb.site_id = ?", siteID)

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

	return fb, nil
}

// GetAll returns all Fabrics filtering by Site, InfrastructureProvider and IDs
// errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
// if orderBy is nil, then records are ordered by column specified in FabricOrderByDefault in ascending order
func (fbsd FabricSQLDAO) GetAll(ctx context.Context, tx *db.Tx, org *string, siteID, infrastructureProviderID *uuid.UUID, status *string, ids []string, searchQuery *string, includeRelations []string, offset *int, limit *int, orderBy *paginator.OrderBy) ([]Fabric, int, error) {
	// Create a child span and set the attributes for current request
	ctx, fabricDAOSpan := fbsd.tracerSpan.CreateChildInCurrentContext(ctx, "FabricDAO.GetAll")
	if fabricDAOSpan != nil {
		defer fabricDAOSpan.End()
	}

	fbs := []Fabric{}
	if ids != nil && len(ids) == 0 {
		return fbs, 0, nil
	}

	query := db.GetIDB(tx, fbsd.dbSession).NewSelect().Model(&fbs)
	if org != nil {
		query = query.Where("fb.org = ?", *org)
		fbsd.tracerSpan.SetAttribute(fabricDAOSpan, "org", *org)
	}
	if siteID != nil {
		query = query.Where("fb.site_id = ?", *siteID)

		if fabricDAOSpan != nil {
			fbsd.tracerSpan.SetAttribute(fabricDAOSpan, "site_id", siteID.String())
		}

	}
	if infrastructureProviderID != nil {
		query = query.Where("fb.infrastructure_provider_id = ?", *infrastructureProviderID)

		if fabricDAOSpan != nil {
			fbsd.tracerSpan.SetAttribute(fabricDAOSpan, "infrastructure_provider_id", infrastructureProviderID.String())
		}
	}
	if status != nil {
		query = query.Where("fb.status = ?", *status)

		if fabricDAOSpan != nil {
			fbsd.tracerSpan.SetAttribute(fabricDAOSpan, "status", *status)
		}
	}
	if ids != nil {
		if len(ids) == 1 {
			query = query.Where("fb.id = ?", ids[0])
		} else {
			query = query.Where("fb.id IN (?)", bun.In(ids))
		}
	}

	normalizedSearchQuery, searchTokens, ok := db.NormalizeSearchQuery(searchQuery)
	if ok {
		query = query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				Where("to_tsvector('english', (coalesce(fb.id, ' ') || ' ' || coalesce(fb.status, ' '))) @@ to_tsquery('english', ?)", *searchTokens).
				WhereOr("fb.id ILIKE ?", "%"+normalizedSearchQuery+"%").
				WhereOr("fb.status ILIKE ?", "%"+normalizedSearchQuery+"%")
		})

		if fabricDAOSpan != nil {
			fbsd.tracerSpan.SetAttribute(fabricDAOSpan, "search_query", normalizedSearchQuery)
		}
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// if no order is passed, set default to make sure objects return always in the same order and pagination works properly
	if orderBy == nil {
		orderBy = paginator.NewDefaultOrderBy(FabricOrderByDefault)
	}

	paginator, err := paginator.NewPaginator(ctx, query, offset, limit, orderBy, FabricOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = paginator.Query.Limit(paginator.Limit).Offset(paginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return fbs, paginator.Total, nil
}

// UpdateFromParams updates specified fields of an existing Fabric
// The updated fields are assumed to be set to non-null values
// For setting to null values, use: ClearFromParams
// since there are 2 operations (UPDATE, SELECT), in this, it is required that
// this library call happens within a transaction
func (fbsd FabricSQLDAO) UpdateFromParams(ctx context.Context, tx *db.Tx, id string, siteID uuid.UUID, infrastructureProviderID *uuid.UUID, status *string, isMissingOnSite *bool) (*Fabric, error) {
	// Create a child span and set the attributes for current request
	ctx, fabricDAOSpan := fbsd.tracerSpan.CreateChildInCurrentContext(ctx, "FabricDAO.UpdateFromParams")
	if fabricDAOSpan != nil {
		defer fabricDAOSpan.End()
	}

	fb := &Fabric{
		ID:     id,
		SiteID: siteID,
	}

	updatedFields := []string{}
	if infrastructureProviderID != nil {
		fb.InfrastructureProviderID = *infrastructureProviderID
		updatedFields = append(updatedFields, "infrastructure_provider_id")

		if fabricDAOSpan != nil {
			fbsd.tracerSpan.SetAttribute(fabricDAOSpan, "infrastructure_provider_id", infrastructureProviderID.String())
		}
	}
	if status != nil {
		fb.Status = *status
		updatedFields = append(updatedFields, "status")

		if fabricDAOSpan != nil {
			fbsd.tracerSpan.SetAttribute(fabricDAOSpan, "status", *status)
		}
	}
	if isMissingOnSite != nil {
		fb.IsMissingOnSite = *isMissingOnSite
		updatedFields = append(updatedFields, "is_missing_on_site")
		fbsd.tracerSpan.SetAttribute(fabricDAOSpan, "is_missing_on_site", *isMissingOnSite)
	}
	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, fbsd.dbSession).NewUpdate().Model(fb).Column(updatedFields...).Where("id = ?", id).Where("site_id = ?", siteID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nfb, err := fbsd.GetByID(ctx, tx, fb.ID, siteID, nil)

	if err != nil {
		return nil, err
	}
	return nfb, nil
}

// DeleteByID deletes an Fabric by ID and SiteID
// error is returned only if there is a db error
// if the object being deleted doesnt exist, error is not returned
func (fbsd FabricSQLDAO) DeleteByID(ctx context.Context, tx *db.Tx, id string, siteID uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, FabricDAOSpan := fbsd.tracerSpan.CreateChildInCurrentContext(ctx, "FabricSQLDAO.DeleteByID")
	if FabricDAOSpan != nil {
		defer FabricDAOSpan.End()

		fbsd.tracerSpan.SetAttribute(FabricDAOSpan, "id", id)
	}
	fb := &Fabric{
		ID:     id,
		SiteID: siteID,
	}

	_, err := db.GetIDB(tx, fbsd.dbSession).NewDelete().Model(fb).Where("id = ?", id).Where("site_id = ?", siteID).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// DeleteAll deletes an Fabric by ID or Site ID
// error is returned only if there is a db error
// if the object being deleted doesnt exist, error is not returned
func (fbsd FabricSQLDAO) DeleteAll(ctx context.Context, tx *db.Tx, ids []string, siteID *uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, FabricDAOSpan := fbsd.tracerSpan.CreateChildInCurrentContext(ctx, "FabricSQLDAO.DeleteAll")
	if FabricDAOSpan != nil {
		defer FabricDAOSpan.End()
	}

	fb := &Fabric{}
	query := db.GetIDB(tx, fbsd.dbSession).NewDelete().Model(fb)

	if ids != nil {
		if len(ids) == 1 {
			query = query.Where("fb.id = ?", ids[0])
		} else {
			query = query.Where("fb.id IN (?)", bun.In(ids))
		}
	}

	if siteID != nil {
		query = query.Where("fb.site_id = ?", *siteID)
	}

	_, err := query.Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewFabricDAO returns a new FabricDAO
func NewFabricDAO(dbSession *db.Session) FabricDAO {
	return &FabricSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
