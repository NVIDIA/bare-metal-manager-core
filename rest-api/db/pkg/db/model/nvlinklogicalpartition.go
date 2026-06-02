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
	// NVLinkLogicalPartitionStatusPending indicates that the NVLinkLogicalPartition request was received but not yet processed
	NVLinkLogicalPartitionStatusPending = "Pending"
	// NVLinkLogicalPartitionStatusProvisioning indicates that the NVLinkLogicalPartition is being provisioned
	NVLinkLogicalPartitionStatusProvisioning = "Provisioning"
	// NVLinkLogicalPartitionStatusReady indicates that the NVLinkLogicalPartition has been successfully provisioned on the Site
	NVLinkLogicalPartitionStatusReady = "Ready"
	// NVLinkLogicalPartitionStatusConfiguring indicates that the NVLinkLogicalPartition is being configuring
	NVLinkLogicalPartitionStatusConfiguring = "Configuring"
	// NVLinkLogicalPartitionStatusError is the status of a NVLinkLogicalPartition that is in error mode
	NVLinkLogicalPartitionStatusError = "Error"
	// NVLinkLogicalPartitionStatusDeleting indicates that the NVLinkLogicalPartition is being deleted
	NVLinkLogicalPartitionStatusDeleting = "Deleting"
	// NVLinkLogicalPartitionRelationName is the relation name for the NVLinkLogicalPartition model
	NVLinkLogicalPartitionRelationName = "NVLinkLogicalPartition"

	// NVLinkLogicalPartitionOrderByDefault default field to be used for ordering when none specified
	NVLinkLogicalPartitionOrderByDefault = "created"
)

var (
	// NVLinkLogicalPartitionOrderByFields is a list of valid order by fields for the NVLinkLogicalPartition model
	NVLinkLogicalPartitionOrderByFields = []string{"name", "status", "created", "updated"}
	// NVLinkLogicalPartitionRelatedEntities is a list of valid relation by fields for the NVLinkLogicalPartition model
	NVLinkLogicalPartitionRelatedEntities = map[string]bool{
		SiteRelationName:   true,
		TenantRelationName: true,
	}
	// NVLinkLogicalPartitionStatusMap is a list of valid status for the NVLinkLogicalPartition model
	NVLinkLogicalPartitionStatusMap = map[string]bool{
		NVLinkLogicalPartitionStatusPending:      true,
		NVLinkLogicalPartitionStatusProvisioning: true,
		NVLinkLogicalPartitionStatusReady:        true,
		NVLinkLogicalPartitionStatusConfiguring:  true,
		NVLinkLogicalPartitionStatusError:        true,
		NVLinkLogicalPartitionStatusDeleting:     true,
	}
)

// NVLinkLogicalPartition represents entries in the NVLinkLogicalPartition table
type NVLinkLogicalPartition struct {
	bun.BaseModel `bun:"table:nvlink_logical_partition,alias:nvllp"`

	ID              uuid.UUID  `bun:"type:uuid,pk"`
	Name            string     `bun:"name,notnull"`
	Description     *string    `bun:"description"`
	Org             string     `bun:"org,notnull"`
	SiteID          uuid.UUID  `bun:"site_id,type:uuid,notnull"`
	Site            *Site      `bun:"rel:belongs-to,join:site_id=id"`
	TenantID        uuid.UUID  `bun:"tenant_id,type:uuid,notnull"`
	Tenant          *Tenant    `bun:"rel:belongs-to,join:tenant_id=id"`
	Status          string     `bun:"status,notnull"`
	IsMissingOnSite bool       `bun:"is_missing_on_site,notnull"`
	Created         time.Time  `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated         time.Time  `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted         *time.Time `bun:"deleted,soft_delete"`
	CreatedBy       uuid.UUID  `bun:"type:uuid,notnull"`
}

// NVLinkLogicalPartitionCreateInput input parameters for Create method
type NVLinkLogicalPartitionCreateInput struct {
	NVLinkLogicalPartitionID *uuid.UUID
	Name                     string
	Description              *string
	TenantOrg                string
	SiteID                   uuid.UUID
	TenantID                 uuid.UUID
	Status                   string
	CreatedBy                uuid.UUID
}

// NVLinkLogicalPartitionUpdateInput input parameters for Update method
type NVLinkLogicalPartitionUpdateInput struct {
	NVLinkLogicalPartitionID uuid.UUID
	Name                     *string
	Description              *string
	Status                   *string
	IsMissingOnSite          *bool
}

// NVLinkLogicalPartitionClearInput input parameters for Clear method
type NVLinkLogicalPartitionClearInput struct {
	NVLinkLogicalPartitionID uuid.UUID
	Description              bool
}

// NVLinkLogicalPartitionFilterInput input parameters for Filter method
type NVLinkLogicalPartitionFilterInput struct {
	NVLinkLogicalPartitionIDs []uuid.UUID
	Names                     []string
	SiteIDs                   []uuid.UUID
	TenantOrgs                []string
	TenantIDs                 []uuid.UUID
	Statuses                  []string
	SearchQuery               *string
}

var _ bun.BeforeAppendModelHook = (*NVLinkLogicalPartition)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (nvllp *NVLinkLogicalPartition) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		nvllp.Created = db.GetCurTime()
		nvllp.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		nvllp.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*NVLinkLogicalPartition)(nil)

// BeforeCreateTable is a hook that is called before the table is created
func (nvllp *NVLinkLogicalPartition) BeforeCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey(`("tenant_id") REFERENCES "tenant" ("id")`).
		ForeignKey(`("site_id") REFERENCES "site" ("id")`)
	return nil
}

// NVLinkLogicalPartitionDAO is an interface for interacting with the NVLinkLogicalPartition model
type NVLinkLogicalPartitionDAO interface {
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*NVLinkLogicalPartition, error)
	//
	GetAll(ctx context.Context, tx *db.Tx, filter NVLinkLogicalPartitionFilterInput, page paginator.PageInput, includeRelations []string) ([]NVLinkLogicalPartition, int, error)
	//
	Create(ctx context.Context, tx *db.Tx, input NVLinkLogicalPartitionCreateInput) (*NVLinkLogicalPartition, error)
	//
	Update(ctx context.Context, tx *db.Tx, input NVLinkLogicalPartitionUpdateInput) (*NVLinkLogicalPartition, error)
	//
	Clear(ctx context.Context, tx *db.Tx, input NVLinkLogicalPartitionClearInput) (*NVLinkLogicalPartition, error)
	//
	Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// NVLinkLogicalPartitionSQLDAO is an implementation of the NVLinkLogicalPartitionDAO interface
type NVLinkLogicalPartitionSQLDAO struct {
	dbSession  *db.Session
	tracerSpan *stracer.TracerSpan
}

// GetByID returns a NVLinkLogicalPartition by ID
func (nvllpsd NVLinkLogicalPartitionSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*NVLinkLogicalPartition, error) {
	// Create a child span and set the attributes for current request
	ctx, NVLinkLogicalPartitionDAOSpan := nvllpsd.tracerSpan.CreateChildInCurrentContext(ctx, "NVLinkLogicalPartitionDAO.GetByID")
	if NVLinkLogicalPartitionDAOSpan != nil {
		defer NVLinkLogicalPartitionDAOSpan.End()

		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "id", id.String())
	}

	nvllp := &NVLinkLogicalPartition{}

	query := db.GetIDB(tx, nvllpsd.dbSession).NewSelect().Model(nvllp).Where("nvllp.id = ?", id)

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

	return nvllp, nil
}

// GetAll returns all NVLinkLogicalPartitions for a tenant or site
// Errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
// if orderBy is nil, then records are ordered by column specified in NVLinkLogicalPartitionOrderByDefault in ascending order
func (nvllpsd NVLinkLogicalPartitionSQLDAO) GetAll(ctx context.Context, tx *db.Tx, filter NVLinkLogicalPartitionFilterInput, page paginator.PageInput, includeRelations []string) ([]NVLinkLogicalPartition, int, error) {
	// Create a child span and set the attributes for current request
	ctx, NVLinkLogicalPartitionDAOSpan := nvllpsd.tracerSpan.CreateChildInCurrentContext(ctx, "NVLinkLogicalPartitionDAO.GetAll")
	if NVLinkLogicalPartitionDAOSpan != nil {
		defer NVLinkLogicalPartitionDAOSpan.End()
	}

	nvllps := []NVLinkLogicalPartition{}

	query := db.GetIDB(tx, nvllpsd.dbSession).NewSelect().Model(&nvllps)
	if filter.Names != nil {
		query = query.Where("nvllp.name IN (?)", bun.In(filter.Names))
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "name", filter.Names)
	}
	if filter.SiteIDs != nil {
		query = query.Where("nvllp.site_id IN (?)", bun.In(filter.SiteIDs))
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "site_id", filter.SiteIDs)
	}
	if filter.TenantIDs != nil {
		query = query.Where("nvllp.tenant_id IN (?)", bun.In(filter.TenantIDs))
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "tenant_id", filter.TenantIDs)
	}
	if filter.TenantOrgs != nil {
		query = query.Where("nvllp.org IN (?)", bun.In(filter.TenantOrgs))
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "org", filter.TenantOrgs)
	}
	if filter.Statuses != nil {
		query = query.Where("nvllp.status IN (?)", bun.In(filter.Statuses))
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "status", filter.Statuses)
	}
	if filter.NVLinkLogicalPartitionIDs != nil {
		query = query.Where("nvllp.id IN (?)", bun.In(filter.NVLinkLogicalPartitionIDs))
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "id", filter.NVLinkLogicalPartitionIDs)
	}
	searchQuery, searchTokens, ok := db.NormalizeSearchQuery(filter.SearchQuery)
	if ok {
		query = query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				Where("to_tsvector('english', (coalesce(nvllp.name, ' ') || ' ' || coalesce(nvllp.description, ' ') || ' ' || coalesce(nvllp.status, ' '))) @@ to_tsquery('english', ?)", *searchTokens).
				WhereOr("nvllp.name ILIKE ?", "%"+searchQuery+"%").
				WhereOr("nvllp.description ILIKE ?", "%"+searchQuery+"%").
				WhereOr("nvllp.status ILIKE ?", "%"+searchQuery+"%")
		})
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "search_query", searchQuery)
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// if no order is passed, set default to make sure objects return always in the same order and pagination works properly
	if page.OrderBy == nil {
		page.OrderBy = paginator.NewDefaultOrderBy(NVLinkLogicalPartitionOrderByDefault)
	}

	paginator, err := paginator.NewPaginator(ctx, query, page.Offset, page.Limit, page.OrderBy, NVLinkLogicalPartitionOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = paginator.Query.Limit(paginator.Limit).Offset(paginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return nvllps, paginator.Total, nil
}

// Create creates a new NVLinkLogicalPartition from the given parameters
func (nvllpsd NVLinkLogicalPartitionSQLDAO) Create(ctx context.Context, tx *db.Tx, input NVLinkLogicalPartitionCreateInput) (*NVLinkLogicalPartition, error) {
	// Create a child span and set the attributes for current request
	ctx, NVLinkLogicalPartitionDAOSpan := nvllpsd.tracerSpan.CreateChildInCurrentContext(ctx, "NVLinkLogicalPartitionDAO.Create")
	if NVLinkLogicalPartitionDAOSpan != nil {
		defer NVLinkLogicalPartitionDAOSpan.End()

		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "name", input.Name)
	}

	id := uuid.New()

	if input.NVLinkLogicalPartitionID != nil {
		id = *input.NVLinkLogicalPartitionID
	}

	nvllp := &NVLinkLogicalPartition{
		ID:              id,
		Name:            input.Name,
		Description:     input.Description,
		Org:             input.TenantOrg,
		SiteID:          input.SiteID,
		TenantID:        input.TenantID,
		Status:          input.Status,
		IsMissingOnSite: false,
		CreatedBy:       input.CreatedBy,
	}

	_, err := db.GetIDB(tx, nvllpsd.dbSession).NewInsert().Model(nvllp).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nnvllp, err := nvllpsd.GetByID(ctx, tx, nvllp.ID, nil)
	if err != nil {
		return nil, err
	}

	return nnvllp, nil
}

// Update updates an existing NVLinkLogicalPartition from the given parameters
func (nvllpsd NVLinkLogicalPartitionSQLDAO) Update(ctx context.Context, tx *db.Tx, input NVLinkLogicalPartitionUpdateInput) (*NVLinkLogicalPartition, error) {
	// Create a child span and set the attributes for current request
	ctx, NVLinkLogicalPartitionDAOSpan := nvllpsd.tracerSpan.CreateChildInCurrentContext(ctx, "NVLinkLogicalPartitionDAO.Update")
	if NVLinkLogicalPartitionDAOSpan != nil {
		defer NVLinkLogicalPartitionDAOSpan.End()

		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "id", input.NVLinkLogicalPartitionID)
	}

	nvllp := &NVLinkLogicalPartition{
		ID: input.NVLinkLogicalPartitionID,
	}

	updatedFields := []string{}

	if input.Name != nil {
		nvllp.Name = *input.Name
		updatedFields = append(updatedFields, "name")
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "name", *input.Name)
	}
	if input.Description != nil {
		nvllp.Description = input.Description
		updatedFields = append(updatedFields, "description")
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "description", *input.Description)
	}
	if input.Status != nil {
		nvllp.Status = *input.Status
		updatedFields = append(updatedFields, "status")
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "status", *input.Status)
	}
	if input.IsMissingOnSite != nil {
		nvllp.IsMissingOnSite = *input.IsMissingOnSite
		updatedFields = append(updatedFields, "is_missing_on_site")
		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "is_missing_on_site", *input.IsMissingOnSite)
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, nvllpsd.dbSession).NewUpdate().Model(nvllp).Column(updatedFields...).Where("id = ?", nvllp.ID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}
	nnvllp, err := nvllpsd.GetByID(ctx, tx, nvllp.ID, nil)
	if err != nil {
		return nil, err
	}

	return nnvllp, nil
}

// Clear clears NVLinkLogicalPartition attributes based on provided arguments
func (nvllpsd NVLinkLogicalPartitionSQLDAO) Clear(ctx context.Context, tx *db.Tx, input NVLinkLogicalPartitionClearInput) (*NVLinkLogicalPartition, error) {
	// Create a child span and set the attributes for current request
	ctx, NVLinkLogicalPartitionDAOSpan := nvllpsd.tracerSpan.CreateChildInCurrentContext(ctx, "NVLinkLogicalPartitionDAO.Clear")
	if NVLinkLogicalPartitionDAOSpan != nil {
		defer NVLinkLogicalPartitionDAOSpan.End()

		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "id", input.NVLinkLogicalPartitionID)
	}

	nvllp := &NVLinkLogicalPartition{
		ID: input.NVLinkLogicalPartitionID,
	}

	updatedFields := []string{}

	if input.Description {
		nvllp.Description = nil
		updatedFields = append(updatedFields, "description")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, nvllpsd.dbSession).NewUpdate().Model(nvllp).Column(updatedFields...).Where("id = ?", nvllp.ID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nnvllp, err := nvllpsd.GetByID(ctx, tx, nvllp.ID, nil)
	if err != nil {
		return nil, err
	}

	return nnvllp, nil
}

// Delete deletes a NVLinkLogicalPartition by ID
func (nvllpsd NVLinkLogicalPartitionSQLDAO) Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, NVLinkLogicalPartitionDAOSpan := nvllpsd.tracerSpan.CreateChildInCurrentContext(ctx, "NVLinkLogicalPartitionDAO.Delete")
	if NVLinkLogicalPartitionDAOSpan != nil {
		defer NVLinkLogicalPartitionDAOSpan.End()

		nvllpsd.tracerSpan.SetAttribute(NVLinkLogicalPartitionDAOSpan, "id", id.String())
	}

	nvllp := &NVLinkLogicalPartition{
		ID: id,
	}

	_, err := db.GetIDB(tx, nvllpsd.dbSession).NewDelete().Model(nvllp).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewNVLinkLogicalPartitionDAO returns a new NVLinkLogicalPartitionDAO
func NewNVLinkLogicalPartitionDAO(dbSession *db.Session) NVLinkLogicalPartitionDAO {
	return &NVLinkLogicalPartitionSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
