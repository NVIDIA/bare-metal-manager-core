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
	// InfiniBandPartitionStatusPending indicates that the InfiniBandPartition request was received but not yet processed
	InfiniBandPartitionStatusPending = "Pending"
	// InfiniBandPartitionStatusProvisioning indicates that the InfiniBandPartition is being provisioned
	InfiniBandPartitionStatusProvisioning = "Provisioning"
	// InfiniBandPartitionStatusReady indicates that the InfiniBandPartition has been successfully provisioned on the Site
	InfiniBandPartitionStatusReady = "Ready"
	// InfiniBandPartitionStatusConfiguring indicates that the InfiniBandPartition is being configuring
	InfiniBandPartitionStatusConfiguring = "Configuring"
	// InfiniBandPartitionStatusError is the status of a InfiniBandPartition that is in error mode
	InfiniBandPartitionStatusError = "Error"
	// InfiniBandPartitionStatusDeleting indicates that the InfiniBandPartition is being deleted
	InfiniBandPartitionStatusDeleting = "Deleting"
	// InfiniBandPartitionRelationName is the relation name for the InfiniBandPartition model
	InfiniBandPartitionRelationName = "InfiniBandPartition"

	// InfiniBandPartitionOrderByDefault default field to be used for ordering when none specified
	InfiniBandPartitionOrderByDefault = "created"
)

var (
	// InfiniBandPartitionOrderByFields is a list of valid order by fields for the InfiniBandPartition model
	InfiniBandPartitionOrderByFields = []string{"name", "status", "created", "updated"}
	// InfiniBandPartitionRelatedEntities is a list of valid relation by fields for the InfiniBandPartition model
	InfiniBandPartitionRelatedEntities = map[string]bool{
		SiteRelationName:   true,
		TenantRelationName: true,
	}
	// InfiniBandPartitionStatusMap is a list of valid status for the InfiniBandPartition model
	InfiniBandPartitionStatusMap = map[string]bool{
		InfiniBandPartitionStatusPending:      true,
		InfiniBandPartitionStatusProvisioning: true,
		InfiniBandPartitionStatusReady:        true,
		InfiniBandPartitionStatusConfiguring:  true,
		InfiniBandPartitionStatusError:        true,
		InfiniBandPartitionStatusDeleting:     true,
	}
)

// InfiniBandPartition represents entries in the InfiniBandPartition table
type InfiniBandPartition struct {
	bun.BaseModel `bun:"table:infiniband_partition,alias:ibp"`

	ID                      uuid.UUID         `bun:"type:uuid,pk"`
	Name                    string            `bun:"name,notnull"`
	Description             *string           `bun:"description"`
	Org                     string            `bun:"org,notnull"`
	SiteID                  uuid.UUID         `bun:"site_id,type:uuid,notnull"`
	Site                    *Site             `bun:"rel:belongs-to,join:site_id=id"`
	TenantID                uuid.UUID         `bun:"tenant_id,type:uuid,notnull"`
	Tenant                  *Tenant           `bun:"rel:belongs-to,join:tenant_id=id"`
	ControllerIBPartitionID *uuid.UUID        `bun:"controller_ib_partition_id,type:uuid"`
	PartitionKey            *string           `bun:"partition_key"`
	PartitionName           *string           `bun:"partition_name"`
	ServiceLevel            *int              `bun:"service_level"`
	RateLimit               *float32          `bun:"rate_limit"`
	Mtu                     *int              `bun:"mtu"`
	EnableSharp             *bool             `bun:"enable_sharp"`
	Labels                  map[string]string `bun:"labels,type:jsonb"`
	Status                  string            `bun:"status,notnull"`
	IsMissingOnSite         bool              `bun:"is_missing_on_site,notnull"`
	Created                 time.Time         `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated                 time.Time         `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted                 *time.Time        `bun:"deleted,soft_delete"`
	CreatedBy               uuid.UUID         `bun:"type:uuid,notnull"`
}

// InfiniBandPartitionCreateInput input parameters for Create method
type InfiniBandPartitionCreateInput struct {
	InfiniBandPartitionID   *uuid.UUID
	Name                    string
	Description             *string
	TenantOrg               string
	SiteID                  uuid.UUID
	TenantID                uuid.UUID
	ControllerIBPartitionID *uuid.UUID
	PartitionKey            *string
	PartitionName           *string
	ServiceLevel            *int
	RateLimit               *float32
	Mtu                     *int
	EnableSharp             *bool
	Labels                  map[string]string
	Status                  string
	CreatedBy               uuid.UUID
}

// InfiniBandPartitionUpdateInput input parameters for Update method
type InfiniBandPartitionUpdateInput struct {
	InfiniBandPartitionID   uuid.UUID
	Name                    *string
	Description             *string
	ControllerIBPartitionID *uuid.UUID
	PartitionKey            *string
	PartitionName           *string
	ServiceLevel            *int
	RateLimit               *float32
	Mtu                     *int
	EnableSharp             *bool
	Labels                  map[string]string
	Status                  *string
	IsMissingOnSite         *bool
}

// InfiniBandPartitionClearInput input parameters for Clear method
type InfiniBandPartitionClearInput struct {
	InfiniBandPartitionID   uuid.UUID
	Description             bool
	ControllerIBPartitionID bool
	PartitionKey            bool
	PartitionName           bool
	ServiceLevel            bool
	RateLimit               bool
	Mtu                     bool
	EnableSharp             bool
	Labels                  bool
}

// InfiniBandPartitionFilterInput input parameters for Filter method
type InfiniBandPartitionFilterInput struct {
	InfiniBandPartitionIDs []uuid.UUID
	Names                  []string
	SiteIDs                []uuid.UUID
	TenantOrgs             []string
	TenantIDs              []uuid.UUID
	Statuses               []string
	SearchQuery            *string
	PartitionNames         []string
	PartitionKeys          []string
	SharpEnabled           *bool
}

var _ bun.BeforeAppendModelHook = (*InfiniBandPartition)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (ibp *InfiniBandPartition) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		ibp.Created = db.GetCurTime()
		ibp.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		ibp.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*InfiniBandPartition)(nil)

// BeforeCreateTable is a hook that is called before the table is created
func (ibp *InfiniBandPartition) BeforeCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey(`("tenant_id") REFERENCES "tenant" ("id")`).
		ForeignKey(`("site_id") REFERENCES "site" ("id")`)
	return nil
}

// InfiniBandPartitionDAO is an interface for interacting with the InfiniBandPartition model
type InfiniBandPartitionDAO interface {
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*InfiniBandPartition, error)
	//
	GetAll(ctx context.Context, tx *db.Tx, filter InfiniBandPartitionFilterInput, page paginator.PageInput, includeRelations []string) ([]InfiniBandPartition, int, error)
	//
	Create(ctx context.Context, tx *db.Tx, input InfiniBandPartitionCreateInput) (*InfiniBandPartition, error)
	//
	Update(ctx context.Context, tx *db.Tx, input InfiniBandPartitionUpdateInput) (*InfiniBandPartition, error)
	//
	Clear(ctx context.Context, tx *db.Tx, input InfiniBandPartitionClearInput) (*InfiniBandPartition, error)
	//
	Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// InfiniBandPartitionSQLDAO is an implementation of the InfiniBandPartitionDAO interface
type InfiniBandPartitionSQLDAO struct {
	dbSession  *db.Session
	tracerSpan *stracer.TracerSpan
}

// GetByID returns a InfiniBandPartition by ID
func (ibpsd InfiniBandPartitionSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*InfiniBandPartition, error) {
	// Create a child span and set the attributes for current request
	ctx, PartitionDAOSpan := ibpsd.tracerSpan.CreateChildInCurrentContext(ctx, "PartitionDAO.GetByID")
	if PartitionDAOSpan != nil {
		defer PartitionDAOSpan.End()

		ibpsd.tracerSpan.SetAttribute(PartitionDAOSpan, "id", id.String())
	}

	p := &InfiniBandPartition{}

	query := db.GetIDB(tx, ibpsd.dbSession).NewSelect().Model(p).Where("ibp.id = ?", id)

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

	return p, nil
}

// GetAll returns all Partitions for a tenant or site
// Errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
// if orderBy is nil, then records are ordered by column specified in InfiniBandPartitionOrderByDefault in ascending order
func (ibpsd InfiniBandPartitionSQLDAO) GetAll(ctx context.Context, tx *db.Tx, filter InfiniBandPartitionFilterInput, page paginator.PageInput, includeRelations []string) ([]InfiniBandPartition, int, error) {
	// Create a child span and set the attributes for current request
	ctx, InfiniBandPartitionDAOSpan := ibpsd.tracerSpan.CreateChildInCurrentContext(ctx, "PartitionDAO.GetAll")
	if InfiniBandPartitionDAOSpan != nil {
		defer InfiniBandPartitionDAOSpan.End()
	}

	ibps := []InfiniBandPartition{}

	query := db.GetIDB(tx, ibpsd.dbSession).NewSelect().Model(&ibps)
	if filter.Names != nil {
		query = query.Where("ibp.name IN (?)", bun.In(filter.Names))
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "name", filter.Names)
	}
	if filter.SharpEnabled != nil {
		query = query.Where("ibp.enable_sharp = ?", filter.SharpEnabled)
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "enable_sharp", filter.SharpEnabled)
	}
	if filter.SiteIDs != nil {
		query = query.Where("ibp.site_id IN (?)", bun.In(filter.SiteIDs))
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "site_id", filter.SiteIDs)
	}
	if filter.TenantIDs != nil {
		query = query.Where("ibp.tenant_id IN (?)", bun.In(filter.TenantIDs))
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "tenant_id", filter.TenantIDs)
	}
	if filter.TenantOrgs != nil {
		query = query.Where("ibp.org IN (?)", bun.In(filter.TenantOrgs))
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "org", filter.TenantOrgs)
	}
	if filter.Statuses != nil {
		query = query.Where("ibp.status IN (?)", bun.In(filter.Statuses))
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "status", filter.Statuses)
	}
	if filter.InfiniBandPartitionIDs != nil {
		query = query.Where("ibp.id IN (?)", bun.In(filter.InfiniBandPartitionIDs))
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "id", filter.InfiniBandPartitionIDs)
	}

	if filter.PartitionKeys != nil {
		query = query.Where("ibp.partition_key IN (?)", bun.In(filter.PartitionKeys))
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "partition_key", filter.PartitionKeys)
	}
	if filter.PartitionNames != nil {
		query = query.Where("ibp.partition_name IN (?)", bun.In(filter.PartitionNames))
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "partition_name", filter.PartitionNames)
	}

	searchQuery, searchTokens, ok := db.NormalizeSearchQuery(filter.SearchQuery)
	if ok {
		query = query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				Where("to_tsvector('english', (coalesce(ibp.name, ' ') || ' ' || coalesce(ibp.description, ' ') || ' ' || coalesce(ibp.partition_key, ' ') || ' ' || coalesce(ibp.partition_name, ' ') || ' ' || coalesce(ibp.status, ' ') || ' ' || coalesce(ibp.labels::text, ' '))) @@ to_tsquery('english', ?)", *searchTokens).
				WhereOr("ibp.name ILIKE ?", "%"+searchQuery+"%").
				WhereOr("ibp.description ILIKE ?", "%"+searchQuery+"%").
				WhereOr("ibp.partition_key ILIKE ?", "%"+searchQuery+"%").
				WhereOr("ibp.partition_name ILIKE ?", "%"+searchQuery+"%").
				WhereOr("ibp.status ILIKE ?", "%"+searchQuery+"%").
				WhereOr("ibp.labels::text ILIKE ?", "%"+searchQuery+"%")
		})
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "search_query", searchQuery)
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// if no order is passed, set default to make sure objects return always in the same order and pagination works properly
	if page.OrderBy == nil {
		page.OrderBy = paginator.NewDefaultOrderBy(InfiniBandPartitionOrderByDefault)
	}

	paginator, err := paginator.NewPaginator(ctx, query, page.Offset, page.Limit, page.OrderBy, InfiniBandPartitionOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = paginator.Query.Limit(paginator.Limit).Offset(paginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return ibps, paginator.Total, nil
}

// Create creates a new InfiniBandPartition from the given parameters
func (ibpsd InfiniBandPartitionSQLDAO) Create(ctx context.Context, tx *db.Tx, input InfiniBandPartitionCreateInput) (*InfiniBandPartition, error) {
	// Create a child span and set the attributes for current request
	ctx, InfiniBandPartitionDAOSpan := ibpsd.tracerSpan.CreateChildInCurrentContext(ctx, "InfiniBandPartitionDAO.Create")
	if InfiniBandPartitionDAOSpan != nil {
		defer InfiniBandPartitionDAOSpan.End()

		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "name", input.Name)
	}

	id := uuid.New()

	if input.InfiniBandPartitionID != nil {
		id = *input.InfiniBandPartitionID
	}

	ibp := &InfiniBandPartition{
		ID:                      id,
		Name:                    input.Name,
		Description:             input.Description,
		Org:                     input.TenantOrg,
		SiteID:                  input.SiteID,
		TenantID:                input.TenantID,
		ControllerIBPartitionID: input.ControllerIBPartitionID,
		PartitionKey:            input.PartitionKey,
		PartitionName:           input.PartitionName,
		ServiceLevel:            input.ServiceLevel,
		RateLimit:               input.RateLimit,
		Mtu:                     input.Mtu,
		EnableSharp:             input.EnableSharp,
		Labels:                  input.Labels,
		Status:                  input.Status,
		IsMissingOnSite:         false,
		CreatedBy:               input.CreatedBy,
	}

	_, err := db.GetIDB(tx, ibpsd.dbSession).NewInsert().Model(ibp).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nibp, err := ibpsd.GetByID(ctx, tx, ibp.ID, nil)
	if err != nil {
		return nil, err
	}

	return nibp, nil
}

// Update updates an existing InfiniBandPartition from the given parameters
func (ibpsd InfiniBandPartitionSQLDAO) Update(ctx context.Context, tx *db.Tx, input InfiniBandPartitionUpdateInput) (*InfiniBandPartition, error) {
	// Create a child span and set the attributes for current request
	ctx, InfiniBandPartitionDAOSpan := ibpsd.tracerSpan.CreateChildInCurrentContext(ctx, "InfiniBandPartitionDAO.Update")
	if InfiniBandPartitionDAOSpan != nil {
		defer InfiniBandPartitionDAOSpan.End()

		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "id", input.InfiniBandPartitionID)
	}

	ibp := &InfiniBandPartition{
		ID: input.InfiniBandPartitionID,
	}

	updatedFields := []string{}

	if input.Name != nil {
		ibp.Name = *input.Name
		updatedFields = append(updatedFields, "name")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "name", *input.Name)
	}
	if input.Description != nil {
		ibp.Description = input.Description
		updatedFields = append(updatedFields, "description")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "description", *input.Description)
	}
	if input.ControllerIBPartitionID != nil {
		ibp.ControllerIBPartitionID = input.ControllerIBPartitionID
		updatedFields = append(updatedFields, "controller_ib_partition_id")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "controller_ib_partition_id", input.ControllerIBPartitionID)
	}
	if input.PartitionKey != nil {
		ibp.PartitionKey = input.PartitionKey
		updatedFields = append(updatedFields, "partition_key")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "partition_key", *input.PartitionKey)
	}
	if input.PartitionName != nil {
		ibp.PartitionName = input.PartitionName
		updatedFields = append(updatedFields, "partition_name")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "partition_name", *input.PartitionName)
	}
	if input.ServiceLevel != nil {
		ibp.ServiceLevel = input.ServiceLevel
		updatedFields = append(updatedFields, "service_level")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "service_level", *input.ServiceLevel)
	}
	if input.RateLimit != nil {
		ibp.RateLimit = input.RateLimit
		updatedFields = append(updatedFields, "rate_limit")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "rate_limit", *input.RateLimit)
	}
	if input.Mtu != nil {
		ibp.Mtu = input.Mtu
		updatedFields = append(updatedFields, "mtu")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "mtu", *input.Mtu)
	}
	if input.EnableSharp != nil {
		ibp.EnableSharp = input.EnableSharp
		updatedFields = append(updatedFields, "enable_sharp")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "enable_sharp", *input.EnableSharp)
	}
	if input.Labels != nil {
		ibp.Labels = input.Labels
		updatedFields = append(updatedFields, "labels")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "labels", input.Labels)
	}
	if input.Status != nil {
		ibp.Status = *input.Status
		updatedFields = append(updatedFields, "status")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "status", *input.Status)
	}
	if input.IsMissingOnSite != nil {
		ibp.IsMissingOnSite = *input.IsMissingOnSite
		updatedFields = append(updatedFields, "is_missing_on_site")
		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "is_missing_on_site", *input.IsMissingOnSite)
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, ibpsd.dbSession).NewUpdate().Model(ibp).Column(updatedFields...).Where("id = ?", ibp.ID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}
	nibp, err := ibpsd.GetByID(ctx, tx, ibp.ID, nil)
	if err != nil {
		return nil, err
	}

	return nibp, nil
}

// Clear clears InfiniBandPartition attributes based on provided arguments
func (ibpsd InfiniBandPartitionSQLDAO) Clear(ctx context.Context, tx *db.Tx, input InfiniBandPartitionClearInput) (*InfiniBandPartition, error) {
	// Create a child span and set the attributes for current request
	ctx, InfiniBandPartitionDAOSpan := ibpsd.tracerSpan.CreateChildInCurrentContext(ctx, "InfiniBandPartitionDAO.Clear")
	if InfiniBandPartitionDAOSpan != nil {
		defer InfiniBandPartitionDAOSpan.End()

		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "id", input.InfiniBandPartitionID)
	}

	ibp := &InfiniBandPartition{
		ID: input.InfiniBandPartitionID,
	}

	updatedFields := []string{}

	if input.Description {
		ibp.Description = nil
		updatedFields = append(updatedFields, "description")
	}

	if input.ControllerIBPartitionID {
		ibp.ControllerIBPartitionID = nil
		updatedFields = append(updatedFields, "controller_ib_partition_id")
	}
	if input.PartitionKey {
		ibp.PartitionKey = nil
		updatedFields = append(updatedFields, "partition_key")
	}
	if input.PartitionName {
		ibp.PartitionName = nil
		updatedFields = append(updatedFields, "partition_name")
	}
	if input.ServiceLevel {
		ibp.ServiceLevel = nil
		updatedFields = append(updatedFields, "service_level")
	}
	if input.RateLimit {
		ibp.RateLimit = nil
		updatedFields = append(updatedFields, "rate_limit")
	}
	if input.Mtu {
		ibp.Mtu = nil
		updatedFields = append(updatedFields, "mtu")
	}
	if input.EnableSharp {
		ibp.EnableSharp = nil
		updatedFields = append(updatedFields, "enable_sharp")
	}
	if input.Labels {
		ibp.Labels = nil
		updatedFields = append(updatedFields, "labels")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, ibpsd.dbSession).NewUpdate().Model(ibp).Column(updatedFields...).Where("id = ?", ibp.ID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nibp, err := ibpsd.GetByID(ctx, tx, ibp.ID, nil)
	if err != nil {
		return nil, err
	}

	return nibp, nil
}

// Delete deletes a InfiniBandPartition by ID
func (ibpsd InfiniBandPartitionSQLDAO) Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, InfiniBandPartitionDAOSpan := ibpsd.tracerSpan.CreateChildInCurrentContext(ctx, "InfiniBandPartitionDAO.Delete")
	if InfiniBandPartitionDAOSpan != nil {
		defer InfiniBandPartitionDAOSpan.End()

		ibpsd.tracerSpan.SetAttribute(InfiniBandPartitionDAOSpan, "id", id.String())
	}

	ibp := &InfiniBandPartition{
		ID: id,
	}

	_, err := db.GetIDB(tx, ibpsd.dbSession).NewDelete().Model(ibp).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewInfiniBandPartitionDAO returns a new InfiniBandPartitionDAO
func NewInfiniBandPartitionDAO(dbSession *db.Session) InfiniBandPartitionDAO {
	return &InfiniBandPartitionSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
