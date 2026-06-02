// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	"github.com/google/uuid"

	"github.com/uptrace/bun"

	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
)

const (
	// IPBlockStatusPending status is pending
	IPBlockStatusPending = "Pending"
	// IPBlockStatusProvisioning status is provisioning
	IPBlockStatusProvisioning = "Provisioning"
	// IPBlockStatusReady status is ready
	IPBlockStatusReady = "Ready"
	// IPBlockStatusError status is error
	IPBlockStatusError = "Error"
	// IPBlockStatusDeleting indicates that the IPBlock is being deleted
	IPBlockStatusDeleting = "Deleting"

	// IPBlockRoutingTypePublic routing type is Public
	IPBlockRoutingTypePublic = "Public"
	// IPBlockRoutingTypeDatacenterOnly routing type is DatacenterOnly
	IPBlockRoutingTypeDatacenterOnly = "DatacenterOnly"

	// IPBlockProtocolVersionV4 protocol version is ipv4
	IPBlockProtocolVersionV4 = "IPv4"
	// IPBlockProtocolVersionV6 protocol version is ipv6
	IPBlockProtocolVersionV6 = "IPv6"
	// IPBlockRelationName is the relation name for the IPBlock model
	IPBlockRelationName = "IPBlock"
	// IPv4BlockRelationName is the relation name for the IPBlock model
	IPv4BlockRelationName = "IPv4Block"
	// IPv6BlockRelationName is the relation name for the IPBlock model
	IPv6BlockRelationName = "IPv6Block"

	// IPBlockOrderByDefault default field to be used for ordering when none specified
	IPBlockOrderByDefault = "created"
)

var (
	// IPBlockOrderByFields is a list of valid order by fields for the IPBlock model
	IPBlockOrderByFields = []string{"name", "prefix", "status", "created", "updated"}
	// IPBlockRelatedEntities is a list of valid relation by fields for the IPBlock model
	IPBlockRelatedEntities = map[string]bool{
		SiteRelationName:                   true,
		InfrastructureProviderRelationName: true,
		TenantRelationName:                 true,
	}
	// IPBlockStatusMap is a list of valid status for the IPBlock model
	IPBlockStatusMap = map[string]bool{
		IPBlockStatusPending:      true,
		IPBlockStatusProvisioning: true,
		IPBlockStatusReady:        true,
		IPBlockStatusError:        true,
		IPBlockStatusDeleting:     true,
	}
)

// IPBlock contains information about an IPv4/v6 address pool owned
// by the InfrastructureProvider and assigned as an overlay network
// for a particular site
type IPBlock struct {
	bun.BaseModel `bun:"table:ip_block,alias:ipb"`

	ID                       uuid.UUID               `bun:"type:uuid,pk"`
	Name                     string                  `bun:"name,notnull"`
	Description              *string                 `bun:"description"`
	SiteID                   uuid.UUID               `bun:"site_id,type:uuid,notnull"`
	Site                     *Site                   `bun:"rel:belongs-to,join:site_id=id"`
	InfrastructureProviderID uuid.UUID               `bun:"infrastructure_provider_id,type:uuid,notnull"`
	InfrastructureProvider   *InfrastructureProvider `bun:"rel:belongs-to,join:infrastructure_provider_id=id"`
	TenantID                 *uuid.UUID              `bun:"tenant_id,type:uuid"`
	Tenant                   *Tenant                 `bun:"rel:belongs-to,join:tenant_id=id"`
	RoutingType              string                  `bun:"routing_type,notnull"`
	Prefix                   string                  `bun:"prefix,notnull"`
	PrefixLength             int                     `bun:"prefix_length,notnull"`
	ProtocolVersion          string                  `bun:"protocol_version,notnull"`
	FullGrant                bool                    `bun:"full_grant,notnull"`
	Status                   string                  `bun:"status,notnull"`
	Created                  time.Time               `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated                  time.Time               `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted                  *time.Time              `bun:"deleted,soft_delete"`
	CreatedBy                *uuid.UUID              `bun:"created_by,type:uuid"`
}

// IPBlockCreateInput input parameters for Create method
type IPBlockCreateInput struct {
	IPBlockID                *uuid.UUID
	Name                     string
	Description              *string
	SiteID                   uuid.UUID
	InfrastructureProviderID uuid.UUID
	TenantID                 *uuid.UUID
	RoutingType              string
	Prefix                   string
	PrefixLength             int
	ProtocolVersion          string
	FullGrant                bool
	Status                   string
	CreatedBy                *uuid.UUID
}

// IPBlockUpdateInput input parameters for Update method
type IPBlockUpdateInput struct {
	IPBlockID                uuid.UUID
	Name                     *string
	Description              *string
	SiteID                   *uuid.UUID
	InfrastructureProviderID *uuid.UUID
	TenantID                 *uuid.UUID
	RoutingType              *string
	Prefix                   *string
	PrefixLength             *int
	ProtocolVersion          *string
	FullGrant                *bool
	Status                   *string
}

// IPBlockClearInput input parameters for Clear method
type IPBlockClearInput struct {
	IPBlockID   uuid.UUID
	Description bool
	TenantID    bool
}

// IPBlockFilterInput input parameters for Filter method
type IPBlockFilterInput struct {
	IPBlockIDs                []uuid.UUID
	Names                     []string
	SiteIDs                   []uuid.UUID
	InfrastructureProviderIDs []uuid.UUID
	TenantIDs                 []uuid.UUID
	RoutingTypes              []string
	Prefixes                  []string
	PrefixLengths             []int
	ProtocolVersions          []string
	FullGrant                 *bool
	Statuses                  []string
	ExcludeDerived            bool
	SearchQuery               *string
}

var _ bun.BeforeAppendModelHook = (*IPBlock)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (ipb *IPBlock) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		ipb.Created = db.GetCurTime()
		ipb.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		ipb.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*IPBlock)(nil)

// BeforeCreateTable is a hook that is called before the table is created
func (it *IPBlock) BeforeCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey(`("site_id") REFERENCES "site" ("id")`).
		ForeignKey(`("infrastructure_provider_id") REFERENCES "infrastructure_provider" ("id")`).
		ForeignKey(`("tenant_id") REFERENCES "tenant" ("id")`)
	return nil
}

// IPBlockDAO is an interface for interacting with the IPBlock model
type IPBlockDAO interface {
	//
	Create(ctx context.Context, tx *db.Tx, input IPBlockCreateInput) (*IPBlock, error)
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*IPBlock, error)
	//
	GetCountByStatus(ctx context.Context, tx *db.Tx, infrastructureProviderID *uuid.UUID, siteID *uuid.UUID, tenantID *uuid.UUID) (map[string]int, error)
	//
	GetAll(ctx context.Context, tx *db.Tx, filter IPBlockFilterInput, page paginator.PageInput, includeRelations []string) ([]IPBlock, int, error)
	//
	Update(ctx context.Context, tx *db.Tx, input IPBlockUpdateInput) (*IPBlock, error)
	//
	Clear(ctx context.Context, tx *db.Tx, input IPBlockClearInput) (*IPBlock, error)
	//
	Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// IPBlockSQLDAO is an implementation of the IPBlockDAO interface
type IPBlockSQLDAO struct {
	dbSession *db.Session
	IPBlockDAO
	tracerSpan *stracer.TracerSpan
}

// Create creates a new IPBlock from the given parameters
// The returned IPBlock will not have any related structs (Site/InfrastructureProvider/Tenant) filled in
// since there are 2 operations (INSERT, SELECT), in this, it is required that
// this library call happens within a transaction
func (ipbsd IPBlockSQLDAO) Create(ctx context.Context, tx *db.Tx, input IPBlockCreateInput) (*IPBlock, error) {
	// Create a child span and set the attributes for current request
	ctx, ipblockDAOSpan := ipbsd.tracerSpan.CreateChildInCurrentContext(ctx, "IPBlockDAO.Create")
	if ipblockDAOSpan != nil {
		defer ipblockDAOSpan.End()

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "name", input.Name)
	}

	id := uuid.New()

	if input.IPBlockID != nil {
		id = *input.IPBlockID
	}

	ipb := &IPBlock{
		ID:                       id,
		Name:                     input.Name,
		Description:              input.Description,
		SiteID:                   input.SiteID,
		InfrastructureProviderID: input.InfrastructureProviderID,
		TenantID:                 input.TenantID,
		RoutingType:              input.RoutingType,
		Prefix:                   input.Prefix,
		PrefixLength:             input.PrefixLength,
		ProtocolVersion:          input.ProtocolVersion,
		FullGrant:                input.FullGrant,
		Status:                   input.Status,
		CreatedBy:                input.CreatedBy,
	}

	_, err := db.GetIDB(tx, ipbsd.dbSession).NewInsert().Model(ipb).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nv, err := ipbsd.GetByID(ctx, tx, ipb.ID, nil)
	if err != nil {
		return nil, err
	}

	return nv, nil
}

// GetByID returns a IPBlock by ID
// includeRelation can be a subset of "Site", "InfrastructureProvider", "Tenant"
// returns db.ErrDoesNotExist error if the record is not found
func (ipbsd IPBlockSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*IPBlock, error) {
	// Create a child span and set the attributes for current request
	ctx, ipblockDAOSpan := ipbsd.tracerSpan.CreateChildInCurrentContext(ctx, "IPBlockDAO.GetByID")
	if ipblockDAOSpan != nil {
		defer ipblockDAOSpan.End()

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "id", id.String())
	}

	ipb := &IPBlock{}

	query := db.GetIDB(tx, ipbsd.dbSession).NewSelect().Model(ipb).Where("ipb.id = ?", id)

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

	return ipb, nil
}

// GetCountByStatus returns count of IPBlocks for given status
// Errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned map is 0
func (ipbsd IPBlockSQLDAO) GetCountByStatus(ctx context.Context, tx *db.Tx, infrastructureProviderID *uuid.UUID, siteID *uuid.UUID, tenantID *uuid.UUID) (map[string]int, error) {
	// Create a child span and set the attributes for current request
	ctx, ipblockDAOSpan := ipbsd.tracerSpan.CreateChildInCurrentContext(ctx, "IPBlockDAO.GetCountByStatus")
	if ipblockDAOSpan != nil {
		defer ipblockDAOSpan.End()
	}

	ipb := &IPBlock{}
	var statusQueryResults []map[string]interface{}

	query := db.GetIDB(tx, ipbsd.dbSession).NewSelect().Model(ipb)
	if infrastructureProviderID != nil {
		query = query.Where("ipb.infrastructure_provider_id = ?", *infrastructureProviderID)

		if ipblockDAOSpan != nil {
			ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "infrastructure_provider_id", infrastructureProviderID.String())
		}
	}
	if siteID != nil {
		query = query.Where("ipb.site_id = ?", *siteID)

		if ipblockDAOSpan != nil {
			ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "site_id", siteID.String())
		}
	}
	if tenantID != nil {
		query = query.Where("ipb.tenant_id = ?", *tenantID)

		if ipblockDAOSpan != nil {
			ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "tenant_id", tenantID.String())
		}
	}

	err := query.Column("ipb.status").ColumnExpr("COUNT(*) AS total_count").GroupExpr("ipb.status").Scan(ctx, &statusQueryResults)
	if err != nil {
		return nil, err
	}

	// creare results map by holding key as status value with total count
	results := map[string]int{
		"total":                   0,
		IPBlockStatusDeleting:     0,
		IPBlockStatusError:        0,
		IPBlockStatusReady:        0,
		IPBlockStatusProvisioning: 0,
		IPBlockStatusPending:      0,
	}
	if len(statusQueryResults) > 0 {
		for _, statusMap := range statusQueryResults {
			results[statusMap["status"].(string)] = int(statusMap["total_count"].(int64))
			results["total"] = results["total"] + int(statusMap["total_count"].(int64))
		}
	}
	return results, nil
}

// GetAll returns all IPBlocks filtering by Site, InfrastructureProvider
// Tenant,  RoutingType or Name
// errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
// if orderBy is nil, then records are ordered by column specified in IPBlockOrderByDefault in ascending order
func (ipbsd IPBlockSQLDAO) GetAll(ctx context.Context, tx *db.Tx, filter IPBlockFilterInput, page paginator.PageInput, includeRelations []string) ([]IPBlock, int, error) {
	// Create a child span and set the attributes for current request
	ctx, ipblockDAOSpan := ipbsd.tracerSpan.CreateChildInCurrentContext(ctx, "IPBlockDAO.GetAll")
	if ipblockDAOSpan != nil {
		defer ipblockDAOSpan.End()
	}

	ipbs := []IPBlock{}

	query := db.GetIDB(tx, ipbsd.dbSession).NewSelect().Model(&ipbs)
	if filter.SiteIDs != nil {
		query = query.Where("ipb.site_id IN (?)", bun.In(filter.SiteIDs))
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "site_id", filter.SiteIDs)
	}
	if filter.InfrastructureProviderIDs != nil {
		query = query.Where("ipb.infrastructure_provider_id IN (?)", bun.In(filter.InfrastructureProviderIDs))
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "infrastructure_provider_id", filter.InfrastructureProviderIDs)
	}
	if filter.TenantIDs != nil {
		if filter.ExcludeDerived {
			return nil, 0, db.ErrInvalidParams
		}

		query = query.Where("ipb.tenant_id IN (?)", bun.In(filter.TenantIDs))
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "tenant_id", filter.TenantIDs)
	}
	if filter.RoutingTypes != nil {
		query = query.Where("ipb.routing_type IN (?)", bun.In(filter.RoutingTypes))
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "routing_type", filter.RoutingTypes)
	}
	if filter.Names != nil {
		query = query.Where("ipb.name IN (?)", bun.In(filter.Names))
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "name", filter.Names)
	}
	if filter.FullGrant != nil {
		query = query.Where("ipb.full_grant = ?", *filter.FullGrant)
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "full_grant", filter.FullGrant)
	}
	if filter.ExcludeDerived {
		query = query.Where("ipb.tenant_id IS ?", nil)
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "exclude_derived", filter.ExcludeDerived)
	}
	if filter.Prefixes != nil {
		query = query.Where("ipb.prefix IN (?)", bun.In(filter.Prefixes))
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "prefix", filter.Prefixes)
	}
	if filter.PrefixLengths != nil {
		query = query.Where("ipb.prefix_length IN (?)", bun.In(filter.PrefixLengths))
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "prefix_length", filter.PrefixLengths)
	}
	if filter.Statuses != nil {
		query = query.Where("ipb.status IN (?)", bun.In(filter.Statuses))
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "status", filter.Statuses)
	}

	if filter.IPBlockIDs != nil {
		query = query.Where("ipb.id IN (?)", bun.In(filter.IPBlockIDs))
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "id", filter.IPBlockIDs)
	}

	searchQuery, searchTokens, ok := db.NormalizeSearchQuery(filter.SearchQuery)
	if ok {
		query = query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				Where("to_tsvector('english', (coalesce(ipb.name, ' ') || ' ' || coalesce(ipb.description, ' ') || ' ' || coalesce(ipb.status, ' '))) @@ to_tsquery('english', ?)", *searchTokens).
				WhereOr("ipb.name ILIKE ?", "%"+searchQuery+"%").
				WhereOr("ipb.description ILIKE ?", "%"+searchQuery+"%").
				WhereOr("ipb.status ILIKE ?", "%"+searchQuery+"%")
		})

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "search_query", searchQuery)
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// if no order is passed, set default to make sure objects return always in the same order and pagination works properly
	if page.OrderBy == nil {
		page.OrderBy = paginator.NewDefaultOrderBy(IPBlockOrderByDefault)
	}

	paginator, err := paginator.NewPaginator(ctx, query, page.Offset, page.Limit, page.OrderBy, IPBlockOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = paginator.Query.Limit(paginator.Limit).Offset(paginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return ipbs, paginator.Total, nil
}

// Update updates specified fields of an existing IPBlock
// The updated fields are assumed to be set to non-null values
// For setting to null values, use: ClearFromParams
// since there are 2 operations (UPDATE, SELECT), in this, it is required that
// this library call happens within a transaction
func (ipbsd IPBlockSQLDAO) Update(ctx context.Context, tx *db.Tx, input IPBlockUpdateInput) (*IPBlock, error) {
	// Create a child span and set the attributes for current request
	ctx, ipblockDAOSpan := ipbsd.tracerSpan.CreateChildInCurrentContext(ctx, "IPBlockDAO.Update")
	if ipblockDAOSpan != nil {
		defer ipblockDAOSpan.End()
	}

	ipb := &IPBlock{
		ID: input.IPBlockID,
	}

	updatedFields := []string{}

	if input.Name != nil {
		ipb.Name = *input.Name
		updatedFields = append(updatedFields, "name")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "name", *input.Name)
	}
	if input.Description != nil {
		ipb.Description = input.Description
		updatedFields = append(updatedFields, "description")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "description", *input.Description)
	}
	if input.SiteID != nil {
		ipb.SiteID = *input.SiteID
		updatedFields = append(updatedFields, "site_id")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "site_id", input.SiteID)
	}
	if input.InfrastructureProviderID != nil {
		ipb.InfrastructureProviderID = *input.InfrastructureProviderID
		updatedFields = append(updatedFields, "infrastructure_provider_id")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "infrastructure_provider_id", input.InfrastructureProviderID)
	}
	if input.TenantID != nil {
		ipb.TenantID = input.TenantID
		updatedFields = append(updatedFields, "tenant_id")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "tenant_id", input.TenantID)
	}
	if input.RoutingType != nil {
		ipb.RoutingType = *input.RoutingType
		updatedFields = append(updatedFields, "routing_type")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "routing_type", *input.RoutingType)
	}
	if input.Prefix != nil {
		ipb.Prefix = *input.Prefix
		updatedFields = append(updatedFields, "prefix")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "prefix", *input.Prefix)
	}
	if input.PrefixLength != nil {
		ipb.PrefixLength = *input.PrefixLength
		updatedFields = append(updatedFields, "prefix_length")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "prefix_length", *input.PrefixLength)
	}
	if input.ProtocolVersion != nil {
		ipb.ProtocolVersion = *input.ProtocolVersion
		updatedFields = append(updatedFields, "protocol_version")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "protocol_version", *input.ProtocolVersion)
	}
	if input.FullGrant != nil {
		ipb.FullGrant = *input.FullGrant
		updatedFields = append(updatedFields, "full_grant")

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "full_grant", *input.FullGrant)
	}
	if input.Status != nil {
		ipb.Status = *input.Status
		updatedFields = append(updatedFields, "status")
		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "name", *input.Status)
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, ipbsd.dbSession).NewUpdate().Model(ipb).Column(updatedFields...).Where("id = ?", ipb.ID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := ipbsd.GetByID(ctx, tx, ipb.ID, nil)

	if err != nil {
		return nil, err
	}
	return nv, nil
}

// ClearFromParams sets parameters of an existing IPBlock to null values in db
// parameters displayName, description, siteID when true, the are set to null in db
// since there are 2 operations (UPDATE, SELECT), it is required that
// this must be within a transaction
func (ipbsd IPBlockSQLDAO) Clear(ctx context.Context, tx *db.Tx, input IPBlockClearInput) (*IPBlock, error) {
	// Create a child span and set the attributes for current request
	ctx, ipblockDAOSpan := ipbsd.tracerSpan.CreateChildInCurrentContext(ctx, "IPBlockDAO.ClearFromParams")
	if ipblockDAOSpan != nil {
		defer ipblockDAOSpan.End()

		ipbsd.tracerSpan.SetAttribute(ipblockDAOSpan, "id", input.IPBlockID)
	}

	ipb := &IPBlock{
		ID: input.IPBlockID,
	}

	updatedFields := []string{}

	if input.Description {
		ipb.Description = nil
		updatedFields = append(updatedFields, "description")
	}
	if input.TenantID {
		ipb.TenantID = nil
		updatedFields = append(updatedFields, "tenant_id")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, ipbsd.dbSession).NewUpdate().Model(ipb).Column(updatedFields...).Where("id = ?", input.IPBlockID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := ipbsd.GetByID(ctx, tx, ipb.ID, nil)
	if err != nil {
		return nil, err
	}
	return nv, nil
}

// Delete deletes an IPBlock by ID
// error is returned only if there is a db error
// if the object being deleted doesnt exist, error is not returned (idempotent delete)
func (ipbsd IPBlockSQLDAO) Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, ipblockDAOSpan := ipbsd.tracerSpan.CreateChildInCurrentContext(ctx, "IPBlockDAO.Delete")
	if ipblockDAOSpan != nil {
		defer ipblockDAOSpan.End()
	}

	ipb := &IPBlock{
		ID: id,
	}

	_, err := db.GetIDB(tx, ipbsd.dbSession).NewDelete().Model(ipb).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewIPBlockDAO returns a new IPBlockDAO
func NewIPBlockDAO(dbSession *db.Session) IPBlockDAO {
	return &IPBlockSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
