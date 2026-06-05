// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	stracer "github.com/NVIDIA/infra-controller/rest-api/db/pkg/tracer"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"

	"github.com/uptrace/bun"
)

const (
	// VpcStatusPending indicates that the VPC request was received but not yet processed
	VpcStatusPending = "Pending"
	// VpcStatusProvisioning indicates that the VPC is being provisioned
	VpcStatusProvisioning = "Provisioning"
	// VpcStatusReady indicates that the VPC has been successfully provisioned on the Site
	VpcStatusReady = "Ready"
	// VpcStatusError is the status of a Vpc that is in error mode
	VpcStatusError = "Error"
	// VpcStatusDeleting indicates that the VPC is being deleted
	VpcStatusDeleting = "Deleting"
	// VpcRelationName is the relation name for the Vpc model
	VpcRelationName = "Vpc"

	// VpcOrderByDefault default field to be used for ordering when none specified
	VpcOrderByDefault = "created"

	// Network virtualization type values. Each value is the literal
	// string stored in the `network_virtualization_type` column and
	// returned as the REST API enum value. See `vpcTypeCapabilities`
	// (below) for the per-type capability matrix.
	VpcEthernetVirtualizer         = "ETHERNET_VIRTUALIZER"
	VpcEthernetVirtualizerWithNVUE = "ETHERNET_VIRTUALIZER_WITH_NVUE"
	VpcFNNClassic                  = "FNN_CLASSIC"
	VpcFNNL3                       = "FNN_L3"
	VpcFNN                         = "FNN"
	VpcFlat                        = "FLAT"
)

var (
	// VpcOrderByFields is a list of valid order by fields for the Subnet model
	VpcOrderByFields = []string{"name", "status", "created", "updated"}
	// VpcRelatedEntities is a list of valid relation by fields for the VPC model
	VpcRelatedEntities = map[string]bool{
		InfrastructureProviderRelationName: true,
		SiteRelationName:                   true,
		TenantRelationName:                 true,
		NetworkSecurityGroupRelationName:   true,
		NVLinkLogicalPartitionRelationName: true,
	}
	// VpcStatusMap is a list of valid status for the VPC model
	VpcStatusMap = map[string]bool{
		VpcStatusPending:      true,
		VpcStatusProvisioning: true,
		VpcStatusReady:        true,
		VpcStatusError:        true,
		VpcStatusDeleting:     true,
	}

	// VpcNetworkVirtualzationTypeMap is a list of supported network virtulization for the VPC model
	VpcNetworkVirtualzationTypeMap = map[string]bool{
		VpcEthernetVirtualizer: true,
		VpcFNN:                 true,
		VpcFlat:                true,
	}

	// vpcTypeCapabilities encodes the REST-tier capability matrix for
	// VPC network-virtualization types. It mirrors the richer capability
	// matrix in Core (see `carbide_api_model::vpc::capability`) but only
	// carries the bits this layer actually gates on. Unknown or
	// deprecated values (e.g. legacy FNN_CLASSIC, FNN_L3 rows) resolve
	// to the zero value, which is the safe "supports nothing
	// REST-specific" default. Callers should use the helper functions
	// below rather than this map directly.
	vpcTypeCapabilities = map[string]struct {
		// supportsRoutingProfile is true for VPC types that accept a
		// `routingProfile` field on create. FNN-only today.
		supportsRoutingProfile bool

		// supportsAutoInterface is true for VPC types that allow
		// Instances to opt in to NICo-resolved interface configuration
		// via `auto: true`. Flat-only today.
		supportsAutoInterface bool
	}{
		VpcEthernetVirtualizer:         {},
		VpcEthernetVirtualizerWithNVUE: {},
		VpcFNN:                         {supportsRoutingProfile: true},
		VpcFlat:                        {supportsAutoInterface: true},
	}
)

// VpcTypeSupportsRoutingProfile reports whether VPCs of the given
// network-virtualization type accept a `routingProfile` on create.
// A nil pointer (no type specified) returns false; the caller is
// expected to have resolved any defaulting beforehand.
func VpcTypeSupportsRoutingProfile(virtType *string) bool {
	if virtType == nil {
		return false
	}
	return vpcTypeCapabilities[*virtType].supportsRoutingProfile
}

// VpcTypeSupportsAutoInterface reports whether Instances in VPCs of
// the given network-virtualization type may set `auto: true` on
// create or update. A nil pointer (no type recorded on the VPC)
// returns false -- the safe default for legacy or unresolvable rows.
func VpcTypeSupportsAutoInterface(virtType *string) bool {
	if virtType == nil {
		return false
	}
	return vpcTypeCapabilities[*virtType].supportsAutoInterface
}

// Vpc represents entries in the vpc table
type Vpc struct {
	bun.BaseModel `bun:"table:vpc,alias:v"`

	ID                                     uuid.UUID                               `bun:"type:uuid,pk"`
	Name                                   string                                  `bun:"name,notnull"`
	Description                            *string                                 `bun:"description"`
	Org                                    string                                  `bun:"org,notnull"`
	InfrastructureProviderID               uuid.UUID                               `bun:"infrastructure_provider_id,type:uuid,notnull"`
	InfrastructureProvider                 *InfrastructureProvider                 `bun:"rel:belongs-to,join:infrastructure_provider_id=id"`
	TenantID                               uuid.UUID                               `bun:"tenant_id,type:uuid,notnull"`
	Tenant                                 *Tenant                                 `bun:"rel:belongs-to,join:tenant_id=id"`
	SiteID                                 uuid.UUID                               `bun:"site_id,type:uuid,notnull"`
	Site                                   *Site                                   `bun:"rel:belongs-to,join:site_id=id"`
	NVLinkLogicalPartitionID               *uuid.UUID                              `bun:"nvlink_logical_partition_id,type:uuid"`
	NVLinkLogicalPartition                 *NVLinkLogicalPartition                 `bun:"rel:belongs-to,join:nvlink_logical_partition_id=id"`
	NetworkVirtualizationType              *string                                 `bun:"network_virtualization_type"`
	RoutingProfile                         *string                                 `bun:"routing_profile"`
	ControllerVpcID                        *uuid.UUID                              `bun:"controller_vpc_id,type:uuid"`
	ActiveVni                              *int                                    `bun:"active_vni,type:integer"`
	NetworkSecurityGroupID                 *string                                 `bun:"network_security_group_id"`
	NetworkSecurityGroup                   *NetworkSecurityGroup                   `bun:"rel:belongs-to,join:network_security_group_id=id"`
	NetworkSecurityGroupPropagationDetails *NetworkSecurityGroupPropagationDetails `bun:"network_security_group_propagation_details,type:jsonb"`
	Labels                                 Labels                                  `bun:"labels,type:jsonb"`
	Status                                 string                                  `bun:"status,notnull"`
	IsMissingOnSite                        bool                                    `bun:"is_missing_on_site,notnull"`
	Created                                time.Time                               `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated                                time.Time                               `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted                                *time.Time                              `bun:"deleted,soft_delete"`
	CreatedBy                              uuid.UUID                               `bun:"type:uuid,notnull"`
	Vni                                    *int                                    `bun:"vni,type:integer"`
}

// GetSiteID returns the VPC ID to use when communicating with the Site:
// the controller-supplied ControllerVpcID when present, otherwise the
// VPC's own ID. The Site treats both as opaque identifiers.
func (vpc *Vpc) GetSiteID() *uuid.UUID {
	if vpc.ControllerVpcID != nil {
		return vpc.ControllerVpcID
	}
	return &vpc.ID
}

// toMetadataProto builds a workflow Metadata proto from the VPC's Name,
// Description, and Labels. Description defaults to the empty string when
// the receiver's pointer is nil; this matches the existing handler
// behaviour.
func (vpc *Vpc) toMetadataProto() *cwssaws.Metadata {
	md := &cwssaws.Metadata{
		Name:        vpc.Name,
		Description: "",
	}
	if vpc.Description != nil {
		md.Description = *vpc.Description
	}
	if vpc.Labels != nil {
		md.Labels = vpc.Labels.ToProto()
	}
	return md
}

// ToProto converts this VPC into its workflow proto representation.
// Used as the canonical entity-to-proto conversion; request-shape
// protos (create / update) are produced by `ToProto` methods on the
// corresponding API request types in api/pkg/api/model/vpc.go.
//
// `NetworkVirtualizationType` is mapped from the DB column's string
// value to the workflow enum (defaulting to `ETHERNET_VIRTUALIZER`
// when the string is set but unrecognized, matching the pre-refactor
// handler behaviour). It is omitted from the proto when the DB
// column is nil.
func (vpc *Vpc) ToProto() *cwssaws.Vpc {
	proto := &cwssaws.Vpc{
		Id:                     &cwssaws.VpcId{Value: vpc.GetSiteID().String()},
		Name:                   vpc.Name,
		TenantOrganizationId:   vpc.Org,
		NetworkSecurityGroupId: vpc.NetworkSecurityGroupID,
		Metadata:               vpc.toMetadataProto(),
	}
	if vpc.NVLinkLogicalPartitionID != nil {
		proto.DefaultNvlinkLogicalPartitionId = &cwssaws.NVLinkLogicalPartitionId{Value: vpc.NVLinkLogicalPartitionID.String()}
	}
	if vpc.NetworkVirtualizationType != nil {
		nwvt := cwssaws.VpcVirtualizationType_ETHERNET_VIRTUALIZER
		switch *vpc.NetworkVirtualizationType {
		case cwssaws.VpcVirtualizationType_FNN.String():
			nwvt = cwssaws.VpcVirtualizationType_FNN
		case cwssaws.VpcVirtualizationType_FLAT.String():
			nwvt = cwssaws.VpcVirtualizationType_FLAT
		}
		proto.NetworkVirtualizationType = &nwvt
	}
	return proto
}

// FromProto populates this VPC from its workflow proto representation.
// A nil proto is a no-op. This is the inverse of `ToProto` and exists
// for convention symmetry — currently no code path on the cloud side
// reconstructs a full VPC entity from a `cwssaws.Vpc` (the site is the
// destination, not the source), but the method is provided so future
// reconciliation flows have a single canonical entry point.
//
// Field-level contract:
//   - `vpc.ID` is preserved on a missing or unparseable `proto.Id`,
//     because callers pre-validate the UUID before calling.
//   - `Name` is sourced from `proto.Metadata.Name` when set, falling
//     back to the (deprecated) top-level `proto.Name` so the method
//     keeps working through the deprecation window.
//   - Optional pointer fields (NetworkSecurityGroupID,
//     NVLinkLogicalPartitionID) are cleared when the proto omits them
//     OR when the proto value is invalid (e.g. an unparseable UUID).
//     This makes `FromProto` a clean reset rather than a partial
//     merge, matching the Expected* pattern.
func (vpc *Vpc) FromProto(proto *cwssaws.Vpc) {
	if proto == nil {
		return
	}
	if proto.Id != nil {
		if id, err := uuid.Parse(proto.Id.Value); err == nil {
			vpc.ID = id
		}
	}
	vpc.Name = proto.Name
	if proto.Metadata != nil && proto.Metadata.Name != "" {
		vpc.Name = proto.Metadata.Name
	}
	vpc.Org = proto.TenantOrganizationId
	vpc.NetworkSecurityGroupID = proto.NetworkSecurityGroupId
	if proto.DefaultNvlinkLogicalPartitionId != nil {
		if id, err := uuid.Parse(proto.DefaultNvlinkLogicalPartitionId.Value); err == nil {
			vpc.NVLinkLogicalPartitionID = &id
		} else {
			vpc.NVLinkLogicalPartitionID = nil
		}
	} else {
		vpc.NVLinkLogicalPartitionID = nil
	}
	if proto.Metadata != nil {
		vpc.Description = nil
		if proto.Metadata.Description != "" {
			desc := proto.Metadata.Description
			vpc.Description = &desc
		}
		vpc.Labels.FromProto(proto.Metadata.GetLabels())
	} else {
		vpc.Description = nil
		vpc.Labels = nil
	}
}

// ToDeletionRequestProto builds the workflow request that asks a Site to
// delete this VPC.
func (vpc *Vpc) ToDeletionRequestProto() *cwssaws.VpcDeletionRequest {
	return &cwssaws.VpcDeletionRequest{
		Id: &cwssaws.VpcId{Value: vpc.GetSiteID().String()},
	}
}

// VpcCreateInput input parameters for Create method
type VpcCreateInput struct {
	Name                                   string
	Description                            *string
	Org                                    string
	ID                                     *uuid.UUID
	InfrastructureProviderID               uuid.UUID
	TenantID                               uuid.UUID
	SiteID                                 uuid.UUID
	NVLinkLogicalPartitionID               *uuid.UUID
	NetworkVirtualizationType              *string
	RoutingProfile                         *string
	ControllerVpcID                        *uuid.UUID
	NetworkSecurityGroupID                 *string
	NetworkSecurityGroupPropagationDetails *NetworkSecurityGroupPropagationDetails
	Labels                                 map[string]string
	Status                                 string
	CreatedBy                              User
	Vni                                    *int
}

// VpcUpdateInput input parameters for Update method
type VpcUpdateInput struct {
	VpcID                                  uuid.UUID
	Name                                   *string
	Description                            *string
	NetworkVirtualizationType              *string
	RoutingProfile                         *string
	ControllerVpcID                        *uuid.UUID
	ActiveVni                              *int
	NVLinkLogicalPartitionID               *uuid.UUID
	NetworkSecurityGroupID                 *string
	NetworkSecurityGroupPropagationDetails *NetworkSecurityGroupPropagationDetails
	Labels                                 map[string]string
	Status                                 *string
	IsMissingOnSite                        *bool
	Vni                                    *int
}

// VpcClearInput input parameters for Clear method
type VpcClearInput struct {
	VpcID                                  uuid.UUID
	Description                            bool
	ControllerVpcID                        bool
	RoutingProfile                         bool
	NVLinkLogicalPartitionID               bool
	NetworkSecurityGroupID                 bool
	NetworkSecurityGroupPropagationDetails bool
	Labels                                 bool
}

// VpcFilterInput input parameters for Filter method
type VpcFilterInput struct {
	Name                      *string
	VpcIDs                    []uuid.UUID
	InfrastructureProviderID  *uuid.UUID
	TenantIDs                 []uuid.UUID
	SiteIDs                   []uuid.UUID
	NVLinkLogicalPartitionIDs []uuid.UUID
	NetworkSecurityGroupIDs   []string
	Org                       *string
	NetworkVirtualizationType *string
	Statuses                  []string
	SearchQuery               *string
}

var _ bun.BeforeAppendModelHook = (*Vpc)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (v *Vpc) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		v.Created = db.GetCurTime()
		v.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		v.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*Vpc)(nil)

// BeforeCreateTable is a hook that is called before the table is created
func (v *Vpc) BeforeCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey(`("infrastructure_provider_id") REFERENCES "infrastructure_provider" ("id")`).
		ForeignKey(`("tenant_id") REFERENCES "tenant" ("id")`).
		ForeignKey(`("site_id") REFERENCES "site" ("id")`).
		ForeignKey(`("nvlink_logical_partition_id") REFERENCES "nvlink_logical_partition" ("id")`).
		ForeignKey(`("network_security_group_id") REFERENCES "network_security_group" ("id")`)

	return nil
}

// VpcDAO is an interface for interacting with the Vpc model
type VpcDAO interface {
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*Vpc, error)
	//
	GetAll(ctx context.Context, tx *db.Tx, filter VpcFilterInput, page paginator.PageInput, includeRelations []string) ([]Vpc, int, error)
	//
	GetCountByStatus(ctx context.Context, tx *db.Tx, infrastructureProviderID *uuid.UUID, tenantID *uuid.UUID, siteID *uuid.UUID) (map[string]int, error)
	//
	Create(ctx context.Context, tx *db.Tx, input VpcCreateInput) (*Vpc, error)
	//
	Update(ctx context.Context, tx *db.Tx, input VpcUpdateInput) (*Vpc, error)
	//
	Clear(ctx context.Context, tx *db.Tx, input VpcClearInput) (*Vpc, error)
	//
	DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// VpcSQLDAO is an implementation of the VpcDAO interface
type VpcSQLDAO struct {
	dbSession  *db.Session
	tracerSpan *stracer.TracerSpan
}

// GetByID returns a Vpc by ID
func (vsd VpcSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*Vpc, error) {
	// Create a child span and set the attributes for current request
	ctx, vpcDAOSpan := vsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcDAO.GetByID")
	if vpcDAOSpan != nil {
		defer vpcDAOSpan.End()

		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "id", id.String())
	}

	v := &Vpc{}

	query := db.GetIDB(tx, vsd.dbSession).NewSelect().Model(v).Where("v.id = ?", id)

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

	return v, nil
}

// GetCountByStatus returns count of VPCs for given status
// Errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned map is 0
func (vsd VpcSQLDAO) GetCountByStatus(ctx context.Context, tx *db.Tx, infrastructureProviderID *uuid.UUID, tenantID *uuid.UUID, siteID *uuid.UUID) (map[string]int, error) {
	// Create a child span and set the attributes for current request
	ctx, vpcDAOSpan := vsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcDAO.GetCountByStatus")
	if vpcDAOSpan != nil {
		defer vpcDAOSpan.End()
	}

	v := &Vpc{}
	var statusQueryResults []map[string]interface{}

	query := db.GetIDB(tx, vsd.dbSession).NewSelect().Model(v)
	if infrastructureProviderID != nil {
		query = query.Where("v.infrastructure_provider_id = ?", *infrastructureProviderID)
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "infrastructure_provider_id", infrastructureProviderID.String())
	}
	if tenantID != nil {
		query = query.Where("v.tenant_id = ?", *tenantID)
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "tenant_id", tenantID.String())
	}
	if siteID != nil {
		query = query.Where("v.site_id = ?", *siteID)
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "site_id", siteID.String())
	}

	err := query.Column("v.status").ColumnExpr("COUNT(*) AS total_count").GroupExpr("v.status").Scan(ctx, &statusQueryResults)
	if err != nil {
		return nil, err
	}

	// creare results map by holding key as status value with total count
	results := map[string]int{
		"total":               0,
		VpcStatusDeleting:     0,
		VpcStatusError:        0,
		VpcStatusProvisioning: 0,
		VpcStatusPending:      0,
		VpcStatusReady:        0,
	}

	if len(statusQueryResults) > 0 {
		for _, statusMap := range statusQueryResults {
			results[statusMap["status"].(string)] = int(statusMap["total_count"].(int64))
			results["total"] = results["total"] + int(statusMap["total_count"].(int64))
		}
	}
	return results, nil
}

func (vsd VpcSQLDAO) setQueryWithFilter(filter VpcFilterInput, query *bun.SelectQuery, vpcDAOSpan *stracer.CurrentContextSpan) (*bun.SelectQuery, error) {
	if filter.Name != nil {
		query = query.Where("v.name = ?", *filter.Name)

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "name", *filter.Name)
		}
	}

	if filter.Org != nil {
		query = query.Where("v.org = ?", *filter.Org)

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "org", *filter.Org)
		}
	}

	if filter.InfrastructureProviderID != nil {
		query = query.Where("v.infrastructure_provider_id = ?", *filter.InfrastructureProviderID)

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "infrastructure_provider_id", filter.InfrastructureProviderID.String())
		}
	}

	if filter.TenantIDs != nil {
		if len(filter.TenantIDs) == 1 {
			query = query.Where("v.tenant_id = ?", filter.TenantIDs[0])
		} else {
			query = query.Where("v.tenant_id IN (?)", bun.In(filter.TenantIDs))
		}

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "tenant_ids", filter.TenantIDs)
		}
	}

	if filter.SiteIDs != nil {
		if len(filter.SiteIDs) == 1 {
			query = query.Where("v.site_id = ?", filter.SiteIDs[0])
		} else {
			query = query.Where("v.site_id IN (?)", bun.In(filter.SiteIDs))
		}

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "site_ids", filter.SiteIDs)
		}
	}

	if filter.NVLinkLogicalPartitionIDs != nil {
		query = query.Where("v.nvlink_logical_partition_id IN (?)", bun.In(filter.NVLinkLogicalPartitionIDs))

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "nvlink_logical_partition_ids", filter.NVLinkLogicalPartitionIDs)
		}
	}

	if filter.NetworkVirtualizationType != nil {
		query = query.Where("v.network_virtualization_type = ?", filter.NetworkVirtualizationType)

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "network_virtualization_type", *filter.NetworkVirtualizationType)
		}
	}

	if filter.Statuses != nil {
		if len(filter.Statuses) == 1 {
			query = query.Where("v.status = ?", filter.Statuses[0])
		} else {
			query = query.Where("v.status IN (?)", bun.In(filter.Statuses))
		}

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "statuses", filter.Statuses)
		}
	}

	if filter.NetworkSecurityGroupIDs != nil {
		// Single-item IN queries are optimized by the query planner to =
		query = query.Where("v.network_security_group_id IN (?)", bun.In(filter.NetworkSecurityGroupIDs))

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "network_security_group_ids", filter.NetworkSecurityGroupIDs)
		}
	}

	if filter.VpcIDs != nil {
		query = query.Where("v.id IN (?)", bun.In(filter.VpcIDs))

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "vpc_ids", filter.VpcIDs)
		}
	}

	searchQuery, searchTokens, ok := db.NormalizeSearchQuery(filter.SearchQuery)
	if ok {
		query = query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				Where("to_tsvector('english', (coalesce(v.name, ' ') || ' ' || coalesce(v.description, ' ') || ' ' || coalesce(v.network_virtualization_type, ' ') || ' ' || coalesce(v.status, ' ') || ' ' || coalesce(v.labels::text, ' '))) @@ to_tsquery('english', ?)", *searchTokens).
				WhereOr("v.name ILIKE ?", "%"+searchQuery+"%").
				WhereOr("v.description ILIKE ?", "%"+searchQuery+"%").
				WhereOr("v.network_virtualization_type ILIKE ?", "%"+searchQuery+"%").
				WhereOr("v.status ILIKE ?", "%"+searchQuery+"%").
				WhereOr("v.labels::text ILIKE ?", "%"+searchQuery+"%")
		})
		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "search_query", searchQuery)
		}
	}
	return query, nil
}

// GetAll returns all VPCs for a tenant or site
// Errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
// if orderBy is nil, then records are ordered by column specified in VpcOrderByDefault in ascending order
func (vsd VpcSQLDAO) GetAll(ctx context.Context, tx *db.Tx, filter VpcFilterInput, page paginator.PageInput, includeRelations []string) ([]Vpc, int, error) {
	// Create a child span and set the attributes for current request
	ctx, vpcDAOSpan := vsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcDAO.GetAll")
	if vpcDAOSpan != nil {
		defer vpcDAOSpan.End()
	}

	// var vpcs []Vpc
	vpcs := []Vpc{}
	query := db.GetIDB(tx, vsd.dbSession).NewSelect().Model(&vpcs)

	query, err := vsd.setQueryWithFilter(filter, query, vpcDAOSpan)
	if err != nil {
		return vpcs, 0, err
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// if no order is passed, set default to make sure objects return always in the same order and pagination works properly
	if page.OrderBy == nil {
		page.OrderBy = paginator.NewDefaultOrderBy(VpcOrderByDefault)
	}

	paginator, err := paginator.NewPaginator(ctx, query, page.Offset, page.Limit, page.OrderBy, VpcOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = paginator.Query.Limit(paginator.Limit).Offset(paginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return vpcs, paginator.Total, nil
}

// Create a new Vpc from the given parameters
func (vsd VpcSQLDAO) Create(ctx context.Context, tx *db.Tx, input VpcCreateInput) (*Vpc, error) {
	// Create a child span and set the attributes for current request
	ctx, vpcDAOSpan := vsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcDAO.CreateFromParams")
	if vpcDAOSpan != nil {
		defer vpcDAOSpan.End()

		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "name", input.Name)
	}

	id := uuid.New()
	if input.ID != nil {
		id = *input.ID
	}

	v := &Vpc{
		ID:                                     id,
		Name:                                   input.Name,
		Description:                            input.Description,
		Org:                                    input.Org,
		InfrastructureProviderID:               input.InfrastructureProviderID,
		TenantID:                               input.TenantID,
		SiteID:                                 input.SiteID,
		NVLinkLogicalPartitionID:               input.NVLinkLogicalPartitionID,
		NetworkVirtualizationType:              input.NetworkVirtualizationType,
		RoutingProfile:                         input.RoutingProfile,
		ControllerVpcID:                        input.ControllerVpcID,
		NetworkSecurityGroupID:                 input.NetworkSecurityGroupID,
		NetworkSecurityGroupPropagationDetails: input.NetworkSecurityGroupPropagationDetails,
		Labels:                                 input.Labels,
		Status:                                 input.Status,
		IsMissingOnSite:                        false,
		CreatedBy:                              input.CreatedBy.ID,
		Vni:                                    input.Vni,
	}

	_, err := db.GetIDB(tx, vsd.dbSession).NewInsert().Model(v).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nv, err := vsd.GetByID(ctx, tx, v.ID, nil)
	if err != nil {
		return nil, err
	}

	return nv, nil
}

// Update updates an existing Vpc from the given parameters
func (vsd VpcSQLDAO) Update(ctx context.Context, tx *db.Tx, input VpcUpdateInput) (*Vpc, error) {
	// Create a child span and set the attributes for current request
	ctx, vpcDAOSpan := vsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcDAO.UpdateFromParams")
	if vpcDAOSpan != nil {
		defer vpcDAOSpan.End()

		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "id", input.VpcID.String())
	}

	v := &Vpc{
		ID: input.VpcID,
	}

	updatedFields := []string{}

	if input.Name != nil {
		v.Name = *input.Name
		updatedFields = append(updatedFields, "name")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "name", *input.Name)
	}

	if input.Description != nil {
		v.Description = input.Description
		updatedFields = append(updatedFields, "description")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "description", *input.Description)
	}

	if input.NVLinkLogicalPartitionID != nil {
		v.NVLinkLogicalPartitionID = input.NVLinkLogicalPartitionID
		updatedFields = append(updatedFields, "nvlink_logical_partition_id")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "nvlink_logical_partition_id", input.NVLinkLogicalPartitionID.String())
	}

	if input.NetworkVirtualizationType != nil {
		v.NetworkVirtualizationType = input.NetworkVirtualizationType
		updatedFields = append(updatedFields, "network_virtualization_type")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "network_virtualization_type", *input.NetworkVirtualizationType)
	}

	if input.ControllerVpcID != nil {
		v.ControllerVpcID = input.ControllerVpcID
		updatedFields = append(updatedFields, "controller_vpc_id")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "controller_vpc_id", input.ControllerVpcID.String())
	}

	if input.RoutingProfile != nil {
		v.RoutingProfile = input.RoutingProfile
		updatedFields = append(updatedFields, "routing_profile")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "routing_profile", *input.RoutingProfile)
	}

	if input.ActiveVni != nil {
		v.ActiveVni = input.ActiveVni
		updatedFields = append(updatedFields, "active_vni")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "active_vni", *input.ActiveVni)
	}

	if input.Vni != nil {
		v.Vni = input.Vni
		updatedFields = append(updatedFields, "vni")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "vni", *input.Vni)
	}

	if input.Labels != nil {
		v.Labels = input.Labels
		updatedFields = append(updatedFields, "labels")
	}

	if input.Status != nil {
		v.Status = *input.Status
		updatedFields = append(updatedFields, "status")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "status", *input.Status)
	}

	if input.IsMissingOnSite != nil {
		v.IsMissingOnSite = *input.IsMissingOnSite
		updatedFields = append(updatedFields, "is_missing_on_site")
		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "is_missing_on_site", *input.IsMissingOnSite)
	}

	if input.NetworkSecurityGroupID != nil {
		v.NetworkSecurityGroupID = input.NetworkSecurityGroupID
		updatedFields = append(updatedFields, "network_security_group_id")

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "network_security_group_id", input.NetworkSecurityGroupID)
		}
	}

	if input.NetworkSecurityGroupPropagationDetails != nil {
		v.NetworkSecurityGroupPropagationDetails = input.NetworkSecurityGroupPropagationDetails
		updatedFields = append(updatedFields, "network_security_group_propagation_details")

		if vpcDAOSpan != nil {
			vsd.tracerSpan.SetAttribute(vpcDAOSpan, "network_security_group_propagation_details", input.NetworkSecurityGroupPropagationDetails)
		}
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, vsd.dbSession).NewUpdate().Model(v).Column(updatedFields...).Where("id = ?", input.VpcID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := vsd.GetByID(ctx, tx, v.ID, nil)
	if err != nil {
		return nil, err
	}

	return nv, nil
}

// Clear clears VPC attributes based on provided arguments
func (vsd VpcSQLDAO) Clear(ctx context.Context, tx *db.Tx, input VpcClearInput) (*Vpc, error) {
	// Create a child span and set the attributes for current request
	ctx, vpcDAOSpan := vsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcDAO.ClearFromParams")
	if vpcDAOSpan != nil {
		defer vpcDAOSpan.End()

		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "id", input.VpcID.String())
	}

	v := &Vpc{
		ID: input.VpcID,
	}

	updatedFields := []string{}

	if input.Description {
		v.Description = nil
		updatedFields = append(updatedFields, "description")
	}

	if input.ControllerVpcID {
		v.ControllerVpcID = nil
		updatedFields = append(updatedFields, "controller_vpc_id")
	}

	if input.RoutingProfile {
		v.RoutingProfile = nil
		updatedFields = append(updatedFields, "routing_profile")
	}

	if input.Labels {
		v.Labels = nil
		updatedFields = append(updatedFields, "labels")
	}

	if input.NVLinkLogicalPartitionID {
		v.NVLinkLogicalPartitionID = nil
		updatedFields = append(updatedFields, "nvlink_logical_partition_id")
	}

	if input.NetworkSecurityGroupID {
		v.NetworkSecurityGroupID = nil
		updatedFields = append(updatedFields, "network_security_group_id")
	}

	if input.NetworkSecurityGroupPropagationDetails {
		v.NetworkSecurityGroupPropagationDetails = nil
		updatedFields = append(updatedFields, "network_security_group_propagation_details")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, vsd.dbSession).NewUpdate().Model(v).Column(updatedFields...).Where("id = ?", input.VpcID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := vsd.GetByID(ctx, tx, v.ID, nil)
	if err != nil {
		return nil, err
	}

	return nv, nil
}

// DeleteByID deletes a Vpc by ID
func (vsd VpcSQLDAO) DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, vpcDAOSpan := vsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcDAO.DeleteByID")
	if vpcDAOSpan != nil {
		defer vpcDAOSpan.End()

		vsd.tracerSpan.SetAttribute(vpcDAOSpan, "id", id.String())
	}

	v := &Vpc{
		ID: id,
	}

	_, err := db.GetIDB(tx, vsd.dbSession).NewDelete().Model(v).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewVpcDAO returns a new VpcDAO
func NewVpcDAO(dbSession *db.Session) VpcDAO {
	return &VpcSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
