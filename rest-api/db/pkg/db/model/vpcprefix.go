// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"

	"github.com/google/uuid"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	cipam "github.com/NVIDIA/infra-controller/rest-api/ipam"

	"github.com/uptrace/bun"

	stracer "github.com/NVIDIA/infra-controller/rest-api/db/pkg/tracer"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

const (
	// VpcPrefixStatusReady status is ready
	VpcPrefixStatusReady = "Ready"
	// VpcPrefixStatusError status is error
	VpcPrefixStatusError = "Error"
	// VpcPrefixStatusDeleting indicates that the VpcPrefix is being deleted
	VpcPrefixStatusDeleting = "Deleting"
	// VpcPrefixStatusDeleted indicates that the VpcPrefix has been deleted
	VpcPrefixStatusDeleted = "Deleted"
	// VpcPrefixRelationName is the relation name for the VpcPrefix model
	VpcPrefixRelationName = "VpcPrefix"

	// VpcPrefixOrderByDefault default field to be used for ordering when none specified
	VpcPrefixOrderByDefault = "created"
)

var (
	// VpcPrefixOrderByFields is a list of valid order by fields for the VpcPrefix model
	VpcPrefixOrderByFields = []string{"name", "status", "created", "updated"}
	// VpcPrefixRelatedEntities is a list of valid relation by fields for the VpcPrefix model
	VpcPrefixRelatedEntities = map[string]bool{
		SiteRelationName:    true,
		VpcRelationName:     true,
		TenantRelationName:  true,
		IPBlockRelationName: true,
	}
	// VpcPrefixStatusMap is a list of valid status for the VpcPrefix model
	VpcPrefixStatusMap = map[string]bool{
		VpcPrefixStatusReady:    true,
		VpcPrefixStatusError:    true,
		VpcPrefixStatusDeleting: true,
		VpcPrefixStatusDeleted:  true,
	}
)

// VpcPrefix is a network construct for bare-metal machines
type VpcPrefix struct {
	bun.BaseModel `bun:"table:vpc_prefix,alias:vp"`

	ID              uuid.UUID  `bun:"type:uuid,pk"`
	Name            string     `bun:"name,notnull"`
	Org             string     `bun:"org,notnull"`
	SiteID          uuid.UUID  `bun:"site_id,type:uuid,notnull"`
	Site            *Site      `bun:"rel:belongs-to,join:site_id=id"`
	VpcID           uuid.UUID  `bun:"vpc_id,type:uuid,notnull"`
	Vpc             *Vpc       `bun:"rel:belongs-to,join:vpc_id=id"`
	TenantID        uuid.UUID  `bun:"tenant_id,type:uuid"`
	Tenant          *Tenant    `bun:"rel:belongs-to,join:tenant_id=id"`
	IPBlockID       *uuid.UUID `bun:"ip_block_id,type:uuid"`
	IPBlock         *IPBlock   `bun:"rel:belongs-to,join:ip_block_id=id"`
	Prefix          string     `bun:"prefix,notnull"`
	PrefixLength    int        `bun:"prefix_length,notnull"`
	Status          string     `bun:"status,notnull"`
	IsMissingOnSite bool       `bun:"is_missing_on_site,notnull"`
	Created         time.Time  `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated         time.Time  `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted         *time.Time `bun:"deleted,soft_delete"`
	CreatedBy       uuid.UUID  `bun:"type:uuid,notnull"`
}

// ToProto converts this VpcPrefix into its workflow proto representation.
// Used as the canonical entity-to-proto conversion; request-shape protos
// (create / update) are produced by `ToProto` methods on the corresponding
// API request types in api/pkg/api/model/vpcprefix.go.
//
// The parent `vpc` is passed as a side input because the Site-facing VPC
// ID can differ from the cloud-side `vp.VpcID` (see `Vpc.GetSiteID`), and
// handlers typically already have a hydrated *Vpc from a separate query.
// A nil `vpc` leaves the wire `VpcId` unset.
func (vp *VpcPrefix) ToProto(vpc *Vpc) *cwssaws.VpcPrefix {
	proto := &cwssaws.VpcPrefix{
		Id: &cwssaws.VpcPrefixId{Value: vp.ID.String()},
		Config: &cwssaws.VpcPrefixConfig{
			Prefix: vp.Prefix,
		},
		Metadata: &cwssaws.Metadata{
			Name: vp.Name,
		},
	}
	if vpc != nil {
		proto.VpcId = &cwssaws.VpcId{Value: vpc.GetSiteID().String()}
	}
	return proto
}

// FromProto populates this VpcPrefix from its workflow proto representation.
// A nil proto is a no-op. This is the inverse of `ToProto` and exists for
// convention symmetry — currently no code path on the cloud side
// reconstructs a full VpcPrefix entity from a `cwssaws.VpcPrefix` (the
// site is the destination, not the source), but the method is provided so
// future reconciliation flows have a single canonical entry point.
//
// Field-level contract:
//   - `vp.ID` is preserved on a missing or unparseable `proto.Id`,
//     because callers pre-validate the UUID before calling.
//   - `Name` is sourced from `proto.Metadata.Name` when set, falling back
//     to the (deprecated) top-level `proto.Name` so the method keeps
//     working through the deprecation window.
//   - `Prefix` is sourced from `proto.Config.Prefix` when set, falling
//     back to the (deprecated) top-level `proto.Prefix`.
//   - `Name` and `Prefix` are similarly reset to the empty string when
//     the proto omits both the deprecated top-level field and the
//     structured `Metadata` / `Config` field; `FromProto` is a full
//     overwrite of those fields, not a merge.
//   - `VpcID` is cleared when the proto omits it OR when the proto value
//     is unparseable, so `FromProto` is a clean reset rather than a
//     partial merge.
func (vp *VpcPrefix) FromProto(proto *cwssaws.VpcPrefix) {
	if proto == nil {
		return
	}
	if proto.Id != nil {
		if id, err := uuid.Parse(proto.Id.Value); err == nil {
			vp.ID = id
		}
	}
	vp.Name = proto.Name
	if proto.Metadata != nil && proto.Metadata.Name != "" {
		vp.Name = proto.Metadata.Name
	}
	vp.Prefix = proto.Prefix
	if proto.Config != nil && proto.Config.Prefix != "" {
		vp.Prefix = proto.Config.Prefix
	}
	if proto.VpcId != nil {
		if id, err := uuid.Parse(proto.VpcId.Value); err == nil {
			vp.VpcID = id
		} else {
			vp.VpcID = uuid.Nil
		}
	} else {
		vp.VpcID = uuid.Nil
	}
}

// ToDeletionRequestProto builds the workflow request that asks a Site to
// delete this VpcPrefix.
func (vp *VpcPrefix) ToDeletionRequestProto() *cwssaws.VpcPrefixDeletionRequest {
	return &cwssaws.VpcPrefixDeletionRequest{
		Id: &cwssaws.VpcPrefixId{Value: vp.ID.String()},
	}
}

// VpcPrefixCreateInput input parameters for Create method
type VpcPrefixCreateInput struct {
	VpcPrefixID  *uuid.UUID
	Name         string
	TenantOrg    string
	SiteID       uuid.UUID
	VpcID        uuid.UUID
	TenantID     uuid.UUID
	IpBlockID    *uuid.UUID
	Prefix       string
	PrefixLength int
	Status       string
	CreatedBy    uuid.UUID
}

// VpcPrefixUpdateInput input parameters for Update method
type VpcPrefixUpdateInput struct {
	VpcPrefixID     uuid.UUID
	Name            *string
	TenantOrg       *string
	VpcID           *uuid.UUID
	TenantID        *uuid.UUID
	IpBlockID       *uuid.UUID
	Prefix          *string
	PrefixLength    *int
	Status          *string
	IsMissingOnSite *bool
}

// VpcPrefixFilterInput input parameters for Filter method
type VpcPrefixFilterInput struct {
	VpcPrefixIDs  []uuid.UUID
	Names         []string
	VpcIDs        []uuid.UUID
	TenantOrgs    []string
	TenantIDs     []uuid.UUID
	IpBlockIDs    []uuid.UUID
	SiteIDs       []uuid.UUID
	Statuses      []string
	SearchQuery   *string
	Prefixes      []string
	PrefixLengths []int
}

var _ bun.BeforeAppendModelHook = (*VpcPrefix)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (vp *VpcPrefix) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		vp.Created = db.GetCurTime()
		vp.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		vp.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*VpcPrefix)(nil)

// BeforeCreateTable is a hook that is called before the table is created
func (vp *VpcPrefix) BeforeCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey(`("site_id") REFERENCES "site" ("id")`).
		ForeignKey(`("vpc_id") REFERENCES "vpc" ("id")`).
		ForeignKey(`("tenant_id") REFERENCES "tenant" ("id")`).
		ForeignKey(`("ip_block_id") REFERENCES "ip_block" ("id")`)
	return nil
}

// VpcPrefixDAO is an interface for interacting with the VpcPrefix model
type VpcPrefixDAO interface {
	//
	Create(ctx context.Context, tx *db.Tx, input VpcPrefixCreateInput) (*VpcPrefix, error)
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*VpcPrefix, error)
	//
	GetAll(ctx context.Context, tx *db.Tx, filter VpcPrefixFilterInput, page paginator.PageInput, includeRelations []string) ([]VpcPrefix, int, error)
	//
	Update(ctx context.Context, tx *db.Tx, input VpcPrefixUpdateInput) (*VpcPrefix, error)
	//
	Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error
	//
	// GetPrefixUsage returns IPv4 interface usage for this VPC prefix (in-memory IPAM simulation).
	GetPrefixUsage(ctx context.Context, tx *db.Tx, vp *VpcPrefix) (*cipam.Usage, error)
}

// VpcPrefixSQLDAO is an implementation of the VpcPrefixDAO interface
type VpcPrefixSQLDAO struct {
	dbSession *db.Session
	VpcPrefixDAO
	tracerSpan *stracer.TracerSpan
}

// Create creates a new VpcPrefix from the given parameters
func (vpsd VpcPrefixSQLDAO) Create(ctx context.Context, tx *db.Tx, input VpcPrefixCreateInput) (*VpcPrefix, error) {
	// Create a child span and set the attributes for current request
	ctx, vpDAOSpan := vpsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcPrefixDAO.Create")
	if vpDAOSpan != nil {
		defer vpDAOSpan.End()

		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "name", input.Name)
	}

	id := input.VpcPrefixID
	if id == nil {
		id = cutil.GetPtr(uuid.New())
	}

	vpp := &VpcPrefix{
		ID:              *id,
		Name:            input.Name,
		Org:             input.TenantOrg,
		SiteID:          input.SiteID,
		VpcID:           input.VpcID,
		TenantID:        input.TenantID,
		IPBlockID:       input.IpBlockID,
		Prefix:          input.Prefix,
		PrefixLength:    input.PrefixLength,
		IsMissingOnSite: false,
		Status:          input.Status,
		CreatedBy:       input.CreatedBy,
	}

	_, err := db.GetIDB(tx, vpsd.dbSession).NewInsert().Model(vpp).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nvp, err := vpsd.GetByID(ctx, tx, vpp.ID, nil)
	if err != nil {
		return nil, err
	}

	return nvp, nil
}

// GetByID returns a VpcPrefix by ID
// includeRelation can be a subset of Vpc
// returns db.ErrDoesNotExist error if the record is not found
func (vpsd VpcPrefixSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*VpcPrefix, error) {
	// Create a child span and set the attributes for current request
	ctx, vpDAOSpan := vpsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcPrefixDAO.GetByID")
	if vpDAOSpan != nil {
		defer vpDAOSpan.End()

		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "id", id.String())
	}

	vpp := &VpcPrefix{}

	query := db.GetIDB(tx, vpsd.dbSession).NewSelect().Model(vpp).Where("vp.id = ?", id)

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

	return vpp, nil
}

// GetAll returns all VpcPrefixs filtering by Vpc, Domain, Tenant
// errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
// if orderBy is nil, then records are ordered by column specified in VpcPrefixOrderByDefault in ascending order
func (vpsd VpcPrefixSQLDAO) GetAll(ctx context.Context, tx *db.Tx, filter VpcPrefixFilterInput, page paginator.PageInput, includeRelations []string) ([]VpcPrefix, int, error) {
	// Create a child span and set the attributes for current request
	ctx, vpDAOSpan := vpsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcPrefixDAO.GetAll")
	if vpDAOSpan != nil {
		defer vpDAOSpan.End()
	}

	vps := []VpcPrefix{}

	query := db.GetIDB(tx, vpsd.dbSession).NewSelect().Model(&vps)
	if filter.VpcPrefixIDs != nil {
		query = query.Where("vp.id IN (?)", bun.In(filter.VpcPrefixIDs))
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "vpc_prefix_ids", filter.VpcPrefixIDs)
	}
	if filter.Names != nil {
		query = query.Where("vp.name IN (?)", bun.In(filter.Names))
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "name", filter.Names)
	}
	if filter.SiteIDs != nil {
		query = query.Where("vp.site_id IN (?)", bun.In(filter.SiteIDs))
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "site_id", filter.SiteIDs)
	}
	if filter.VpcIDs != nil {
		query = query.Where("vp.vpc_id IN (?)", bun.In(filter.VpcIDs))
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "vpc_id", filter.VpcIDs)
	}
	if filter.TenantIDs != nil {
		query = query.Where("vp.tenant_id IN (?)", bun.In(filter.TenantIDs))
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "tenant_id", filter.TenantIDs)
	}
	if filter.IpBlockIDs != nil {
		query = query.Where("vp.ip_block_id IN (?)", bun.In(filter.IpBlockIDs))
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "ip_block_id", filter.IpBlockIDs)
	}
	if filter.Prefixes != nil {
		query = query.Where("vp.prefix IN (?)", bun.In(filter.Prefixes))
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "prefix", filter.Prefixes)
	}
	if filter.PrefixLengths != nil {
		query = query.Where("vp.prefix_length IN (?)", bun.In(filter.PrefixLengths))
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "prefix_length", filter.PrefixLengths)
	}
	if filter.Statuses != nil {
		query = query.Where("vp.status IN (?)", bun.In(filter.Statuses))
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "status", filter.Statuses)
	}
	searchQuery, normalizedTokens, ok := db.NormalizeSearchQuery(filter.SearchQuery)
	if ok {
		query = query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				Where("to_tsvector('english', (coalesce(vp.name, ' ') || ' ' || coalesce(vp.status, ' '))) @@ to_tsquery('english', ?)", *normalizedTokens).
				WhereOr("vp.name ILIKE ?", "%"+searchQuery+"%").
				WhereOr("vp.status ILIKE ?", "%"+searchQuery+"%")
		})
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "search_query", searchQuery)
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// if no order is passed, set default to make sure objects return always in the same order and pagination works properly
	if page.OrderBy == nil {
		page.OrderBy = paginator.NewDefaultOrderBy(VpcPrefixOrderByDefault)
	}

	paginator, err := paginator.NewPaginator(ctx, query, page.Offset, page.Limit, page.OrderBy, VpcPrefixOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = paginator.Query.Limit(paginator.Limit).Offset(paginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return vps, paginator.Total, nil
}

// Update updates specified fields of an existing VpcPrefix
// The updated fields are assumed to be set to non-null values
// For setting to null values, use: Clear
// since there are 2 operations (UPDATE, SELECT), in this, it is required that
// this library call happens within a transaction
func (vpsd VpcPrefixSQLDAO) Update(ctx context.Context, tx *db.Tx, input VpcPrefixUpdateInput) (*VpcPrefix, error) {
	// Create a child span and set the attributes for current request
	ctx, vpDAOSpan := vpsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcPrefixDAO.Update")
	if vpDAOSpan != nil {
		defer vpDAOSpan.End()

		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "id", input.VpcPrefixID)
	}

	vp := &VpcPrefix{
		ID: input.VpcPrefixID,
	}
	updatedFields := []string{}

	if input.Name != nil {
		vp.Name = *input.Name
		updatedFields = append(updatedFields, "name")
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "name", *input.Name)
	}
	if input.TenantOrg != nil {
		vp.Org = *input.TenantOrg
		updatedFields = append(updatedFields, "org")
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "org", *input.TenantOrg)
	}
	if input.VpcID != nil {
		vp.VpcID = *input.VpcID
		updatedFields = append(updatedFields, "vpc_id")
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "vpc_id", input.VpcID.String())
	}
	if input.TenantID != nil {
		vp.TenantID = *input.TenantID
		updatedFields = append(updatedFields, "tenant_id")
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "tenant_id", input.TenantID.String())
	}
	if input.IpBlockID != nil {
		vp.IPBlockID = input.IpBlockID
		updatedFields = append(updatedFields, "ip_block_id")
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "ip_block_id", input.IpBlockID.String())
	}
	if input.Prefix != nil {
		vp.Prefix = *input.Prefix
		updatedFields = append(updatedFields, "prefix")
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "prefix", *input.Prefix)
	}
	if input.PrefixLength != nil {
		vp.PrefixLength = *input.PrefixLength
		updatedFields = append(updatedFields, "prefix_length")
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "prefix_length", *input.PrefixLength)
	}
	if input.Status != nil {
		vp.Status = *input.Status
		updatedFields = append(updatedFields, "status")
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "status", *input.Status)
	}
	if input.IsMissingOnSite != nil {
		vp.IsMissingOnSite = *input.IsMissingOnSite
		updatedFields = append(updatedFields, "is_missing_on_site")
		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "is_missing_on_site", *input.IsMissingOnSite)
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, vpsd.dbSession).NewUpdate().Model(vp).Column(updatedFields...).Where("id = ?", input.VpcPrefixID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nvp, err := vpsd.GetByID(ctx, tx, vp.ID, nil)

	if err != nil {
		return nil, err
	}
	return nvp, nil
}

// Delete deletes an VpcPrefix by ID
// error is returned only if there is a db error
// if the object being deleted doesnt exist, error is not returned (idempotent delete)
func (vpsd VpcPrefixSQLDAO) Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, vpDAOSpan := vpsd.tracerSpan.CreateChildInCurrentContext(ctx, "VpcPrefixDAO.Delete")
	if vpDAOSpan != nil {
		defer vpDAOSpan.End()

		vpsd.tracerSpan.SetAttribute(vpDAOSpan, "id", id.String())
	}

	vp := &VpcPrefix{
		ID: id,
	}

	_, err := db.GetIDB(tx, vpsd.dbSession).NewDelete().Model(vp).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// queryEthernetInterfaceIPsForVPCPrefix returns iface row count (all matching ethernet interfaces)
// and, for each row with assigned IPs, a slice of that interface's IPv4 addresses.
// One SELECT suffices: COUNT(*) equals the number of result rows given the same join/filter.
func queryEthernetInterfaceIPsForVPCPrefix(ctx context.Context, idb bun.IDB, vpcPrefixID uuid.UUID) (ifaceRows int64, ipStrings [][]string, err error) {
	type row struct {
		IPAddresses []string `bun:"ip_addresses,array"`
	}
	var rows []row
	err = idb.NewRaw(
		`SELECT ifc.ip_addresses FROM "interface" AS ifc INNER JOIN instance AS inst ON inst.id = ifc.instance_id
		 WHERE ifc.vpc_prefix_id = ? AND ifc.deleted IS NULL AND inst.deleted IS NULL
		   AND inst.status NOT IN ('Terminating', 'Terminated')`,
		vpcPrefixID,
	).Scan(ctx, &rows)
	if err != nil {
		return 0, nil, err
	}
	count := int64(len(rows))
	ips := make([][]string, 0, len(rows))
	for _, r := range rows {
		if len(r.IPAddresses) > 0 {
			ips = append(ips, r.IPAddresses)
		}
	}
	return count, ips, nil
}

// GetPrefixUsage derives IPv4 interface usage stats for this VpcPrefix via an in-memory IPAM simulation.
func (vpsd VpcPrefixSQLDAO) GetPrefixUsage(ctx context.Context, tx *db.Tx, vp *VpcPrefix) (*cipam.Usage, error) {
	if vp == nil {
		return nil, fmt.Errorf("Failed to calculate usage stats for VPC Prefix: nil argument")
	}

	var cidr string
	if strings.Contains(vp.Prefix, "/") {
		cidr = vp.Prefix
	} else {
		cidr = fmt.Sprintf("%s/%d", vp.Prefix, vp.PrefixLength)
	}
	if cidr == "" {
		return nil, fmt.Errorf("Failed to calculate usage stats for VPC Prefix %q: CIDR could not be populated", vp.ID.String())
	}

	// Query the IP addresses for each Interface associated with this VPC Prefix
	idb := db.GetIDB(tx, vpsd.dbSession)
	ifcCount, ips, err := queryEthernetInterfaceIPsForVPCPrefix(ctx, idb, vp.ID)
	if err != nil {
		return nil, err
	}

	// derive the usage stats via an in-memory IPAM simulation
	ipamer := cipam.New(ctx)
	ipamPrefix, err := ipamer.NewPrefix(ctx, cidr)
	if err != nil {
		return nil, err
	}

	validatedCidr := ipamPrefix.Cidr
	netIpPrefix, err := netip.ParsePrefix(validatedCidr)
	if err != nil {
		return nil, err
	}

	// track acquired prefixes to avoid duplicates
	// each interface IP address consumes 2 /31 prefixes
	acquiredPrefixes := make(map[string]struct{})
	for _, ipAddresses := range ips {
		for _, ipStr := range ipAddresses {
			netIpAddr, ierr := netip.ParseAddr(strings.TrimSpace(ipStr))
			if ierr != nil || !netIpAddr.Is4() {
				continue
			}
			if !netIpPrefix.Contains(netIpAddr) {
				continue
			}
			// derive the /31 prefix for the IP address
			contained31Prefix, perr := netIpAddr.Prefix(31)
			if perr != nil {
				continue
			}
			k := contained31Prefix.Masked().String()
			if _, dup := acquiredPrefixes[k]; dup {
				continue
			}
			if _, ierr := ipamer.AcquireSpecificChildPrefix(ctx, validatedCidr, k); ierr != nil {
				continue
			}
			acquiredPrefixes[k] = struct{}{}
		}
	}

	ipamPrefix = ipamer.PrefixFrom(ctx, validatedCidr)
	if ipamPrefix == nil {
		return nil, fmt.Errorf("Prefix %q was not found in IPAM after loading IPs", validatedCidr)
	}

	usage := ipamPrefix.Usage()

	acquiredIPs := uint64(ifcCount) * 2
	if acquiredIPs > usage.AvailableIPs {
		acquiredIPs = usage.AvailableIPs
	}

	return &cipam.Usage{
		AvailableIPs:              usage.AvailableIPs,
		AcquiredIPs:               acquiredIPs,
		AvailableSmallestPrefixes: usage.AvailableSmallestPrefixes,
		AvailablePrefixes:         usage.AvailablePrefixes,
		AcquiredPrefixes:          usage.AcquiredPrefixes,
	}, nil
}

// NewVpcPrefixDAO returns a new VpcPrefixDAO
func NewVpcPrefixDAO(dbSession *db.Session) VpcPrefixDAO {
	return &VpcPrefixSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
