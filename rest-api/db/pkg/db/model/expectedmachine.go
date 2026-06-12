// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"

	"github.com/uptrace/bun"

	stracer "github.com/NVIDIA/infra-controller/rest-api/db/pkg/tracer"
)

const (
	// ExpectedMachineOrderByDefault default field to be used for ordering when none specified
	ExpectedMachineOrderByDefault = "created"
)

var (
	// ExpectedMachineOrderByFields is a list of valid order by fields for the ExpectedMachine model
	ExpectedMachineOrderByFields = []string{
		"id",
		"site_id",
		"bmc_mac_address",
		"chassis_serial_number",
		"created",
		"updated",
	}
	// ExpectedMachineRelatedEntities is a list of valid relation by fields for the ExpectedMachine model
	ExpectedMachineRelatedEntities = map[string]bool{
		SiteRelationName:    true,
		SkuRelationName:     true,
		MachineRelationName: true,
	}
)

// ExpectedMachine is a record for each bare-metal host expected to be processed by NICo
type ExpectedMachine struct {
	bun.BaseModel `bun:"table:expected_machine,alias:em"`

	ID                       uuid.UUID `bun:"id,pk"`
	SiteID                   uuid.UUID `bun:"site_id,type:uuid,notnull"`
	Site                     *Site     `bun:"rel:belongs-to,join:site_id=id"`
	BmcMacAddress            string    `bun:"bmc_mac_address,notnull"`
	ChassisSerialNumber      string    `bun:"chassis_serial_number,notnull"`
	SkuID                    *string   `bun:"sku_id"`
	Sku                      *SKU      `bun:"rel:belongs-to,join:sku_id=id"`
	MachineID                *string   `bun:"machine_id"`
	Machine                  *Machine  `bun:"rel:belongs-to,join:machine_id=id"`
	FallbackDpuSerialNumbers []string  `bun:"fallback_dpu_serial_numbers,array"`
	BmcIpAddress             *string   `bun:"bmc_ip_address"`
	RackID                   *string   `bun:"rack_id"`
	Name                     *string   `bun:"name"`
	Manufacturer             *string   `bun:"manufacturer"`
	Model                    *string   `bun:"model"`
	Description              *string   `bun:"description"`
	SlotID                   *int32    `bun:"slot_id"`
	TrayIdx                  *int32    `bun:"tray_idx"`
	HostID                   *int32    `bun:"host_id"`
	Labels                   Labels    `bun:"labels,type:jsonb"`
	Created                  time.Time `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated                  time.Time `bun:"updated,nullzero,notnull,default:current_timestamp"`
	CreatedBy                uuid.UUID `bun:"type:uuid,notnull"`
}

// ExpectedMachineCredentials carries the BMC credentials for one
// ExpectedMachine. They live in their own type because they aren't stored
// in the DB record and have to be threaded through to ToProto separately.
type ExpectedMachineCredentials struct {
	Username *string
	Password *string
}

// ToProto builds the workflow proto for this ExpectedMachine. BMC
// credentials are passed in because they aren't persisted on the record;
// labels are read from em.Labels.
func (em *ExpectedMachine) ToProto(creds ExpectedMachineCredentials) *cwssaws.ExpectedMachine {
	proto := &cwssaws.ExpectedMachine{
		Id:                       &cwssaws.UUID{Value: em.ID.String()},
		BmcMacAddress:            em.BmcMacAddress,
		ChassisSerialNumber:      em.ChassisSerialNumber,
		FallbackDpuSerialNumbers: em.FallbackDpuSerialNumbers,
		SkuId:                    em.SkuID,
	}

	if em.BmcIpAddress != nil {
		proto.BmcIpAddress = em.BmcIpAddress
	}
	if em.RackID != nil {
		proto.RackId = &cwssaws.RackId{Id: *em.RackID}
	}
	if em.Name != nil {
		proto.Name = em.Name
	}
	if em.Manufacturer != nil {
		proto.Manufacturer = em.Manufacturer
	}
	if em.Model != nil {
		proto.Model = em.Model
	}
	if em.Description != nil {
		proto.Description = em.Description
	}
	if em.SlotID != nil {
		proto.SlotId = em.SlotID
	}
	if em.TrayIdx != nil {
		proto.TrayIdx = em.TrayIdx
	}
	if em.HostID != nil {
		proto.HostId = em.HostID
	}

	if creds.Username != nil {
		proto.BmcUsername = *creds.Username
	}
	if creds.Password != nil {
		proto.BmcPassword = *creds.Password
	}

	metadata := &cwssaws.Metadata{
		Labels: expectedComponentLabelsInput{
			Manufacturer: em.Manufacturer,
			Model:        em.Model,
			SlotID:       em.SlotID,
			TrayIdx:      em.TrayIdx,
			HostID:       em.HostID,
			Labels:       em.Labels,
		}.ToProto(),
	}
	if em.Name != nil {
		metadata.Name = *em.Name
	}
	if em.Description != nil {
		metadata.Description = *em.Description
	}
	proto.Metadata = metadata

	return proto
}

// FromProto populates this ExpectedMachine from a workflow proto reported
// by a Site. linkedMachineID, when non-nil, is the ID of the Machine
// matched by BmcMacAddress (resolved by the caller from a separate lookup
// table). A nil proto is a no-op. An invalid or missing proto.Id leaves
// em.ID unchanged so the caller can validate the proto's UUID before
// calling.
func (em *ExpectedMachine) FromProto(proto *cwssaws.ExpectedMachine, linkedMachineID *string) {
	if proto == nil {
		return
	}
	if proto.Id != nil {
		if id, err := uuid.Parse(proto.Id.Value); err == nil {
			em.ID = id
		}
	}
	em.BmcMacAddress = proto.BmcMacAddress
	em.ChassisSerialNumber = proto.ChassisSerialNumber
	em.SkuID = proto.SkuId
	em.MachineID = linkedMachineID
	em.FallbackDpuSerialNumbers = proto.FallbackDpuSerialNumbers
	em.BmcIpAddress = proto.BmcIpAddress
	if proto.RackId != nil {
		rackID := proto.RackId.Id
		em.RackID = &rackID
	} else {
		em.RackID = nil
	}
	em.Name = proto.Name
	em.Manufacturer = proto.Manufacturer
	em.Model = proto.Model
	em.Description = proto.Description
	em.SlotID = proto.SlotId
	em.TrayIdx = proto.TrayIdx
	em.HostID = proto.HostId
	em.Labels.FromProto(proto.Metadata.GetLabels())
}

// ExpectedMachineCreateInput input parameters for Create method
type ExpectedMachineCreateInput struct {
	ExpectedMachineID        uuid.UUID
	SiteID                   uuid.UUID
	BmcMacAddress            string
	ChassisSerialNumber      string
	SkuID                    *string
	MachineID                *string
	FallbackDpuSerialNumbers []string
	BmcIpAddress             *string
	RackID                   *string
	Name                     *string
	Manufacturer             *string
	Model                    *string
	Description              *string
	SlotID                   *int32
	TrayIdx                  *int32
	HostID                   *int32
	Labels                   map[string]string
	CreatedBy                uuid.UUID
}

// ExpectedMachineUpdateInput input parameters for Update method
type ExpectedMachineUpdateInput struct {
	ExpectedMachineID        uuid.UUID
	BmcMacAddress            *string
	ChassisSerialNumber      *string
	SkuID                    *string
	MachineID                *string
	FallbackDpuSerialNumbers []string
	BmcIpAddress             *string
	RackID                   *string
	Name                     *string
	Manufacturer             *string
	Model                    *string
	Description              *string
	SlotID                   *int32
	TrayIdx                  *int32
	HostID                   *int32
	Labels                   map[string]string
}

// ExpectedMachineClearInput input parameters for Clear method
type ExpectedMachineClearInput struct {
	ExpectedMachineID        uuid.UUID
	SkuID                    bool
	MachineID                bool
	FallbackDpuSerialNumbers bool
	BmcIpAddress             bool
	RackID                   bool
	Name                     bool
	Manufacturer             bool
	Model                    bool
	Description              bool
	SlotID                   bool
	TrayIdx                  bool
	HostID                   bool
	Labels                   bool
}

// ExpectedMachineFilterInput filtering options for GetAll method
type ExpectedMachineFilterInput struct {
	ExpectedMachineIDs   []uuid.UUID
	SiteIDs              []uuid.UUID
	BmcMacAddresses      []string
	ChassisSerialNumbers []string
	SkuIDs               []string
	MachineIDs           []string
	SearchQuery          *string
}

var _ bun.BeforeAppendModelHook = (*ExpectedMachine)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (em *ExpectedMachine) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		em.Created = db.GetCurTime()
		em.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		em.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*ExpectedMachine)(nil)

// BeforeCreateTable is a hook that is called before the table is created
// This is only used in tests
func (em *ExpectedMachine) BeforeCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey(`("site_id") REFERENCES "site" ("id")`).
		ForeignKey(`("sku_id") REFERENCES "sku" ("id")`).
		ForeignKey(`("machine_id") REFERENCES "machine" ("id")`)
	return nil
}

// ExpectedMachineDAO is an interface for interacting with the ExpectedMachine model
type ExpectedMachineDAO interface {
	// Create used to create new row
	Create(ctx context.Context, tx *db.Tx, input ExpectedMachineCreateInput) (*ExpectedMachine, error)
	// CreateMultiple used to create multiple rows
	CreateMultiple(ctx context.Context, tx *db.Tx, inputs []ExpectedMachineCreateInput) ([]ExpectedMachine, error)
	// Update used to update row
	Update(ctx context.Context, tx *db.Tx, input ExpectedMachineUpdateInput) (*ExpectedMachine, error)
	// UpdateMultiple used to update multiple rows
	UpdateMultiple(ctx context.Context, tx *db.Tx, inputs []ExpectedMachineUpdateInput) ([]ExpectedMachine, error)
	// Delete used to delete row
	Delete(ctx context.Context, tx *db.Tx, expectedMachineID uuid.UUID) error
	// Clear used to clear fields in the row
	Clear(ctx context.Context, tx *db.Tx, input ExpectedMachineClearInput) (*ExpectedMachine, error)
	// GetAll returns all the rows based on the filter and page inputs
	GetAll(ctx context.Context, tx *db.Tx, filter ExpectedMachineFilterInput, page paginator.PageInput, includeRelations []string) ([]ExpectedMachine, int, error)
	// Get returns row for specified ID
	Get(ctx context.Context, tx *db.Tx, expectedMachineID uuid.UUID, includeRelations []string, forUpdate bool) (*ExpectedMachine, error)
}

// ExpectedMachineSQLDAO is an implementation of the ExpectedMachineDAO interface
type ExpectedMachineSQLDAO struct {
	dbSession  *db.Session
	tracerSpan *stracer.TracerSpan

	ExpectedMachineDAO
}

// Create creates a new ExpectedMachine from the given parameters
// The returned ExpectedMachine will not have any related structs filled in.
// Since there are 2 operations (INSERT, SELECT), it is required that
// this library call happens within a transaction
func (emsd ExpectedMachineSQLDAO) Create(ctx context.Context, tx *db.Tx, input ExpectedMachineCreateInput) (*ExpectedMachine, error) {
	// Create a child span and set the attributes for current request
	ctx, expectedMachineDAOSpan := emsd.tracerSpan.CreateChildInCurrentContext(ctx, "ExpectedMachineDAO.Create")
	if expectedMachineDAOSpan != nil {
		defer expectedMachineDAOSpan.End()
	}

	results, err := emsd.CreateMultiple(ctx, tx, []ExpectedMachineCreateInput{input})
	if err != nil {
		return nil, err
	}
	return &results[0], nil
}

// CreateMultiple creates multiple ExpectedMachines from the given parameters
// The returned ExpectedMachines will not have any related structs filled in.
// Since there are 2 operations (INSERT, SELECT), it is required that
// this library call happens within a transaction
func (emsd ExpectedMachineSQLDAO) CreateMultiple(ctx context.Context, tx *db.Tx, inputs []ExpectedMachineCreateInput) ([]ExpectedMachine, error) {
	// Create a child span and set the attributes for current request
	ctx, expectedMachineDAOSpan := emsd.tracerSpan.CreateChildInCurrentContext(ctx, "ExpectedMachineDAO.CreateMultiple")
	if expectedMachineDAOSpan != nil {
		defer expectedMachineDAOSpan.End()
		emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "batch_size", len(inputs))
	}

	if len(inputs) == 0 {
		return []ExpectedMachine{}, nil
	}

	expectedMachines := make([]ExpectedMachine, 0, len(inputs))
	ids := make([]uuid.UUID, 0, len(inputs))

	// NOTE: since Expected Machine can be created by NICo or Cloud API the caller MUST provide the ID.
	for _, input := range inputs {
		em := ExpectedMachine{
			ID:                       input.ExpectedMachineID,
			SiteID:                   input.SiteID,
			BmcMacAddress:            input.BmcMacAddress,
			ChassisSerialNumber:      input.ChassisSerialNumber,
			SkuID:                    input.SkuID,
			MachineID:                input.MachineID,
			FallbackDpuSerialNumbers: input.FallbackDpuSerialNumbers,
			BmcIpAddress:             input.BmcIpAddress,
			RackID:                   input.RackID,
			Name:                     input.Name,
			Manufacturer:             input.Manufacturer,
			Model:                    input.Model,
			Description:              input.Description,
			SlotID:                   input.SlotID,
			TrayIdx:                  input.TrayIdx,
			HostID:                   input.HostID,
			Labels:                   input.Labels,
			CreatedBy:                input.CreatedBy,
		}
		expectedMachines = append(expectedMachines, em)
		ids = append(ids, em.ID)
	}

	// Add summary tracing attributes
	if expectedMachineDAOSpan != nil && len(inputs) > 0 {
		emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "first_id", ids[0].String())
		if len(ids) > 1 {
			emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "last_id", ids[len(ids)-1].String())
		}
	}

	_, err := db.GetIDB(tx, emsd.dbSession).NewInsert().Model(&expectedMachines).Exec(ctx)
	if err != nil {
		return nil, err
	}

	// Fetch the created expected machines
	var result []ExpectedMachine
	err = db.GetIDB(tx, emsd.dbSession).NewSelect().Model(&result).Where("em.id IN (?)", bun.In(ids)).Scan(ctx)
	if err != nil {
		return nil, err
	}

	// Sort result to match input order (O(n) direct index placement)
	// This check should never fail since we just inserted these records with the exact ids
	if len(result) != len(ids) {
		return nil, fmt.Errorf("unexpected result count: got %d, expected %d", len(result), len(ids))
	}
	idToIndex := make(map[uuid.UUID]int, len(ids))
	for i, id := range ids {
		idToIndex[id] = i
	}
	sorted := make([]ExpectedMachine, len(result))
	for _, item := range result {
		sorted[idToIndex[item.ID]] = item
	}

	return sorted, nil
}

// Get returns an ExpectedMachine by ID
// returns db.ErrDoesNotExist error if the record is not found
func (emsd ExpectedMachineSQLDAO) Get(ctx context.Context, tx *db.Tx, expectedMachineID uuid.UUID, includeRelations []string, forUpdate bool) (*ExpectedMachine, error) {
	// Create a child span and set the attributes for current request
	ctx, expectedMachineDAOSpan := emsd.tracerSpan.CreateChildInCurrentContext(ctx, "ExpectedMachineDAO.Get")
	if expectedMachineDAOSpan != nil {
		defer expectedMachineDAOSpan.End()

		emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "id", expectedMachineID.String())
	}

	em := &ExpectedMachine{}

	query := db.GetIDB(tx, emsd.dbSession).NewSelect().Model(em).Where("em.id = ?", expectedMachineID)

	if forUpdate {
		query = query.For("UPDATE")
	}

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

	return em, nil
}

// setQueryWithFilter populates the lookup query based on specified filter
func (emsd ExpectedMachineSQLDAO) setQueryWithFilter(filter ExpectedMachineFilterInput, query *bun.SelectQuery, expectedMachineDAOSpan *stracer.CurrentContextSpan) (*bun.SelectQuery, error) {
	if filter.SiteIDs != nil {
		query = query.Where("em.site_id IN (?)", bun.In(filter.SiteIDs))
		if expectedMachineDAOSpan != nil {
			emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "site_ids", filter.SiteIDs)
		}
	}

	if filter.ExpectedMachineIDs != nil {
		query = query.Where("em.id IN (?)", bun.In(filter.ExpectedMachineIDs))
		if expectedMachineDAOSpan != nil {
			emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "expected_machine_ids", filter.ExpectedMachineIDs)
		}
	}

	if filter.BmcMacAddresses != nil {
		query = query.Where("em.bmc_mac_address IN (?)", bun.In(filter.BmcMacAddresses))
		if expectedMachineDAOSpan != nil {
			emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "bmc_mac_addresses", filter.BmcMacAddresses)
		}
	}

	if filter.ChassisSerialNumbers != nil {
		query = query.Where("em.chassis_serial_number IN (?)", bun.In(filter.ChassisSerialNumbers))
		if expectedMachineDAOSpan != nil {
			emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "chassis_serial_numbers", filter.ChassisSerialNumbers)
		}
	}

	if filter.SkuIDs != nil {
		query = query.Where("em.sku_id IN (?)", bun.In(filter.SkuIDs))
		if expectedMachineDAOSpan != nil {
			emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "sku_ids", filter.SkuIDs)
		}
	}

	if filter.MachineIDs != nil {
		query = query.Where("em.machine_id IN (?)", bun.In(filter.MachineIDs))
		if expectedMachineDAOSpan != nil {
			emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "machine_ids", filter.MachineIDs)
		}
	}

	searchQuery, searchTokens, ok := db.NormalizeSearchQuery(filter.SearchQuery)
	if ok {
		query = query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				Where("to_tsvector('english', (coalesce(em.bmc_mac_address, ' ') || ' ' || coalesce(em.chassis_serial_number, ' ') || ' ' || coalesce(em.sku_id, ' ') || ' ' || coalesce(em.machine_id, ' ') || ' ' || coalesce(em.fallback_dpu_serial_numbers::text, ' ') || ' ' || coalesce(em.labels::text, ' '))) @@ to_tsquery('english', ?)", *searchTokens).
				WhereOr("em.bmc_mac_address ILIKE ?", "%"+searchQuery+"%").
				WhereOr("em.chassis_serial_number ILIKE ?", "%"+searchQuery+"%").
				WhereOr("em.sku_id ILIKE ?", "%"+searchQuery+"%").
				WhereOr("em.machine_id ILIKE ?", "%"+searchQuery+"%").
				WhereOr("em.fallback_dpu_serial_numbers::text ILIKE ?", "%"+searchQuery+"%").
				WhereOr("em.labels::text ILIKE ?", "%"+searchQuery+"%").
				WhereOr("em.id::text ILIKE ?", "%"+searchQuery+"%").
				WhereOr("em.site_id::text ILIKE ?", "%"+searchQuery+"%")
		})
		if expectedMachineDAOSpan != nil {
			emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "search_query", searchQuery)
		}
	}

	return query, nil
}

// GetAll returns all ExpectedMachines based on the filter and paging
// Errors are returned only when there is a db related error
// If records not found, then error is nil, but length of returned slice is 0
// If orderBy is nil, then records are ordered by column specified in ExpectedMachineOrderByDefault in ascending order
func (emsd ExpectedMachineSQLDAO) GetAll(ctx context.Context, tx *db.Tx, filter ExpectedMachineFilterInput, page paginator.PageInput, includeRelations []string) ([]ExpectedMachine, int, error) {
	// Create a child span and set the attributes for current request
	ctx, expectedMachineDAOSpan := emsd.tracerSpan.CreateChildInCurrentContext(ctx, "ExpectedMachineDAO.GetAll")
	if expectedMachineDAOSpan != nil {
		defer expectedMachineDAOSpan.End()
	}

	var expectedMachines []ExpectedMachine

	if filter.ExpectedMachineIDs != nil && len(filter.ExpectedMachineIDs) == 0 {
		return expectedMachines, 0, nil
	}

	query := db.GetIDB(tx, emsd.dbSession).NewSelect().Model(&expectedMachines)

	query, err := emsd.setQueryWithFilter(filter, query, expectedMachineDAOSpan)
	if err != nil {
		return expectedMachines, 0, err
	}

	// Apply relations if requested
	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// If no order is passed, set default order to make sure objects return always in the same order and pagination works properly
	if page.OrderBy == nil {
		page.OrderBy = paginator.NewDefaultOrderBy(ExpectedMachineOrderByDefault)
	}

	expectedMachinePaginator, err := paginator.NewPaginator(ctx, query, page.Offset, page.Limit, page.OrderBy, ExpectedMachineOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = expectedMachinePaginator.Query.Limit(expectedMachinePaginator.Limit).Offset(expectedMachinePaginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return expectedMachines, expectedMachinePaginator.Total, nil
}

// Update updates specified fields of an existing ExpectedMachine
// The updated fields are assumed to be set to non-null values
// For setting to null values, use: Clear
// since there are 2 operations (UPDATE, SELECT), it is required that
// this library call happens within a transaction
func (emsd ExpectedMachineSQLDAO) Update(ctx context.Context, tx *db.Tx, input ExpectedMachineUpdateInput) (*ExpectedMachine, error) {
	// Create a child span and set the attributes for current request
	ctx, expectedMachineDAOSpan := emsd.tracerSpan.CreateChildInCurrentContext(ctx, "ExpectedMachineDAO.Update")
	if expectedMachineDAOSpan != nil {
		defer expectedMachineDAOSpan.End()
		// Detailed per-field tracing is recorded in the UpdateMultiple child span.
	}

	results, err := emsd.UpdateMultiple(ctx, tx, []ExpectedMachineUpdateInput{input})
	if err != nil {
		return nil, err
	}
	return &results[0], nil
}

// UpdateMultiple updates multiple ExpectedMachines with the given parameters using a single bulk UPDATE query
// All inputs should update the same set of fields for optimal performance
// The updated fields are assumed to be set to non-null values.
// Since there are 2 operations (UPDATE, SELECT), it is required that
// this library call happens within a transaction
func (emsd ExpectedMachineSQLDAO) UpdateMultiple(ctx context.Context, tx *db.Tx, inputs []ExpectedMachineUpdateInput) ([]ExpectedMachine, error) {
	// Create a child span and set the attributes for current request
	ctx, expectedMachineDAOSpan := emsd.tracerSpan.CreateChildInCurrentContext(ctx, "ExpectedMachineDAO.UpdateMultiple")
	if expectedMachineDAOSpan != nil {
		defer expectedMachineDAOSpan.End()
		emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "batch_size", len(inputs))
	}

	if len(inputs) == 0 {
		return []ExpectedMachine{}, nil
	}

	// Build expected machines and collect columns to update
	expectedMachines := make([]*ExpectedMachine, 0, len(inputs))
	ids := make([]uuid.UUID, 0, len(inputs))
	columnsSet := make(map[string]bool)

	for _, input := range inputs {
		em := &ExpectedMachine{
			ID: input.ExpectedMachineID,
		}

		if input.BmcMacAddress != nil {
			em.BmcMacAddress = *input.BmcMacAddress
			columnsSet["bmc_mac_address"] = true
		}
		if input.ChassisSerialNumber != nil {
			em.ChassisSerialNumber = *input.ChassisSerialNumber
			columnsSet["chassis_serial_number"] = true
		}
		if input.FallbackDpuSerialNumbers != nil {
			em.FallbackDpuSerialNumbers = input.FallbackDpuSerialNumbers
			columnsSet["fallback_dpu_serial_numbers"] = true
		}
		if input.Labels != nil {
			em.Labels = input.Labels
			columnsSet["labels"] = true
		}
		if input.SkuID != nil {
			em.SkuID = input.SkuID
			columnsSet["sku_id"] = true
		}
		if input.MachineID != nil {
			em.MachineID = input.MachineID
			columnsSet["machine_id"] = true
		}
		if input.BmcIpAddress != nil {
			em.BmcIpAddress = input.BmcIpAddress
			columnsSet["bmc_ip_address"] = true
		}
		if input.RackID != nil {
			em.RackID = input.RackID
			columnsSet["rack_id"] = true
		}
		if input.Name != nil {
			em.Name = input.Name
			columnsSet["name"] = true
		}
		if input.Manufacturer != nil {
			em.Manufacturer = input.Manufacturer
			columnsSet["manufacturer"] = true
		}
		if input.Model != nil {
			em.Model = input.Model
			columnsSet["model"] = true
		}
		if input.Description != nil {
			em.Description = input.Description
			columnsSet["description"] = true
		}
		if input.SlotID != nil {
			em.SlotID = input.SlotID
			columnsSet["slot_id"] = true
		}
		if input.TrayIdx != nil {
			em.TrayIdx = input.TrayIdx
			columnsSet["tray_idx"] = true
		}
		if input.HostID != nil {
			em.HostID = input.HostID
			columnsSet["host_id"] = true
		}

		expectedMachines = append(expectedMachines, em)
		ids = append(ids, input.ExpectedMachineID)
	}

	// Build column list
	columns := make([]string, 0, len(columnsSet)+1)
	for col := range columnsSet {
		columns = append(columns, col)
	}
	columns = append(columns, "updated")

	// Add summary tracing attributes
	if expectedMachineDAOSpan != nil && len(inputs) > 0 {
		emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "columns_updated", strings.Join(columns, ","))
		emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "first_id", ids[0].String())
		if len(ids) > 1 {
			emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "last_id", ids[len(ids)-1].String())
		}
	}

	// Execute bulk update
	_, err := db.GetIDB(tx, emsd.dbSession).NewUpdate().
		Model(&expectedMachines).
		Column(columns...).
		Bulk().
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	// Fetch the updated expected machines
	var result []ExpectedMachine
	err = db.GetIDB(tx, emsd.dbSession).NewSelect().Model(&result).Where("em.id IN (?)", bun.In(ids)).Scan(ctx)
	if err != nil {
		return nil, err
	}

	// Sort result to match input order (O(n) direct index placement)
	// This check should never fail since we just updated these records with the exact ids
	if len(result) != len(ids) {
		return nil, fmt.Errorf("unexpected result count: got %d, expected %d", len(result), len(ids))
	}
	idToIndex := make(map[uuid.UUID]int, len(ids))
	for i, id := range ids {
		idToIndex[id] = i
	}
	sorted := make([]ExpectedMachine, len(result))
	for _, item := range result {
		sorted[idToIndex[item.ID]] = item
	}

	return sorted, nil
}

// Clear sets parameters of an existing ExpectedMachine to null values in db
func (emsd ExpectedMachineSQLDAO) Clear(ctx context.Context, tx *db.Tx, input ExpectedMachineClearInput) (*ExpectedMachine, error) {
	// Create a child span and set the attributes for current request
	ctx, expectedMachineDAOSpan := emsd.tracerSpan.CreateChildInCurrentContext(ctx, "ExpectedMachineDAO.Clear")
	if expectedMachineDAOSpan != nil {
		defer expectedMachineDAOSpan.End()
	}

	em := &ExpectedMachine{
		ID: input.ExpectedMachineID,
	}

	updatedFields := []string{}
	if input.SkuID {
		em.SkuID = nil
		updatedFields = append(updatedFields, "sku_id")
	}
	if input.MachineID {
		em.MachineID = nil
		updatedFields = append(updatedFields, "machine_id")
	}
	if input.FallbackDpuSerialNumbers {
		em.FallbackDpuSerialNumbers = nil
		updatedFields = append(updatedFields, "fallback_dpu_serial_numbers")
	}
	if input.BmcIpAddress {
		em.BmcIpAddress = nil
		updatedFields = append(updatedFields, "bmc_ip_address")
	}
	if input.RackID {
		em.RackID = nil
		updatedFields = append(updatedFields, "rack_id")
	}
	if input.Name {
		em.Name = nil
		updatedFields = append(updatedFields, "name")
	}
	if input.Manufacturer {
		em.Manufacturer = nil
		updatedFields = append(updatedFields, "manufacturer")
	}
	if input.Model {
		em.Model = nil
		updatedFields = append(updatedFields, "model")
	}
	if input.Description {
		em.Description = nil
		updatedFields = append(updatedFields, "description")
	}
	if input.SlotID {
		em.SlotID = nil
		updatedFields = append(updatedFields, "slot_id")
	}
	if input.TrayIdx {
		em.TrayIdx = nil
		updatedFields = append(updatedFields, "tray_idx")
	}
	if input.HostID {
		em.HostID = nil
		updatedFields = append(updatedFields, "host_id")
	}
	if input.Labels {
		em.Labels = nil
		updatedFields = append(updatedFields, "labels")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, emsd.dbSession).NewUpdate().Model(em).Column(updatedFields...).Where("id = ?", input.ExpectedMachineID).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := emsd.Get(ctx, tx, input.ExpectedMachineID, nil, false)
	if err != nil {
		return nil, err
	}
	return nv, nil
}

// Delete deletes an ExpectedMachine by ID
// Error is returned only if there is a db error
func (emsd ExpectedMachineSQLDAO) Delete(ctx context.Context, tx *db.Tx, expectedMachineID uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, expectedMachineDAOSpan := emsd.tracerSpan.CreateChildInCurrentContext(ctx, "ExpectedMachineDAO.Delete")
	if expectedMachineDAOSpan != nil {
		defer expectedMachineDAOSpan.End()

		emsd.tracerSpan.SetAttribute(expectedMachineDAOSpan, "id", expectedMachineID.String())
	}

	em := &ExpectedMachine{
		ID: expectedMachineID,
	}

	var err error

	_, err = db.GetIDB(tx, emsd.dbSession).NewDelete().Model(em).Where("id = ?", expectedMachineID).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewExpectedMachineDAO returns a new ExpectedMachineDAO
func NewExpectedMachineDAO(dbSession *db.Session) ExpectedMachineDAO {
	return &ExpectedMachineSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
