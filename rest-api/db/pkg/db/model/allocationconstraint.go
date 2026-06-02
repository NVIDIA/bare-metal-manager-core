// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	"github.com/google/uuid"

	"github.com/uptrace/bun"
)

const (
	// AllocationConstraintTypeReserved indicates that the resources are reserved
	AllocationConstraintTypeReserved = "Reserved"
	// AllocationConstraintTypeOnDemand indicates that the resources are on-demand
	AllocationConstraintTypeOnDemand = "OnDemand"
	// AllocationConstraintTypePreemptible indicates that the resources are preemptible
	AllocationConstraintTypePreemptible = "Preemptible"

	// AllocationResourceTypeInstanceType indicates that the constraint is for an Instance Type
	AllocationResourceTypeInstanceType = "InstanceType"
	// AllocationResourceTypeIPBlock indicates that the constraint is for an IP Block
	AllocationResourceTypeIPBlock = "IPBlock"
	// AllocationConstraintRelationName is the relation name for the Allocation Constraint model
	AllocationConstraintRelationName = "AllocationConstraint"

	// AllocationConstraintOrderByDefault default field to be used for ordering when none specified
	AllocationConstraintOrderByDefault = "created"
)

var (
	// AllocationConstraintOrderByFields is a list of valid order by fields for the AllocationConstraint model
	AllocationConstraintOrderByFields = []string{"resource_type", "created", "updated"}
	// AllocationConstraintRelatedEntities is a list of valid relation by fields for the AllocationConstraint model
	AllocationConstraintRelatedEntities = map[string]bool{
		AllocationRelationName: true,
	}
	// AllocationConstraintResourceTypes is a list of valid resourcetypes for the AllocationConstraint model
	AllocationConstraintResourceTypes = map[string]bool{
		AllocationResourceTypeInstanceType: true,
		AllocationResourceTypeIPBlock:      true,
	}
	AllocationConstraintTypeMap = map[string]bool{
		AllocationConstraintTypeReserved:    true,
		AllocationConstraintTypeOnDemand:    true,
		AllocationConstraintTypePreemptible: true,
	}
)

// AllocationConstraint represents entries in the allocation_constraint table
// Constraints an allocation by specifying limits for different resource types
type AllocationConstraint struct {
	bun.BaseModel `bun:"table:allocation_constraint,alias:ac"`

	ID                uuid.UUID   `bun:"type:uuid,pk"`
	AllocationID      uuid.UUID   `bun:"allocation_id,type:uuid,notnull"`
	Allocation        *Allocation `bun:"rel:belongs-to,join:allocation_id=id"`
	ResourceType      string      `bun:"resource_type,notnull"` // AllocationResourceType
	ResourceTypeID    uuid.UUID   `bun:"resource_type_id,type:uuid,notnull"`
	ConstraintType    string      `bun:"constraint_type,notnull"` // AllocationConstraintType
	ConstraintValue   int         `bun:"constraint_value,notnull"`
	DerivedResourceID *uuid.UUID  `bun:"derived_resource_id,type:uuid"` // Valid for IPBlock
	Created           time.Time   `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated           time.Time   `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted           *time.Time  `bun:"deleted,soft_delete"`
	CreatedBy         uuid.UUID   `bun:"type:uuid,notnull"`
}

// GetIndentedJSON returns formatted json of AllocationConstraint
func (ac *AllocationConstraint) GetIndentedJSON() ([]byte, error) {
	return json.MarshalIndent(ac, "", "  ")
}

var _ bun.BeforeAppendModelHook = (*AllocationConstraint)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (ac *AllocationConstraint) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		ac.Created = db.GetCurTime()
		ac.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		ac.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*AllocationConstraint)(nil)

// BeforeCreateTable is a hook that is called before the table is created
// This is only used in tests
func (ac *AllocationConstraint) BeforeCreateTable(ctx context.Context,
	query *bun.CreateTableQuery) error {
	query.ForeignKey(`("allocation_id") REFERENCES "allocation" ("id")`)
	return nil
}

// AllocationConstraintDAO is an interface for interacting with the AllocationConstraint model
type AllocationConstraintDAO interface {
	//
	CreateFromParams(ctx context.Context, tx *db.Tx,
		allocationID uuid.UUID, resourceType string,
		resourceTypeID uuid.UUID, constraintType string,
		constraintValue int, derivedResourceID *uuid.UUID,
		createdBy uuid.UUID) (*AllocationConstraint, error)
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID,
		includeRelations []string) (*AllocationConstraint, error)
	//
	GetAll(ctx context.Context, tx *db.Tx,
		allocationIDs []uuid.UUID, resourceType *string,
		resourceTypeID []uuid.UUID, constraintType *string,
		derivedResourceID *uuid.UUID, includeRelations []string,
		offset *int, limit *int, orderBy *paginator.OrderBy) ([]AllocationConstraint, int, error)
	//
	UpdateFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID,
		allocationID *uuid.UUID, resourceType *string,
		resourceTypeID *uuid.UUID, constraintType *string,
		constraintValue *int, derivedResourceID *uuid.UUID) (*AllocationConstraint, error)
	//
	ClearFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID,
		derivedResourceID bool) (*AllocationConstraint, error)
	//
	DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// AllocationConstraintSQLDAO is an implementation of the AllocationConstraintDAO interface
type AllocationConstraintSQLDAO struct {
	dbSession *db.Session
	AllocationConstraintDAO
	tracerSpan *stracer.TracerSpan
}

// CreateFromParams creates a new AllocationConstraint from the given parameters
// The returned AllocationConstraint will not have any related structs filled in
// since there are 2 operations (INSERT, SELECT), in this, it is required that
// this library call happens within a transaction
func (acd AllocationConstraintSQLDAO) CreateFromParams(
	ctx context.Context, tx *db.Tx, allocationID uuid.UUID,
	resourceType string, resourceTypeID uuid.UUID,
	constraintType string, constraintValue int,
	derivedResourceID *uuid.UUID, createdBy uuid.UUID) (*AllocationConstraint, error) {
	// Create a child span and set the attributes for current request
	ctx, aDAOSpan := acd.tracerSpan.CreateChildInCurrentContext(ctx, "AllocationConstraintDAO.CreateFromParams")
	if aDAOSpan != nil {
		defer aDAOSpan.End()

		acd.tracerSpan.SetAttribute(aDAOSpan, "allocation_id", allocationID.String())
	}

	//
	if len(strings.TrimSpace(resourceType)) == 0 {
		return nil, errors.New("resourceType is empty")
	}
	if len(strings.TrimSpace(constraintType)) == 0 {
		return nil, errors.New("constraintType is empty")
	}
	a := &AllocationConstraint{
		ID:                uuid.New(),
		AllocationID:      allocationID,
		ResourceType:      resourceType,
		ResourceTypeID:    resourceTypeID,
		ConstraintType:    constraintType,
		ConstraintValue:   constraintValue,
		DerivedResourceID: derivedResourceID,
		CreatedBy:         createdBy,
	}
	_, err := db.GetIDB(tx, acd.dbSession).NewInsert().Model(a).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nv, err := acd.GetByID(ctx, tx, a.ID, nil)
	if err != nil {
		return nil, err
	}

	return nv, nil
}

// GetByID returns a AllocationConstraint by ID
// returns db.ErrDoesNotExist error if the record is not found
func (acd AllocationConstraintSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID,
	includeRelations []string) (*AllocationConstraint, error) {
	// Create a child span and set the attributes for current request
	ctx, aDAOSpan := acd.tracerSpan.CreateChildInCurrentContext(ctx, "AllocationConstraintDAO.GetByID")
	if aDAOSpan != nil {
		defer aDAOSpan.End()

		acd.tracerSpan.SetAttribute(aDAOSpan, "id", id.String())
	}

	a := &AllocationConstraint{}

	query := db.GetIDB(tx, acd.dbSession).NewSelect().Model(a).Where("ac.id = ?", id)

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

	return a, nil
}

// GetAll returns all AllocationConstraints for an InstanceType
// Errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
// if orderBy is nil, then records are ordered by column specified in AllocationConstraintOrderByDefault in ascending order
func (acd AllocationConstraintSQLDAO) GetAll(ctx context.Context, tx *db.Tx,
	allocationIDs []uuid.UUID, resourceType *string,
	resourceTypeIDs []uuid.UUID, constraintType *string,
	derivedResourceID *uuid.UUID, includeRelations []string,
	offset *int, limit *int, orderBy *paginator.OrderBy) ([]AllocationConstraint, int, error) {
	acs := []AllocationConstraint{}
	// Create a child span and set the attributes for current request
	ctx, aDAOSpan := acd.tracerSpan.CreateChildInCurrentContext(ctx, "AllocationConstraintDAO.GetAll")
	if aDAOSpan != nil {
		defer aDAOSpan.End()
	}

	query := db.GetIDB(tx, acd.dbSession).NewSelect().Model(&acs)

	if allocationIDs != nil {
		if len(allocationIDs) == 1 {
			query = query.Where("ac.allocation_id = ?", allocationIDs[0])
		} else {
			query = query.Where("ac.allocation_id IN (?)", bun.In(allocationIDs))
		}
	}

	if resourceType != nil {
		query = query.Where("ac.resource_type = ?", *resourceType)

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "resource_type", *resourceType)
		}
	}

	if resourceTypeIDs != nil {
		if len(resourceTypeIDs) == 1 {
			query = query.Where("ac.resource_type_id = ?", resourceTypeIDs[0])
		} else {
			query = query.Where("ac.resource_type_id IN (?)", bun.In(resourceTypeIDs))
		}

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "resource_type_ids", resourceTypeIDs)
		}
	}

	if constraintType != nil {
		query = query.Where("ac.constraint_type = ?", *constraintType)

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "constraint_type", *constraintType)
		}
	}

	if derivedResourceID != nil {
		query = query.Where("ac.derived_resource_id = ?", *derivedResourceID)

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "derived_resource_id", *derivedResourceID)
		}
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// if no order is passed, set default to make sure objects return always in the same order and pagination works properly
	if orderBy == nil {
		orderBy = paginator.NewDefaultOrderBy(AllocationConstraintOrderByDefault)
	}

	paginator, err := paginator.NewPaginator(ctx, query, offset, limit, orderBy, SiteOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = paginator.Query.Limit(paginator.Limit).Offset(paginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return acs, paginator.Total, nil
}

// UpdateFromParams updates specified fields of an existing AllocationConstraint
// The updated fields are assumed to be set to non-null values
// since there are 2 operations (UPDATE, SELECT), in this, it is required that
// this library call happens within a transaction
func (acd AllocationConstraintSQLDAO) UpdateFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID,
	allocationID *uuid.UUID, resourceType *string,
	resourceTypeID *uuid.UUID, constraintType *string,
	constraintValue *int, derivedResourceID *uuid.UUID) (*AllocationConstraint, error) {
	// Create a child span and set the attributes for current request
	ctx, aDAOSpan := acd.tracerSpan.CreateChildInCurrentContext(ctx, "AllocationConstraintDAO.UpdateFromParams")
	if aDAOSpan != nil {
		defer aDAOSpan.End()

		acd.tracerSpan.SetAttribute(aDAOSpan, "id", id.String())
	}

	a := &AllocationConstraint{
		ID: id,
	}

	updatedFields := []string{}

	if allocationID != nil {
		a.AllocationID = *allocationID
		updatedFields = append(updatedFields, "allocation_id")

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "allocation_id", allocationID.String())
		}
	}
	if resourceType != nil {
		if len(strings.TrimSpace(*resourceType)) == 0 {
			return nil, errors.New("resourceType is empty")
		}
		a.ResourceType = *resourceType
		updatedFields = append(updatedFields, "resource_type")

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "resource_type", *resourceType)
		}
	}
	if resourceTypeID != nil {
		a.ResourceTypeID = *resourceTypeID
		updatedFields = append(updatedFields, "resource_type_id")

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "resource_type_id", resourceTypeID.String())
		}
	}
	if constraintType != nil {
		if len(strings.TrimSpace(*constraintType)) == 0 {
			return nil, errors.New("constraintType is empty")
		}
		a.ConstraintType = *constraintType
		updatedFields = append(updatedFields, "constraint_type")

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "constraint_type", *constraintType)
		}
	}
	if constraintValue != nil {
		a.ConstraintValue = *constraintValue
		updatedFields = append(updatedFields, "constraint_value")

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "constraint_value", *constraintValue)
		}
	}
	if derivedResourceID != nil {
		a.DerivedResourceID = derivedResourceID
		updatedFields = append(updatedFields, "derived_resource_id")

		if aDAOSpan != nil {
			acd.tracerSpan.SetAttribute(aDAOSpan, "derived_resource_id", derivedResourceID.String())
		}
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, acd.dbSession).NewUpdate().Model(a).Column(updatedFields...).Where("id = ?", id).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := acd.GetByID(ctx, tx, a.ID, nil)

	if err != nil {
		return nil, err
	}
	return nv, nil
}

// ClearFromParams sets parameters of an existing AllocationConstraint to null values in db
// since there are 2 operations (UPDATE, SELECT), it is required that
// this must be within a transaction
func (acd AllocationConstraintSQLDAO) ClearFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID,
	derivedResourceID bool) (*AllocationConstraint, error) {
	// Create a child span and set the attributes for current request
	ctx, aDAOSpan := acd.tracerSpan.CreateChildInCurrentContext(ctx, "AllocationConstraintDAO.ClearFromParams")
	if aDAOSpan != nil {
		defer aDAOSpan.End()

		acd.tracerSpan.SetAttribute(aDAOSpan, "id", id.String())
	}

	a := &AllocationConstraint{
		ID: id,
	}

	updatedFields := []string{}
	if derivedResourceID {
		a.DerivedResourceID = nil
		updatedFields = append(updatedFields, "derived_resource_id")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, acd.dbSession).NewUpdate().Model(a).Column(updatedFields...).Where("id = ?", id).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := acd.GetByID(ctx, tx, id, []string{"Allocation"})
	if err != nil {
		return nil, err
	}
	return nv, nil
}

// DeleteByID deletes an AllocationConstraint by ID
// error is returned only if there is a db error
// if the object being deleted doesnt exist, error is not returned (idempotent delete)
func (acd AllocationConstraintSQLDAO) DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, aDAOSpan := acd.tracerSpan.CreateChildInCurrentContext(ctx, "AllocationConstraintDAO.DeleteByID")
	if aDAOSpan != nil {
		defer aDAOSpan.End()

		acd.tracerSpan.SetAttribute(aDAOSpan, "id", id.String())
	}

	a := &AllocationConstraint{
		ID: id,
	}

	_, err := db.GetIDB(tx, acd.dbSession).NewDelete().Model(a).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewAllocationConstraintDAO returns a new AllocationConstraintDAO
func NewAllocationConstraintDAO(dbSession *db.Session) AllocationConstraintDAO {
	return &AllocationConstraintSQLDAO{
		dbSession: dbSession,
	}
}
