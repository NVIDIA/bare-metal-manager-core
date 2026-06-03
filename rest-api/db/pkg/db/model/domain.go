// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/google/uuid"

	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	"github.com/uptrace/bun"
)

const (
	// DomainStatusPending status is pending
	DomainStatusPending = "DomainStatusPending"
	// DomainStatusRegistering status is registering
	DomainStatusRegistering = "DomainStatusRegistering"
	// DomainStatusReady status is ready
	DomainStatusReady = "DomainStatusReady"
	// DomainStatusError status is error
	DomainStatusError = "DomainStatusError"
	// DomainRelationName is the relation name for the Domain model
	DomainRelationName = "Domain"
)

var (
	// DomainStatusMap is a list of valid status for the Domain model
	DomainStatusMap = map[string]bool{
		DomainStatusPending:     true,
		DomainStatusReady:       true,
		DomainStatusError:       true,
		DomainStatusRegistering: true,
	}
)

// Domain contains information about the fully qualified domain
// name for determining machine hostnames
type Domain struct {
	bun.BaseModel `bun:"table:domain,alias:d"`

	ID                 uuid.UUID  `bun:"type:uuid,pk"`
	Hostname           string     `bun:"hostname,notnull"`
	Org                string     `bun:"org,notnull"`
	ControllerDomainID *uuid.UUID `bun:"controller_domain_id,type:uuid"`
	Status             string     `bun:"status,notnull"`
	Created            time.Time  `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated            time.Time  `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted            *time.Time `bun:"deleted,soft_delete"`
	CreatedBy          uuid.UUID  `bun:"type:uuid,notnull"`
}

var _ bun.BeforeAppendModelHook = (*Domain)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (d *Domain) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		d.Created = db.GetCurTime()
		d.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		d.Updated = db.GetCurTime()
	}
	return nil
}

// DomainDAO is an interface for interacting with the Domain model
type DomainDAO interface {
	//
	CreateFromParams(ctx context.Context, tx *db.Tx, hostname string, org string, controllerDomainID *uuid.UUID, status string, createdBy uuid.UUID) (*Domain, error)
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*Domain, error)
	//
	GetAll(ctx context.Context, tx *db.Tx, hostname, org *string, controllerDomainID *uuid.UUID, status *string, includeRelations []string) ([]Domain, error)
	//
	UpdateFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID, hostname *string, org *string, controllerDomainID *uuid.UUID, status *string) (*Domain, error)
	//
	ClearFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID, controllerDomainID bool) (*Domain, error)
	//
	DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// DomainSQLDAO is an implementation of the DomainDAO interface
type DomainSQLDAO struct {
	dbSession *db.Session
	DomainDAO
	tracerSpan *stracer.TracerSpan
}

// CreateFromParams creates a new Domain from the given parameters
// since there are 2 operations (INSERT, SELECT), in this, it is required that
// this library call happens within a transaction
func (dsd DomainSQLDAO) CreateFromParams(
	ctx context.Context, tx *db.Tx,
	hostname string,
	org string,
	controllerDomainID *uuid.UUID,
	status string, createdBy uuid.UUID) (*Domain, error) {
	// Create a child span and set the attributes for current request
	ctx, domainDAOSpan := dsd.tracerSpan.CreateChildInCurrentContext(ctx, "DomainDAO.CreateFromParams")
	if domainDAOSpan != nil {
		defer domainDAOSpan.End()
	}

	d := &Domain{
		ID:                 uuid.New(),
		Hostname:           hostname,
		Org:                org,
		ControllerDomainID: controllerDomainID,
		Status:             status,
		CreatedBy:          createdBy,
	}

	_, err := db.GetIDB(tx, dsd.dbSession).NewInsert().Model(d).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nv, err := dsd.GetByID(ctx, tx, d.ID, nil)
	if err != nil {
		return nil, err
	}

	return nv, nil
}

// GetByID returns a Domain by ID
// currently returns error if the record is not found or if there is any db error
// TBD: to distinguish not found from db related errors to help application logic to be precise
func (dsd DomainSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*Domain, error) {
	// Create a child span and set the attributes for current request
	ctx, domainDAOSpan := dsd.tracerSpan.CreateChildInCurrentContext(ctx, "DomainDAO.GetByID")
	if domainDAOSpan != nil {
		defer domainDAOSpan.End()

		dsd.tracerSpan.SetAttribute(domainDAOSpan, "domain_id", id.String())
	}

	d := &Domain{}

	query := db.GetIDB(tx, dsd.dbSession).NewSelect().Model(d).Where("d.id = ?", id)

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

	return d, nil
}

// GetAll returns all Domains
// Optional filters can be specified on hostname, org, controllerDomainID
// errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
func (dsd DomainSQLDAO) GetAll(ctx context.Context, tx *db.Tx, hostname, org *string, controllerDomainID *uuid.UUID, status *string, includeRelations []string) ([]Domain, error) {
	// Create a child span and set the attributes for current request
	ctx, domainDAOSpan := dsd.tracerSpan.CreateChildInCurrentContext(ctx, "DomainDAO.GetAll")
	if domainDAOSpan != nil {
		defer domainDAOSpan.End()
	}

	d := []Domain{}

	query := db.GetIDB(tx, dsd.dbSession).NewSelect().Model(&d)

	if hostname != nil {
		query = query.Where("d.hostname = ?", *hostname)

		if domainDAOSpan != nil {
			dsd.tracerSpan.SetAttribute(domainDAOSpan, "hostname", *hostname)
		}
	}
	if org != nil {
		query = query.Where("d.org = ?", *org)

		if domainDAOSpan != nil {
			dsd.tracerSpan.SetAttribute(domainDAOSpan, "org", *org)
		}
	}
	if controllerDomainID != nil {
		query = query.Where("d.controller_domain_id = ?", *controllerDomainID)

		if domainDAOSpan != nil {
			dsd.tracerSpan.SetAttribute(domainDAOSpan, "controller_domain_id", controllerDomainID.String())
		}
	}
	if status != nil {
		query = query.Where("d.status = ?", *status)

		if domainDAOSpan != nil {
			dsd.tracerSpan.SetAttribute(domainDAOSpan, "status", *status)
		}
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	err := query.Scan(ctx)

	if err != nil {
		return nil, err
	}

	return d, nil
}

// UpdateFromParams updates specified fields of an existing Domain
// The updated fields are assumed to be set to non-null values
// For setting to null values, use: ClearFromParams
// since there are 2 operations (UPDATE, SELECT), in this, it is required that
// this library call happens within a transaction
func (dsd DomainSQLDAO) UpdateFromParams(
	ctx context.Context, tx *db.Tx,
	id uuid.UUID,
	hostname *string,
	org *string,
	controllerDomainID *uuid.UUID,
	status *string) (*Domain, error) {
	d := &Domain{
		ID: id,
	}
	// Create a child span and set the attributes for current request
	ctx, domainDAOSpan := dsd.tracerSpan.CreateChildInCurrentContext(ctx, "DomainDAO.UpdateFromParams")
	if domainDAOSpan != nil {
		defer domainDAOSpan.End()
	}

	updatedFields := []string{}

	if hostname != nil {
		d.Hostname = *hostname
		updatedFields = append(updatedFields, "hostname")

		if domainDAOSpan != nil {
			dsd.tracerSpan.SetAttribute(domainDAOSpan, "hostname", *hostname)
		}
	}
	if org != nil {
		d.Org = *org
		updatedFields = append(updatedFields, "org")

		if domainDAOSpan != nil {
			dsd.tracerSpan.SetAttribute(domainDAOSpan, "org", *org)
		}
	}
	if controllerDomainID != nil {
		d.ControllerDomainID = controllerDomainID
		updatedFields = append(updatedFields, "controller_domain_id")

		if domainDAOSpan != nil {
			dsd.tracerSpan.SetAttribute(domainDAOSpan, "controller_domain_id", controllerDomainID.String())
		}
	}
	if status != nil {
		d.Status = *status
		updatedFields = append(updatedFields, "status")

		if domainDAOSpan != nil {
			dsd.tracerSpan.SetAttribute(domainDAOSpan, "status", *status)
		}
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, dsd.dbSession).NewUpdate().Model(d).Column(updatedFields...).Where("id = ?", id).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := dsd.GetByID(ctx, tx, d.ID, nil)
	if err != nil {
		return nil, err
	}
	return nv, nil
}

// ClearFromParams sets parameters of an existing Domain to null values in db
// parameter controllerDomainID when true, the are set to null in db
// since there are 2 operations (UPDATE, SELECT), it is required that
// this must be within a transaction
func (dsd DomainSQLDAO) ClearFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID, controllerDomainID bool) (*Domain, error) {
	// Create a child span and set the attributes for current request
	ctx, domainDAOSpan := dsd.tracerSpan.CreateChildInCurrentContext(ctx, "DomainDAO.ClearFromParams")
	if domainDAOSpan != nil {
		defer domainDAOSpan.End()
	}

	d := &Domain{
		ID: id,
	}

	updatedFields := []string{}

	if controllerDomainID {
		d.ControllerDomainID = nil
		updatedFields = append(updatedFields, "controller_domain_id")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, dsd.dbSession).NewUpdate().Model(d).Column(updatedFields...).Where("id = ?", id).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := dsd.GetByID(ctx, tx, d.ID, nil)
	if err != nil {
		return nil, err
	}
	return nv, nil
}

// DeleteByID deletes an Domain by ID
// error is returned only if there is a db error
// if the object being deleted doesnt exist, error is not returned (idempotent delete)
func (dsd DomainSQLDAO) DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, domainDAOSpan := dsd.tracerSpan.CreateChildInCurrentContext(ctx, "DomainDAO.DeleteByID")
	if domainDAOSpan != nil {
		defer domainDAOSpan.End()
	}

	d := &Domain{
		ID: id,
	}

	_, err := db.GetIDB(tx, dsd.dbSession).NewDelete().Model(d).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewDomainDAO returns a new DomainDAO
func NewDomainDAO(dbSession *db.Session) DomainDAO {
	return &DomainSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
