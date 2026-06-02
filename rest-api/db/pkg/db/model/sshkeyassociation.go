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
	// SSHKeyAssociationOrderByDefault default field to be used for ordering when none specified
	SSHKeyAssociationOrderByDefault = "created"
)

var (
	// SSHKeyAssociationOrderByFields is a list of valid order by fields for the Instance model
	SSHKeyAssociationOrderByFields = []string{"created", "updated"}

	// SSHKeyAssociationRelatedEntities is a list of valid relation by fields for the SSHKeyAssociation model
	SSHKeyAssociationRelatedEntities = map[string]bool{
		SSHKeyRelationName:      true,
		SSHKeyGroupRelationName: true,
	}
)

// SSHKeyAssociation associates a user ssh key with different entities
type SSHKeyAssociation struct {
	bun.BaseModel `bun:"table:ssh_key_association,alias:ska"`

	ID            uuid.UUID    `bun:"type:uuid,pk"`
	SSHKeyID      uuid.UUID    `bun:"ssh_key_id,type:uuid,notnull"`
	SSHKey        *SSHKey      `bun:"rel:belongs-to,join:ssh_key_id=id"`
	SSHKeyGroupID uuid.UUID    `bun:"sshkey_group_id,type:uuid,notnull"`
	SSHKeyGroup   *SSHKeyGroup `bun:"rel:belongs-to,join:sshkey_group_id=id"`
	Created       time.Time    `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated       time.Time    `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted       *time.Time   `bun:"deleted,soft_delete"`
	CreatedBy     uuid.UUID    `bun:"created_by,type:uuid,notnull"`
}

var _ bun.BeforeAppendModelHook = (*SSHKeyAssociation)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (ska *SSHKeyAssociation) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		ska.Created = db.GetCurTime()
		ska.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		ska.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*SSHKeyAssociation)(nil)

// BeforeCreateTable is a hook that is called before the table is created
func (ska *SSHKeyAssociation) BeforeCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey(`("ssh_key_id") REFERENCES "ssh_key" ("id")`).
		ForeignKey(`("sshkey_group_id") REFERENCES "sshkey_group" ("id")`)
	return nil
}

// SSHKeyAssociationDAO is an interface for interacting with the SSHKeyAssociation model
type SSHKeyAssociationDAO interface {
	//
	CreateFromParams(ctx context.Context, tx *db.Tx, sshKeyID uuid.UUID, sshKeyGroupID uuid.UUID, createdBy uuid.UUID) (*SSHKeyAssociation, error)
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*SSHKeyAssociation, error)
	//
	GetAll(ctx context.Context, tx *db.Tx, sshKeyIDs []uuid.UUID, sshKeyGroupIDs []uuid.UUID, includeRelations []string, offset *int, limit *int, orderBy *paginator.OrderBy) ([]SSHKeyAssociation, int, error)
	//
	UpdateFromParams(ctx context.Context, tx *db.Tx, id uuid.UUID, sshKeyID *uuid.UUID, sshKeyGroupID *uuid.UUID) (*SSHKeyAssociation, error)
	//
	DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// SSHKeyAssociationSQLDAO is an implementation of the SSHKeyAssociationDAO interface
type SSHKeyAssociationSQLDAO struct {
	dbSession *db.Session
	SSHKeyAssociationDAO
	tracerSpan *stracer.TracerSpan
}

// CreateFromParams creates a new SSHKeyAssociation from the given parameters
func (skasd SSHKeyAssociationSQLDAO) CreateFromParams(
	ctx context.Context, tx *db.Tx,
	sshKeyID uuid.UUID,
	sshKeyGroupID uuid.UUID,
	createdBy uuid.UUID,
) (*SSHKeyAssociation, error) {
	// Create a child span and set the attributes for current request
	ctx, sshKeyAssociationDAOSpan := skasd.tracerSpan.CreateChildInCurrentContext(ctx, "SSHKeyAssociationDAO.CreateFromParams")
	if sshKeyAssociationDAOSpan != nil {
		defer sshKeyAssociationDAOSpan.End()
	}

	ska := &SSHKeyAssociation{
		ID:            uuid.New(),
		SSHKeyID:      sshKeyID,
		SSHKeyGroupID: sshKeyGroupID,
		CreatedBy:     createdBy,
	}

	_, err := db.GetIDB(tx, skasd.dbSession).NewInsert().Model(ska).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nv, err := skasd.GetByID(ctx, tx, ska.ID, nil)
	if err != nil {
		return nil, err
	}

	return nv, nil
}

// GetByID returns a SSHKeyAssociation by ID
// returns db.ErrDoesNotExist error if the record is not found
func (skasd SSHKeyAssociationSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*SSHKeyAssociation, error) {
	// Create a child span and set the attributes for current request
	ctx, sshKeyAssociationDAOSpan := skasd.tracerSpan.CreateChildInCurrentContext(ctx, "SSHKeyAssociationDAO.GetByID")
	if sshKeyAssociationDAOSpan != nil {
		defer sshKeyAssociationDAOSpan.End()

		skasd.tracerSpan.SetAttribute(sshKeyAssociationDAOSpan, "id", id.String())
	}

	ska := &SSHKeyAssociation{}

	query := db.GetIDB(tx, skasd.dbSession).NewSelect().Model(ska).Where("ska.id = ?", id)

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

	return ska, nil
}

// GetAll returns all SSHKeyAssociations with various optional filters
// errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
// if orderBy is nil, then records are ordered by column specified in SSHKeyAssociationOrderByDefault in ascending order
func (skasd SSHKeyAssociationSQLDAO) GetAll(ctx context.Context, tx *db.Tx, sshKeyIDs []uuid.UUID, sshKeyGroupIDs []uuid.UUID, includeRelations []string, offset *int, limit *int, orderBy *paginator.OrderBy) ([]SSHKeyAssociation, int, error) {
	// Create a child span and set the attributes for current request
	ctx, sshKeyAssociationDAOSpan := skasd.tracerSpan.CreateChildInCurrentContext(ctx, "SSHKeyAssociationDAO.GetAll")
	if sshKeyAssociationDAOSpan != nil {
		defer sshKeyAssociationDAOSpan.End()
	}

	skas := []SSHKeyAssociation{}

	query := db.GetIDB(tx, skasd.dbSession).NewSelect().Model(&skas)
	if sshKeyIDs != nil {
		query = query.Where("ska.ssh_key_id IN (?)", bun.In(sshKeyIDs))
		skasd.tracerSpan.SetAttribute(sshKeyAssociationDAOSpan, "ssh_key_id", sshKeyIDs)
	}

	if sshKeyGroupIDs != nil {
		query = query.Where("ska.sshkey_group_id IN (?)", bun.In(sshKeyGroupIDs))
		skasd.tracerSpan.SetAttribute(sshKeyAssociationDAOSpan, "sshkey_group_id", sshKeyGroupIDs)
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// if no order is passed, set default to make sure objects return always in the same order and pagination works properly
	if orderBy == nil {
		orderBy = paginator.NewDefaultOrderBy(SSHKeyAssociationOrderByDefault)
	}

	paginator, err := paginator.NewPaginator(ctx, query, offset, limit, orderBy, SSHKeyAssociationOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = paginator.Query.Limit(paginator.Limit).Offset(paginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return skas, paginator.Total, nil
}

// UpdateFromParams updates specified fields of an existing SSHKeyAssociation
func (skasd SSHKeyAssociationSQLDAO) UpdateFromParams(
	ctx context.Context, tx *db.Tx,
	id uuid.UUID,
	sshKeyID *uuid.UUID,
	sshKeyGroupID *uuid.UUID,
) (*SSHKeyAssociation, error) {
	// Create a child span and set the attributes for current request
	ctx, sshKeyAssociationDAOSpan := skasd.tracerSpan.CreateChildInCurrentContext(ctx, "SSHKeyAssociationDAO.UpdateFromParams")
	if sshKeyAssociationDAOSpan != nil {
		defer sshKeyAssociationDAOSpan.End()
		skasd.tracerSpan.SetAttribute(sshKeyAssociationDAOSpan, "id", id.String())
	}

	ska := &SSHKeyAssociation{
		ID: id,
	}

	updatedFields := []string{}

	if sshKeyID != nil {
		ska.SSHKeyID = *sshKeyID
		updatedFields = append(updatedFields, "ssh_key_id")
		skasd.tracerSpan.SetAttribute(sshKeyAssociationDAOSpan, "ssh_key_id", sshKeyID.String())
	}
	if sshKeyGroupID != nil {
		ska.SSHKeyGroupID = *sshKeyGroupID
		updatedFields = append(updatedFields, "sshkey_group_id")
		skasd.tracerSpan.SetAttribute(sshKeyAssociationDAOSpan, "sshkey_group_id", sshKeyGroupID.String())
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, skasd.dbSession).NewUpdate().Model(ska).Column(updatedFields...).Where("ska.id = ?", id).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := skasd.GetByID(ctx, tx, ska.ID, nil)

	if err != nil {
		return nil, err
	}
	return nv, nil
}

// DeleteByID deletes an SSHKeyAssociation by ID
// error is returned only if there is a db error
// if the object being deleted doesnt exist, error is not returned
func (skasd SSHKeyAssociationSQLDAO) DeleteByID(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, sshKeyAssociationDAOSpan := skasd.tracerSpan.CreateChildInCurrentContext(ctx, "SSHKeyAssociationDAO.DeleteByID")
	if sshKeyAssociationDAOSpan != nil {
		defer sshKeyAssociationDAOSpan.End()
		skasd.tracerSpan.SetAttribute(sshKeyAssociationDAOSpan, "id", id.String())
	}

	it := &SSHKeyAssociation{
		ID: id,
	}

	_, err := db.GetIDB(tx, skasd.dbSession).NewDelete().Model(it).Where("ska.id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewSSHKeyAssociationDAO returns a new SSHKeyAssociationDAO
func NewSSHKeyAssociationDAO(dbSession *db.Session) SSHKeyAssociationDAO {
	return &SSHKeyAssociationSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
