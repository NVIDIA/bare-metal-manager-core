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
	// OperatingSystemStatusPending status is pending
	OperatingSystemStatusPending = "Pending"
	// OperatingSystemStatusProvisioning status is provisioning
	OperatingSystemStatusProvisioning = "Provisioning"
	// OperatingSystemStatusReady status is ready
	OperatingSystemStatusReady = "Ready"
	// OperatingSystemStatusError status is error
	OperatingSystemStatusError = "Error"
	// OperatingSystemStatusDeleting indicates that the record is being deleted
	OperatingSystemStatusDeleting = "Deleting"
	// OperatingSystemStatusSyncing status is syncing
	OperatingSystemStatusSyncing = "Syncing"
	// OperatingSystemStatusDeactivated status is deactivated
	OperatingSystemStatusDeactivated = "Deactivated"

	// OperatingSystemRelationName is the relation name for the OperatingSystem model
	OperatingSystemRelationName = "OperatingSystem"
	// OperatingSystemTypeIPXE is the ipxe based OperatingSystem type
	OperatingSystemTypeIPXE = "iPXE"
	// OperatingSystemTypeImage is the image based OperatingSystem type
	OperatingSystemTypeImage = "Image"

	// OperatingSystemOrderByDefault default field to be used for ordering when none specified
	OperatingSystemOrderByDefault = "created"

	// OperatingSystemAuthTypeBasic is the basic image auth type
	OperatingSystemAuthTypeBasic = "Basic"
	// OperatingSystemAuthTypeBearer is the bearer image auth type
	OperatingSystemAuthTypeBearer = "Bearer"
)

var (
	// OperatingSystemOrderByFields is a list of valid order by fields for the OperatingSystem model
	OperatingSystemOrderByFields = []string{"name", "version", "status", "is_cloud_init", "created", "updated"}
	// OperatingSystemRelatedEntities is a list of valid relation by fields for the OperatingSystem model
	OperatingSystemRelatedEntities = map[string]bool{
		InfrastructureProviderRelationName: true,
		TenantRelationName:                 true,
	}
	// OperatingSystemStatusMap is a list of valid status for the OperatingSystem model
	OperatingSystemStatusMap = map[string]bool{
		OperatingSystemStatusPending:      true,
		OperatingSystemStatusProvisioning: true,
		OperatingSystemStatusReady:        true,
		OperatingSystemStatusError:        true,
		OperatingSystemStatusDeleting:     true,
		OperatingSystemStatusSyncing:      true,
		OperatingSystemStatusDeactivated:  true,
	}
	//OperatingSystemsTypeMap is a list of valid type for the OperatingSystem model
	OperatingSystemsTypeMap = map[string]bool{
		OperatingSystemTypeIPXE:  true,
		OperatingSystemTypeImage: true,
	}
)

// OperatingSystem describes the attributes of the operating system
// that can be used on instances
type OperatingSystem struct {
	bun.BaseModel `bun:"table:operating_system,alias:os"`

	ID                          uuid.UUID               `bun:"type:uuid,pk"`
	Name                        string                  `bun:"name,notnull"`
	Description                 *string                 `bun:"description"`
	Org                         string                  `bun:"org,notnull"`
	InfrastructureProviderID    *uuid.UUID              `bun:"infrastructure_provider_id,type:uuid"`
	InfrastructureProvider      *InfrastructureProvider `bun:"rel:belongs-to,join:infrastructure_provider_id=id"`
	TenantID                    *uuid.UUID              `bun:"tenant_id,type:uuid"`
	Tenant                      *Tenant                 `bun:"rel:belongs-to,join:tenant_id=id"`
	ControllerOperatingSystemID *uuid.UUID              `bun:"controller_operating_system_id,type:uuid"`
	Version                     *string                 `bun:"version"`
	Type                        string                  `bun:"type,notnull"`
	ImageURL                    *string                 `bun:"image_url"`
	ImageSHA                    *string                 `bun:"image_sha"`
	ImageAuthType               *string                 `bun:"image_auth_type"`
	ImageAuthToken              *string                 `bun:"image_auth_token"`
	ImageDisk                   *string                 `bun:"image_disk"`
	RootFsID                    *string                 `bun:"root_fs_id"`
	RootFsLabel                 *string                 `bun:"root_fs_label"`
	IpxeScript                  *string                 `bun:"ipxe_script"`
	UserData                    *string                 `bun:"user_data"`
	IsCloudInit                 bool                    `bun:"is_cloud_init,notnull"`
	AllowOverride               bool                    `bun:"allow_override,notnull"`
	EnableBlockStorage          bool                    `bun:"enable_block_storage,notnull"`
	PhoneHomeEnabled            bool                    `bun:"phone_home_enabled,notnull"`
	IsActive                    bool                    `bun:"is_active,notnull"`
	DeactivationNote            *string                 `bun:"deactivation_note"` // Note for deactivation, if any
	Status                      string                  `bun:"status,notnull"`
	Created                     time.Time               `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated                     time.Time               `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted                     *time.Time              `bun:"deleted,soft_delete"`
	CreatedBy                   uuid.UUID               `bun:"type:uuid,notnull"`
}

// OperatingSystemCreateInput input parameters for Create method
type OperatingSystemCreateInput struct {
	Name                        string
	Description                 *string
	Org                         string
	InfrastructureProviderID    *uuid.UUID
	TenantID                    *uuid.UUID
	ControllerOperatingSystemID *uuid.UUID
	Version                     *string
	OsType                      string
	ImageURL                    *string
	ImageSHA                    *string
	ImageAuthType               *string
	ImageAuthToken              *string
	ImageDisk                   *string
	RootFsId                    *string
	RootFsLabel                 *string
	IpxeScript                  *string
	UserData                    *string
	IsCloudInit                 bool
	AllowOverride               bool
	EnableBlockStorage          bool
	PhoneHomeEnabled            bool
	Status                      string
	CreatedBy                   uuid.UUID
}

// OperatingSystemUpdateInput input parameters for Update method
type OperatingSystemUpdateInput struct {
	OperatingSystemId           uuid.UUID
	Name                        *string
	Description                 *string
	Org                         *string
	InfrastructureProviderID    *uuid.UUID
	TenantID                    *uuid.UUID
	ControllerOperatingSystemID *uuid.UUID
	Version                     *string
	OsType                      *string
	ImageURL                    *string
	ImageSHA                    *string
	ImageAuthType               *string
	ImageAuthToken              *string
	ImageDisk                   *string
	RootFsId                    *string
	RootFsLabel                 *string
	IpxeScript                  *string
	UserData                    *string
	IsCloudInit                 *bool
	AllowOverride               *bool
	EnableBlockStorage          *bool
	PhoneHomeEnabled            *bool
	IsActive                    *bool
	DeactivationNote            *string
	Status                      *string
}

// OperatingSystemClearInput input parameters for Clear method
type OperatingSystemClearInput struct {
	OperatingSystemId           uuid.UUID
	Description                 bool
	InfrastructureProviderID    bool
	TenantID                    bool
	ControllerOperatingSystemID bool
	Version                     bool
	ImageURL                    bool
	ImageSHA                    bool
	ImageAuthType               bool
	ImageAuthToken              bool
	ImageDisk                   bool
	RootFsId                    bool
	RootFsLabel                 bool
	IpxeScript                  bool
	UserData                    bool
	DeactivationNote            bool
}

type OperatingSystemFilterInput struct {
	InfrastructureProviderID *uuid.UUID
	TenantIDs                []uuid.UUID
	SiteIDs                  []uuid.UUID
	Names                    []string
	Orgs                     []string
	OsTypes                  []string
	Statuses                 []string
	SearchQuery              *string
	OperatingSystemIds       []uuid.UUID
	IsActive                 *bool
}

var _ bun.BeforeAppendModelHook = (*OperatingSystem)(nil)

// BeforeAppendModel is a hook that is called before the model is appended to the query
func (os *OperatingSystem) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		os.Created = db.GetCurTime()
		os.Updated = db.GetCurTime()
	case *bun.UpdateQuery:
		os.Updated = db.GetCurTime()
	}
	return nil
}

var _ bun.BeforeCreateTableHook = (*OperatingSystem)(nil)

// BeforeCreateTable is a hook that is called before the table is created
func (it *OperatingSystem) BeforeCreateTable(ctx context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey(`("infrastructure_provider_id") REFERENCES "infrastructure_provider" ("id")`).
		ForeignKey(`("tenant_id") REFERENCES "tenant" ("id")`)
	return nil
}

// OperatingSystemDAO is an interface for interacting with the OperatingSystem model
type OperatingSystemDAO interface {
	//
	Create(ctx context.Context, tx *db.Tx, input OperatingSystemCreateInput) (*OperatingSystem, error)
	//
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*OperatingSystem, error)
	//
	GetAll(ctx context.Context, tx *db.Tx, filter OperatingSystemFilterInput, page paginator.PageInput, includeRelations []string) ([]OperatingSystem, int, error)
	//
	Update(ctx context.Context, tx *db.Tx, input OperatingSystemUpdateInput) (*OperatingSystem, error)
	//
	Clear(ctx context.Context, tx *db.Tx, input OperatingSystemClearInput) (*OperatingSystem, error)
	//
	Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error
}

// OperatingSystemSQLDAO is an implementation of the OperatingSystemDAO interface
type OperatingSystemSQLDAO struct {
	dbSession *db.Session
	OperatingSystemDAO
	tracerSpan *stracer.TracerSpan
}

// Create creates a new OperatingSystem from the given parameters
// The returned OperatingSystem will not have any related structs (InfrastructureProvider/Site) filled in
// since there are 2 operations (INSERT, SELECT), in this, it is required that
// this library call happens within a transaction
func (ossd OperatingSystemSQLDAO) Create(ctx context.Context, tx *db.Tx, input OperatingSystemCreateInput) (*OperatingSystem, error) {
	// Create a child span and set the attributes for current request
	ctx, operatingSystemSQLDAOSpan := ossd.tracerSpan.CreateChildInCurrentContext(ctx, "OperatingSystemDAO.Create")
	if operatingSystemSQLDAOSpan != nil {
		defer operatingSystemSQLDAOSpan.End()

		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "name", input.Name)
	}

	os := &OperatingSystem{
		ID:                          uuid.New(),
		Name:                        input.Name,
		Description:                 input.Description,
		Org:                         input.Org,
		InfrastructureProviderID:    input.InfrastructureProviderID,
		TenantID:                    input.TenantID,
		ControllerOperatingSystemID: input.ControllerOperatingSystemID,
		Version:                     input.Version,
		Type:                        input.OsType,
		ImageURL:                    input.ImageURL,
		ImageSHA:                    input.ImageSHA,
		ImageAuthType:               input.ImageAuthType,
		ImageAuthToken:              input.ImageAuthToken,
		ImageDisk:                   input.ImageDisk,
		RootFsID:                    input.RootFsId,
		RootFsLabel:                 input.RootFsLabel,
		IpxeScript:                  input.IpxeScript,
		UserData:                    input.UserData,
		IsCloudInit:                 input.IsCloudInit,
		AllowOverride:               input.AllowOverride,
		EnableBlockStorage:          input.EnableBlockStorage,
		PhoneHomeEnabled:            input.PhoneHomeEnabled,
		// WARNING: there is a bug in 'bun' and we cannot use non-nullable AND default=true at this time:
		IsActive:         true, // input.IsActive,
		DeactivationNote: nil,  //input.DeactivationNote,
		Status:           input.Status,
		CreatedBy:        input.CreatedBy,
	}

	_, err := db.GetIDB(tx, ossd.dbSession).NewInsert().Model(os).Exec(ctx)
	if err != nil {
		return nil, err
	}

	nv, err := ossd.GetByID(ctx, tx, os.ID, nil)
	if err != nil {
		return nil, err
	}

	return nv, nil
}

// GetByID returns a OperatingSystem by ID
// Included relations can be a subset of the following: "InfrastructureProvider", "Tenant"
// returns db.ErrDoesNotExist error if the record is not found
func (ossd OperatingSystemSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID, includeRelations []string) (*OperatingSystem, error) {
	// Create a child span and set the attributes for current request
	ctx, operatingSystemSQLDAOSpan := ossd.tracerSpan.CreateChildInCurrentContext(ctx, "OperatingSystemDAO.GetByID")
	if operatingSystemSQLDAOSpan != nil {
		defer operatingSystemSQLDAOSpan.End()

		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "id", id.String())
	}

	it := &OperatingSystem{}

	query := db.GetIDB(tx, ossd.dbSession).NewSelect().Model(it).Where("os.id = ?", id)

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

	return it, nil
}

// GetAll returns all OperatingSystems for an InfrastructureProvider
// Additional optional filters can be specified on name or on siteID
// errors are returned only when there is a db related error
// if records not found, then error is nil, but length of returned slice is 0
// if orderBy is nil, then records are ordered by column specified in OperatingSystemOrderByDefault in ascending order
func (ossd OperatingSystemSQLDAO) GetAll(ctx context.Context, tx *db.Tx, filter OperatingSystemFilterInput, page paginator.PageInput, includeRelations []string) ([]OperatingSystem, int, error) {
	// Create a child span and set the attributes for current request
	ctx, operatingSystemSQLDAOSpan := ossd.tracerSpan.CreateChildInCurrentContext(ctx, "OperatingSystemDAO.GetAll")
	if operatingSystemSQLDAOSpan != nil {
		defer operatingSystemSQLDAOSpan.End()
	}

	oss := []OperatingSystem{}

	if filter.OperatingSystemIds != nil && len(filter.OperatingSystemIds) == 0 {
		return oss, 0, nil
	}

	query := db.GetIDB(tx, ossd.dbSession).NewSelect().Model(&oss)
	if filter.Names != nil {
		query = query.Where("os.name IN (?)", bun.In(filter.Names))
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "name", filter.Names)
	}
	if filter.Orgs != nil {
		query = query.Where("os.org IN (?)", bun.In(filter.Orgs))
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "filter.org", filter.Orgs)
	}
	if filter.InfrastructureProviderID != nil {
		query = query.Where("os.infrastructure_provider_id = ?", *filter.InfrastructureProviderID)
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "infrastructure_provider_id", filter.InfrastructureProviderID.String())
	}
	if filter.TenantIDs != nil {
		query = query.Where("os.tenant_id IN (?)", bun.In(filter.TenantIDs))
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "tenant_id", filter.TenantIDs)
	}
	if filter.OsTypes != nil {
		query = query.Where("os.type IN (?)", bun.In(filter.OsTypes))
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "type", filter.OsTypes)
	}
	if filter.SiteIDs != nil {
		query = query.Join("LEFT JOIN operating_system_site_association as ossa").
			JoinOn("ossa.operating_system_id = os.id").
			JoinOn("ossa.deleted IS NULL").
			Where("ossa.site_id IS NULL OR ossa.site_id IN (?)", bun.In(filter.SiteIDs)).Distinct()
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "site_ids", filter.SiteIDs)
	}
	if filter.OperatingSystemIds != nil {
		query = query.Where("os.id IN (?)", bun.In(filter.OperatingSystemIds))
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "ids", filter.OperatingSystemIds)
	}
	searchQuery, searchTokens, ok := db.NormalizeSearchQuery(filter.SearchQuery)
	if ok {
		query = query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				Where("to_tsvector('english', (coalesce(os.name, ' ') || ' ' || coalesce(os.description, ' ') || ' ' || coalesce(os.status, ' '))) @@ to_tsquery('english', ?)", *searchTokens).
				WhereOr("os.name ILIKE ?", "%"+searchQuery+"%").
				WhereOr("os.description ILIKE ?", "%"+searchQuery+"%").
				WhereOr("os.status ILIKE ?", "%"+searchQuery+"%")
		})
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "search_query", searchQuery)
	}
	if filter.Statuses != nil {
		query = query.Where("os.status IN (?)", bun.In(filter.Statuses))
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "statuses", filter.Statuses)
	}
	if filter.IsActive != nil {
		query = query.Where("os.is_active = ?", *filter.IsActive)
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "is_active", *filter.IsActive)
	}

	for _, relation := range includeRelations {
		query = query.Relation(relation)
	}

	// if no order is passed, set default to make sure objects return always in the same order and pagination works properly
	if page.OrderBy == nil {
		page.OrderBy = paginator.NewDefaultOrderBy(OperatingSystemOrderByDefault)
	}

	paginator, err := paginator.NewPaginator(ctx, query, page.Offset, page.Limit, page.OrderBy, OperatingSystemOrderByFields)
	if err != nil {
		return nil, 0, err
	}

	err = paginator.Query.Limit(paginator.Limit).Offset(paginator.Offset).Scan(ctx)
	if err != nil {
		return nil, 0, err
	}

	return oss, paginator.Total, nil
}

// Update updates specified fields of an existing OperatingSystem
// The updated fields are assumed to be set to non-null values
// For setting to null values, use: Clear
// since there are 2 operations (UPDATE, SELECT), in this, it is required that
// this library call happens within a transaction
func (ossd OperatingSystemSQLDAO) Update(ctx context.Context, tx *db.Tx, input OperatingSystemUpdateInput) (*OperatingSystem, error) {
	// Create a child span and set the attributes for current request
	ctx, operatingSystemSQLDAOSpan := ossd.tracerSpan.CreateChildInCurrentContext(ctx, "OperatingSystemDAO.Update")
	if operatingSystemSQLDAOSpan != nil {
		defer operatingSystemSQLDAOSpan.End()
	}

	it := &OperatingSystem{
		ID: input.OperatingSystemId,
	}

	updatedFields := []string{}

	if input.Name != nil {
		it.Name = *input.Name
		updatedFields = append(updatedFields, "name")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "name", *input.Name)
	}
	if input.Description != nil {
		it.Description = input.Description
		updatedFields = append(updatedFields, "description")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "description", *input.Description)
	}
	if input.Org != nil {
		it.Org = *input.Org
		updatedFields = append(updatedFields, "org")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "org", *input.Org)
	}
	if input.InfrastructureProviderID != nil {
		it.InfrastructureProviderID = input.InfrastructureProviderID
		updatedFields = append(updatedFields, "infrastructure_provider_id")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "infrastructure_provider_id", input.InfrastructureProviderID.String())
	}
	if input.TenantID != nil {
		it.TenantID = input.TenantID
		updatedFields = append(updatedFields, "tenant_id")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "tenant_id", input.TenantID.String())
	}
	if input.ControllerOperatingSystemID != nil {
		it.ControllerOperatingSystemID = input.ControllerOperatingSystemID
		updatedFields = append(updatedFields, "controller_operating_system_id")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "controller_operating_system_id", input.ControllerOperatingSystemID.String())
	}
	if input.Version != nil {
		it.Version = input.Version
		updatedFields = append(updatedFields, "version")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "version", *input.Version)
	}
	if input.OsType != nil {
		it.Type = *input.OsType
		updatedFields = append(updatedFields, "type")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "type", *input.OsType)
	}
	if input.ImageURL != nil {
		it.ImageURL = input.ImageURL
		updatedFields = append(updatedFields, "image_url")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "image_url", *input.ImageURL)
	}
	if input.ImageSHA != nil {
		it.ImageSHA = input.ImageSHA
		updatedFields = append(updatedFields, "image_sha")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "image_sha", *input.ImageSHA)
	}
	if input.ImageAuthType != nil {
		it.ImageAuthType = input.ImageAuthType
		updatedFields = append(updatedFields, "image_auth_type")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "image_auth_type", *input.ImageAuthType)
	}
	if input.ImageAuthToken != nil {
		it.ImageAuthToken = input.ImageAuthToken
		updatedFields = append(updatedFields, "image_auth_token")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "image_auth_token", *input.ImageAuthToken)
	}
	if input.ImageDisk != nil {
		it.ImageDisk = input.ImageDisk
		updatedFields = append(updatedFields, "image_disk")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "image_disk", *input.ImageDisk)
	}
	if input.RootFsId != nil {
		it.RootFsID = input.RootFsId
		updatedFields = append(updatedFields, "root_fs_id")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "root_fs_id", *input.RootFsId)
	}
	if input.RootFsLabel != nil {
		it.RootFsLabel = input.RootFsLabel
		updatedFields = append(updatedFields, "root_fs_label")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "root_fs_label", *input.RootFsLabel)
	}
	if input.IpxeScript != nil {
		it.IpxeScript = input.IpxeScript
		updatedFields = append(updatedFields, "ipxe_script")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "ipxe_script", *input.IpxeScript)
	}
	if input.UserData != nil {
		it.UserData = input.UserData
		updatedFields = append(updatedFields, "user_data")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "user_data", *input.UserData)
	}
	if input.IsCloudInit != nil {
		it.IsCloudInit = *input.IsCloudInit
		updatedFields = append(updatedFields, "is_cloud_init")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "is_cloud_init", *input.IsCloudInit)
	}
	if input.AllowOverride != nil {
		it.AllowOverride = *input.AllowOverride
		updatedFields = append(updatedFields, "allow_override")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "allow_override", *input.AllowOverride)
	}
	if input.EnableBlockStorage != nil {
		it.EnableBlockStorage = *input.EnableBlockStorage
		updatedFields = append(updatedFields, "enable_block_storage")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "enable_block_storage", *input.EnableBlockStorage)
	}
	if input.PhoneHomeEnabled != nil {
		it.PhoneHomeEnabled = *input.PhoneHomeEnabled
		updatedFields = append(updatedFields, "phone_home_enabled")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "phone_home_enabled", *input.PhoneHomeEnabled)
	}
	if input.IsActive != nil {
		it.IsActive = *input.IsActive
		updatedFields = append(updatedFields, "is_active")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "is_active", *input.IsActive)
	}
	if input.DeactivationNote != nil {
		it.DeactivationNote = input.DeactivationNote
		updatedFields = append(updatedFields, "deactivation_note")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "deactivation_note", *input.DeactivationNote)
	}
	if input.Status != nil {
		it.Status = *input.Status
		updatedFields = append(updatedFields, "status")
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "status", *input.Status)
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, ossd.dbSession).NewUpdate().Model(it).Column(updatedFields...).Where("id = ?", input.OperatingSystemId).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := ossd.GetByID(ctx, tx, it.ID, nil)

	if err != nil {
		return nil, err
	}
	return nv, nil
}

// Clear sets parameters of an existing OperatingSystem to null values in db
// parameters when true, the are set to null in db
// since there are 2 operations (UPDATE, SELECT), it is required that
// this must be within a transaction
func (ossd OperatingSystemSQLDAO) Clear(ctx context.Context, tx *db.Tx, input OperatingSystemClearInput) (*OperatingSystem, error) {
	// Create a child span and set the attributes for current request
	ctx, operatingSystemSQLDAOSpan := ossd.tracerSpan.CreateChildInCurrentContext(ctx, "OperatingSystemDAO.Clear")
	if operatingSystemSQLDAOSpan != nil {
		defer operatingSystemSQLDAOSpan.End()
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "id", input.OperatingSystemId.String())
	}

	it := &OperatingSystem{
		ID: input.OperatingSystemId,
	}

	updatedFields := []string{}

	if input.Description {
		it.Description = nil
		updatedFields = append(updatedFields, "description")
	}
	if input.InfrastructureProviderID {
		it.InfrastructureProviderID = nil
		updatedFields = append(updatedFields, "infrastructure_provider_id")
	}
	if input.TenantID {
		it.TenantID = nil
		updatedFields = append(updatedFields, "tenant_id")
	}
	if input.ControllerOperatingSystemID {
		it.ControllerOperatingSystemID = nil
		updatedFields = append(updatedFields, "controller_operating_system_id")
	}
	if input.Version {
		it.Version = nil
		updatedFields = append(updatedFields, "version")
	}
	if input.ImageURL {
		it.ImageURL = nil
		updatedFields = append(updatedFields, "image_url")
	}
	if input.ImageSHA {
		it.ImageSHA = nil
		updatedFields = append(updatedFields, "image_sha")
	}
	if input.ImageAuthType {
		it.ImageAuthType = nil
		updatedFields = append(updatedFields, "image_auth_type")
	}
	if input.ImageAuthToken {
		it.ImageAuthToken = nil
		updatedFields = append(updatedFields, "image_auth_token")
	}
	if input.ImageDisk {
		it.ImageDisk = nil
		updatedFields = append(updatedFields, "image_disk")
	}
	if input.RootFsId {
		it.RootFsID = nil
		updatedFields = append(updatedFields, "root_fs_id")
	}
	if input.RootFsLabel {
		it.RootFsLabel = nil
		updatedFields = append(updatedFields, "root_fs_label")
	}
	if input.IpxeScript {
		it.IpxeScript = nil
		updatedFields = append(updatedFields, "ipxe_script")
	}
	if input.UserData {
		it.UserData = nil
		updatedFields = append(updatedFields, "user_data")
	}
	if input.DeactivationNote {
		it.DeactivationNote = nil
		updatedFields = append(updatedFields, "deactivation_note")
	}

	if len(updatedFields) > 0 {
		updatedFields = append(updatedFields, "updated")

		_, err := db.GetIDB(tx, ossd.dbSession).NewUpdate().Model(it).Column(updatedFields...).Where("id = ?", input.OperatingSystemId).Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	nv, err := ossd.GetByID(ctx, tx, it.ID, nil)
	if err != nil {
		return nil, err
	}
	return nv, nil
}

// Delete deletes an OperatingSystem by ID
// error is returned only if there is a db error
// if the object being deleted doesnt exist, error is not returned (idempotent delete)
func (ossd OperatingSystemSQLDAO) Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	// Create a child span and set the attributes for current request
	ctx, operatingSystemSQLDAOSpan := ossd.tracerSpan.CreateChildInCurrentContext(ctx, "OperatingSystemDAO.Delete")
	if operatingSystemSQLDAOSpan != nil {
		defer operatingSystemSQLDAOSpan.End()
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "id", id.String())
	}

	it := &OperatingSystem{
		ID: id,
	}

	_, err := db.GetIDB(tx, ossd.dbSession).NewDelete().Model(it).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewOperatingSystemDAO returns a new OperatingSystemDAO
func NewOperatingSystemDAO(dbSession *db.Session) OperatingSystemDAO {
	return &OperatingSystemSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}
