// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"

	"github.com/uptrace/bun"

	stracer "github.com/NVIDIA/infra-controller/rest-api/db/pkg/tracer"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
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
	// OperatingSystemTypeIPXE is the raw iPXE script based OperatingSystem type
	OperatingSystemTypeIPXE = "iPXE"
	// OperatingSystemTypeTemplatedIPXE is the iPXE template based OperatingSystem type
	OperatingSystemTypeTemplatedIPXE = "Templated iPXE"
	// OperatingSystemTypeImage is the image based OperatingSystem type
	OperatingSystemTypeImage = "Image"

	// OperatingSystemScopeLocal means single site, bidirectional sync (provider-owned OS from nico-core).
	OperatingSystemScopeLocal = "Local"
	// OperatingSystemScopeLimited means carbide-rest is the source of truth for a fixed list of sites.
	OperatingSystemScopeLimited = "Limited"
	// OperatingSystemScopeGlobal means carbide-rest is the source of truth for all owner sites.
	OperatingSystemScopeGlobal = "Global"

	// OperatingSystemOrderByDefault default field to be used for ordering when none specified
	OperatingSystemOrderByDefault = "created"

	// OperatingSystemAuthTypeBasic is the basic image auth type
	OperatingSystemAuthTypeBasic = "Basic"
	// OperatingSystemAuthTypeBearer is the bearer image auth type
	OperatingSystemAuthTypeBearer = "Bearer"

	// OperatingSystemIpxeArtifactCacheStrategyCacheAsNeeded caches the artifact locally when possible.
	OperatingSystemIpxeArtifactCacheStrategyCacheAsNeeded = "CacheAsNeeded"
	// OperatingSystemIpxeArtifactCacheStrategyLocalOnly marks the artifact URL as usable only on-site.
	OperatingSystemIpxeArtifactCacheStrategyLocalOnly = "LocalOnly"
	// OperatingSystemIpxeArtifactCacheStrategyCachedOnly requires the artifact to be cached locally.
	OperatingSystemIpxeArtifactCacheStrategyCachedOnly = "CachedOnly"
	// OperatingSystemIpxeArtifactCacheStrategyRemoteOnly always fetches the artifact from the remote URL.
	OperatingSystemIpxeArtifactCacheStrategyRemoteOnly = "RemoteOnly"
)

var (
	// OperatingSystemOrderByFields is a list of valid order by fields for the OperatingSystem model
	OperatingSystemOrderByFields = []string{"name", "version", "status", "created", "updated"}
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
		OperatingSystemTypeIPXE:          true,
		OperatingSystemTypeTemplatedIPXE: true,
		OperatingSystemTypeImage:         true,
	}

	// OperatingSystemIpxeArtifactCacheStrategyFromProtoMap maps proto cache strategies to their model string values.
	OperatingSystemIpxeArtifactCacheStrategyFromProtoMap = map[corev1.IpxeTemplateArtifactCacheStrategy]string{
		corev1.IpxeTemplateArtifactCacheStrategy_CACHE_AS_NEEDED: OperatingSystemIpxeArtifactCacheStrategyCacheAsNeeded,
		corev1.IpxeTemplateArtifactCacheStrategy_LOCAL_ONLY:      OperatingSystemIpxeArtifactCacheStrategyLocalOnly,
		corev1.IpxeTemplateArtifactCacheStrategy_CACHED_ONLY:     OperatingSystemIpxeArtifactCacheStrategyCachedOnly,
		corev1.IpxeTemplateArtifactCacheStrategy_REMOTE_ONLY:     OperatingSystemIpxeArtifactCacheStrategyRemoteOnly,
	}

	// OperatingSystemIpxeArtifactCacheStrategyToProtoMap maps model cache strategy strings to their proto values.
	OperatingSystemIpxeArtifactCacheStrategyToProtoMap = map[string]corev1.IpxeTemplateArtifactCacheStrategy{
		OperatingSystemIpxeArtifactCacheStrategyCacheAsNeeded: corev1.IpxeTemplateArtifactCacheStrategy_CACHE_AS_NEEDED,
		OperatingSystemIpxeArtifactCacheStrategyLocalOnly:     corev1.IpxeTemplateArtifactCacheStrategy_LOCAL_ONLY,
		OperatingSystemIpxeArtifactCacheStrategyCachedOnly:    corev1.IpxeTemplateArtifactCacheStrategy_CACHED_ONLY,
		OperatingSystemIpxeArtifactCacheStrategyRemoteOnly:    corev1.IpxeTemplateArtifactCacheStrategy_REMOTE_ONLY,
	}

	// OperatingSystemTypeFromProtoMap maps nico-core OS types to their model string values.
	OperatingSystemTypeFromProtoMap = map[corev1.OperatingSystemType]string{
		corev1.OperatingSystemType_OS_TYPE_IPXE:           OperatingSystemTypeIPXE,
		corev1.OperatingSystemType_OS_TYPE_TEMPLATED_IPXE: OperatingSystemTypeTemplatedIPXE,
	}

	// OperatingSystemStatusFromProtoMap maps nico-core tenant states to OperatingSystem status values.
	OperatingSystemStatusFromProtoMap = map[corev1.TenantState]string{
		corev1.TenantState_PROVISIONING: OperatingSystemStatusProvisioning,
		corev1.TenantState_READY:        OperatingSystemStatusReady,
		corev1.TenantState_CONFIGURING:  OperatingSystemStatusSyncing,
		corev1.TenantState_TERMINATING:  OperatingSystemStatusDeleting,
		corev1.TenantState_FAILED:       OperatingSystemStatusError,
	}
)

// IsIPXEType returns true if the given OS type is any iPXE variant (raw script or templated).
func IsIPXEType(osType string) bool {
	return osType == OperatingSystemTypeIPXE || osType == OperatingSystemTypeTemplatedIPXE
}

// OperatingSystemIpxeParameter holds a single iPXE parameter name/value pair (stored as JSONB).
// These are only populated for iPXE-based OS definitions synced with nico-core.
type OperatingSystemIpxeParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// FromProto fills the receiver from a proto IpxeTemplateParameter. A nil proto resets the receiver.
func (osip *OperatingSystemIpxeParameter) FromProto(protoParam *corev1.IpxeTemplateParameter) {
	if protoParam == nil {
		*osip = OperatingSystemIpxeParameter{}
		return
	}
	osip.Name = protoParam.Name
	osip.Value = protoParam.Value
}

// ToProto converts the receiver to a proto IpxeTemplateParameter.
func (osip *OperatingSystemIpxeParameter) ToProto() *corev1.IpxeTemplateParameter {
	return &corev1.IpxeTemplateParameter{
		Name:  osip.Name,
		Value: osip.Value,
	}
}

// OperatingSystemIpxeArtifact holds a single iPXE artifact descriptor (stored as JSONB).
// These are only populated for iPXE-based OS definitions synced with nico-core.
//
// The proto IpxeTemplateArtifact has a cached_url field that is intentionally NOT
// represented here: cached_url is a per-site value populated by nico-core after a
// successful download, so there is no meaningful global value for it on the rest side.
// The push path must therefore never emit cached_url to core (preserving per-site
// values), and the inbound (pull) path must never store cached_url on the global row.
type OperatingSystemIpxeArtifact struct {
	Name          string  `json:"name"`
	URL           string  `json:"url"`
	SHA           *string `json:"sha"`
	AuthType      *string `json:"authType"`
	AuthToken     *string `json:"authToken"`
	CacheStrategy string  `json:"cacheStrategy"`
}

// FromProto fills the receiver from a proto IpxeTemplateArtifact. A nil proto resets the receiver.
// The proto's cached_url field is intentionally ignored; see the type doc.
func (osia *OperatingSystemIpxeArtifact) FromProto(protoArtifact *corev1.IpxeTemplateArtifact) {
	if protoArtifact == nil {
		*osia = OperatingSystemIpxeArtifact{}
		return
	}
	osia.Name = protoArtifact.Name
	osia.URL = protoArtifact.Url
	osia.SHA = protoArtifact.Sha
	osia.AuthType = protoArtifact.AuthType
	osia.AuthToken = protoArtifact.AuthToken

	cacheStrategy := OperatingSystemIpxeArtifactCacheStrategyFromProtoMap[protoArtifact.CacheStrategy]
	if cacheStrategy == "" {
		cacheStrategy = OperatingSystemIpxeArtifactCacheStrategyCacheAsNeeded
	}
	osia.CacheStrategy = cacheStrategy
}

// ToProto converts the receiver to a proto IpxeTemplateArtifact. cached_url is always left
// nil so the rest side never overwrites the per-site value managed by nico-core.
func (osia *OperatingSystemIpxeArtifact) ToProto() *corev1.IpxeTemplateArtifact {
	return &corev1.IpxeTemplateArtifact{
		Name:          osia.Name,
		Url:           osia.URL,
		Sha:           osia.SHA,
		AuthType:      osia.AuthType,
		AuthToken:     osia.AuthToken,
		CacheStrategy: OperatingSystemIpxeArtifactCacheStrategyToProtoMap[osia.CacheStrategy],
		CachedUrl:     nil,
	}
}

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
	// iPXE template fields, populated for Templated iPXE OS definitions synced with nico-core.
	IpxeTemplateId             *string                        `bun:"ipxe_template_id"`
	IpxeTemplateParameters     []OperatingSystemIpxeParameter `bun:"ipxe_template_parameters,type:jsonb"`
	IpxeTemplateArtifacts      []OperatingSystemIpxeArtifact  `bun:"ipxe_template_artifacts,type:jsonb"`
	IpxeTemplateDefinitionHash *string                        `bun:"ipxe_template_definition_hash"`
	// IpxeOsScope controls synchronization direction between carbide-rest and nico-core for
	// iPXE OS definitions: "Local" is bidirectional/provider-owned from nico-core, while
	// "Global" and "Limited" make carbide-rest the source of truth. nil for Image-type OS;
	// legacy iPXE rows with nil scope are treated as "Local".
	IpxeOsScope        *string    `bun:"ipxe_os_scope"`
	UserData           *string    `bun:"user_data"`
	AllowOverride      bool       `bun:"allow_override,notnull"`
	EnableBlockStorage bool       `bun:"enable_block_storage,notnull"`
	PhoneHomeEnabled   bool       `bun:"phone_home_enabled,notnull"`
	IsActive           bool       `bun:"is_active,notnull"`
	DeactivationNote   *string    `bun:"deactivation_note"` // Note for deactivation, if any
	Status             string     `bun:"status,notnull"`
	Created            time.Time  `bun:"created,nullzero,notnull,default:current_timestamp"`
	Updated            time.Time  `bun:"updated,nullzero,notnull,default:current_timestamp"`
	Deleted            *time.Time `bun:"deleted,soft_delete"`
	CreatedBy          uuid.UUID  `bun:"type:uuid,notnull"`
}

// GetSiteID returns the OperatingSystem ID to use when communicating
// with the Site: ControllerOperatingSystemID when present, otherwise
// the OS's own ID. The Site treats both as opaque identifiers.
func (os *OperatingSystem) GetSiteID() *uuid.UUID {
	if os.ControllerOperatingSystemID != nil {
		return os.ControllerOperatingSystemID
	}
	return &os.ID
}

// ToImageAttributesProto builds the OsImageAttributes proto used by
// both the create and update workflows. tenantOrg is the owning
// tenant's organization id (not stored on the entity directly).
//
// The same proto shape is sent for both create and update flows, so
// this entity-level method is the canonical entity-to-proto for OS
// image data; the request-shape ToProto methods on
// APIOperatingSystemCreateRequest and APIOperatingSystemUpdateRequest
// layer on top of it without altering the wire fields.
//
// Per the proto-conversion convention, the method trusts the caller:
// the request must have been Validated and the handler must have
// performed the cross-context check that the OS is image-typed (the
// dereferences below assume ImageURL and ImageSHA are non-nil, which
// holds for image-typed records after validation).
func (os *OperatingSystem) ToImageAttributesProto(tenantOrg string) *corev1.OsImageAttributes {
	return &corev1.OsImageAttributes{
		Id:                   &corev1.UUID{Value: os.GetSiteID().String()},
		Name:                 &os.Name,
		TenantOrganizationId: tenantOrg,
		Description:          os.Description,
		SourceUrl:            *os.ImageURL,
		Digest:               *os.ImageSHA,
		CreateVolume:         os.EnableBlockStorage,
		AuthType:             os.ImageAuthType,
		AuthToken:            os.ImageAuthToken,
		RootfsId:             os.RootFsID,
		RootfsLabel:          os.RootFsLabel,
	}
}

// ToDeletionRequestProto builds the workflow request that asks a Site
// to delete this OS image.
func (os *OperatingSystem) ToDeletionRequestProto(tenantOrg string) *corev1.DeleteOsImageRequest {
	return &corev1.DeleteOsImageRequest{
		Id:                   &corev1.UUID{Value: os.GetSiteID().String()},
		TenantOrganizationId: tenantOrg,
	}
}

// OperatingSystemCreateInput input parameters for Create method
type OperatingSystemCreateInput struct {
	// ID optionally pre-specifies the primary key. When set (e.g. during inventory sync from
	// nico-core), the same UUID is used on both sides. When zero, a new UUID is generated.
	ID                          uuid.UUID
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
	// iPXE template definition fields (for nico-core synced iPXE OS definitions)
	IpxeTemplateId         *string
	IpxeTemplateParameters []OperatingSystemIpxeParameter
	IpxeTemplateArtifacts  []OperatingSystemIpxeArtifact
	IpxeOSHash             *string
	IpxeOsScope            *string
	UserData               *string
	AllowOverride          bool
	EnableBlockStorage     bool
	PhoneHomeEnabled       bool
	Status                 string
	CreatedBy              uuid.UUID
}

// FromProto fills the proto-derived definition fields of the receiver from a
// nico-core OperatingSystem proto: OS type, status, scalar flags, iPXE script /
// template reference, template parameters, artifacts and definition hash.
//
// Ownership and sync-context fields (ID, Org, InfrastructureProviderID, TenantID,
// IpxeOsScope, CreatedBy and the image-* fields) are not carried on this proto and
// must be set by the caller after calling FromProto. A nil proto is a no-op.
func (in *OperatingSystemCreateInput) FromProto(protoOS *corev1.OperatingSystem) {
	if protoOS == nil {
		return
	}

	in.Name = protoOS.Name
	in.Description = protoOS.Description
	in.UserData = protoOS.UserData
	in.IpxeScript = protoOS.IpxeScript
	in.AllowOverride = protoOS.AllowOverride
	in.PhoneHomeEnabled = protoOS.PhoneHomeEnabled
	in.IpxeOSHash = protoOS.IpxeTemplateDefinitionHash

	in.OsType = OperatingSystemTypeFromProtoMap[protoOS.Type]

	status := OperatingSystemStatusFromProtoMap[protoOS.Status]
	if status == "" {
		status = OperatingSystemStatusSyncing
	}
	in.Status = status

	// Only persist a template reference when non-empty; non-templated OS types
	// carry no template.
	if v := protoOS.GetIpxeTemplateId().GetValue(); v != "" {
		in.IpxeTemplateId = &v
	}

	in.IpxeTemplateParameters = make([]OperatingSystemIpxeParameter, 0, len(protoOS.IpxeTemplateParameters))
	for _, p := range protoOS.IpxeTemplateParameters {
		var param OperatingSystemIpxeParameter
		param.FromProto(p)
		in.IpxeTemplateParameters = append(in.IpxeTemplateParameters, param)
	}

	in.IpxeTemplateArtifacts = make([]OperatingSystemIpxeArtifact, 0, len(protoOS.IpxeTemplateArtifacts))
	for _, a := range protoOS.IpxeTemplateArtifacts {
		var artifact OperatingSystemIpxeArtifact
		artifact.FromProto(a)
		in.IpxeTemplateArtifacts = append(in.IpxeTemplateArtifacts, artifact)
	}
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
	// iPXE template definition fields (for nico-core synced iPXE OS definitions)
	IpxeTemplateId         *string
	IpxeTemplateParameters *[]OperatingSystemIpxeParameter
	IpxeTemplateArtifacts  *[]OperatingSystemIpxeArtifact
	IpxeOSHash             *string
	Scope                  *string
	UserData               *string
	AllowOverride          *bool
	EnableBlockStorage     *bool
	PhoneHomeEnabled       *bool
	IsActive               *bool
	DeactivationNote       *string
	Status                 *string
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
	// iPXE template definition fields (for nico-core synced iPXE OS definitions)
	IpxeTemplateId         bool
	IpxeTemplateParameters bool
	IpxeTemplateArtifacts  bool
	IpxeOSHash             bool
	Scope                  bool
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
	// Scopes filters iPXE OS definitions by their scope (e.g. "Global", "Limited", "Local").
	Scopes []string
	// IncludeDeleted includes soft-deleted records (used by inventory sync to detect deletions).
	IncludeDeleted bool
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

	id := input.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	os := &OperatingSystem{
		ID:                          id,
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
		AllowOverride:               input.AllowOverride,
		EnableBlockStorage:          input.EnableBlockStorage,
		PhoneHomeEnabled:            input.PhoneHomeEnabled,
		// WARNING: there is a bug in 'bun' and we cannot use non-nullable AND default=true at this time:
		IsActive:                   true, // input.IsActive,
		DeactivationNote:           nil,  //input.DeactivationNote,
		Status:                     input.Status,
		CreatedBy:                  input.CreatedBy,
		IpxeTemplateId:             input.IpxeTemplateId,
		IpxeTemplateParameters:     input.IpxeTemplateParameters,
		IpxeTemplateArtifacts:      input.IpxeTemplateArtifacts,
		IpxeTemplateDefinitionHash: input.IpxeOSHash,
		IpxeOsScope:                input.IpxeOsScope,
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
	if filter.Scopes != nil {
		// Scope only applies to iPXE OS rows; restrict the match to iPXE types so Image rows
		// (which have a NULL scope) are not coerced to "Local" by the COALESCE.
		query = query.Where(
			"os.type IN (?) AND COALESCE(os.ipxe_os_scope, ?) IN (?)",
			bun.In([]string{OperatingSystemTypeIPXE, OperatingSystemTypeTemplatedIPXE}),
			OperatingSystemScopeLocal,
			bun.In(filter.Scopes),
		)
		ossd.tracerSpan.SetAttribute(operatingSystemSQLDAOSpan, "scopes", filter.Scopes)
	}
	if filter.IncludeDeleted {
		query = query.WhereAllWithDeleted()
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
	if input.IpxeTemplateId != nil {
		it.IpxeTemplateId = input.IpxeTemplateId
		updatedFields = append(updatedFields, "ipxe_template_id")
	}
	if input.IpxeTemplateParameters != nil {
		it.IpxeTemplateParameters = *input.IpxeTemplateParameters
		updatedFields = append(updatedFields, "ipxe_template_parameters")
	}
	if input.IpxeTemplateArtifacts != nil {
		it.IpxeTemplateArtifacts = *input.IpxeTemplateArtifacts
		updatedFields = append(updatedFields, "ipxe_template_artifacts")
	}
	if input.IpxeOSHash != nil {
		it.IpxeTemplateDefinitionHash = input.IpxeOSHash
		updatedFields = append(updatedFields, "ipxe_template_definition_hash")
	}
	if input.Scope != nil {
		it.IpxeOsScope = input.Scope
		updatedFields = append(updatedFields, "ipxe_os_scope")
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
	if input.IpxeTemplateId {
		it.IpxeTemplateId = nil
		updatedFields = append(updatedFields, "ipxe_template_id")
	}
	if input.IpxeTemplateParameters {
		it.IpxeTemplateParameters = nil
		updatedFields = append(updatedFields, "ipxe_template_parameters")
	}
	if input.IpxeTemplateArtifacts {
		it.IpxeTemplateArtifacts = nil
		updatedFields = append(updatedFields, "ipxe_template_artifacts")
	}
	if input.IpxeOSHash {
		it.IpxeTemplateDefinitionHash = nil
		updatedFields = append(updatedFields, "ipxe_template_definition_hash")
	}
	if input.Scope {
		it.IpxeOsScope = nil
		updatedFields = append(updatedFields, "ipxe_os_scope")
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
