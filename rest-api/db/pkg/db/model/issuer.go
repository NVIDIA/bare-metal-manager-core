// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/google/uuid"

	stracer "github.com/NVIDIA/infra-controller/rest-api/db/pkg/tracer"
	"github.com/uptrace/bun"
)

// IssuerRelationName is the relation name for the Issuer model
const IssuerRelationName = "Issuer"

// ClaimMapping is one entry of an issuer's claim_mappings JSONB array. It is the
// persisted, JSON-tagged twin of auth/pkg/config.ClaimMapping (which carries only
// mapstructure tags for Viper). The two structs hold the same eight fields; the
// config bridge converts between them when (un)loading the live auth registry.
type ClaimMapping struct {
	// OrgAttribute is the JWT claim path to extract the org name (dynamic mapping).
	OrgAttribute string `json:"orgAttribute,omitempty"`
	// OrgDisplayAttribute is the JWT claim path for the org display name (dynamic mapping).
	OrgDisplayAttribute string `json:"orgDisplayAttribute,omitempty"`
	// OrgName is the fixed org name (static mapping).
	OrgName string `json:"orgName,omitempty"`
	// OrgDisplayName is the display name for a static org mapping.
	OrgDisplayName string `json:"orgDisplayName,omitempty"`
	// RolesAttribute is the JWT claim path to extract roles. Takes precedence over Roles.
	RolesAttribute string `json:"rolesAttribute,omitempty"`
	// Roles is the static role list.
	Roles []string `json:"roles,omitempty"`
	// Audiences is the optional per-mapping token audiences allowed to authorize this mapping.
	Audiences []string `json:"audiences,omitempty"`
	// IsServiceAccount, when true, assigns admin roles (disconnected mode only).
	IsServiceAccount bool `json:"isServiceAccount,omitempty"`
}

// IssuerCreateInput are the parameters for the Create method.
type IssuerCreateInput struct {
	Origin         string
	IssuerURL      string
	JWKSUrl        string
	JWKSTimeout    string
	ServiceAccount bool
	Audiences      []string
	Scopes         []string
	ClaimMappings  []ClaimMapping
	CreatedBy      *uuid.UUID
}

// ToIssuer projects a create input onto the Issuer it would produce, applying the
// same defaults the table declares. Create builds the inserted row with it, and
// callers that must validate an Issuer before the row exists use it to build the
// candidate.
func (input IssuerCreateInput) ToIssuer() Issuer {
	claimMappings := input.ClaimMappings
	if claimMappings == nil {
		claimMappings = []ClaimMapping{}
	}
	audiences := input.Audiences
	if audiences == nil {
		audiences = []string{}
	}
	scopes := input.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	jwksTimeout := input.JWKSTimeout
	if jwksTimeout == "" {
		jwksTimeout = "5s"
	}
	origin := input.Origin
	if origin == "" {
		origin = "custom"
	}

	return Issuer{
		Origin:         origin,
		IssuerURL:      input.IssuerURL,
		JWKSUrl:        input.JWKSUrl,
		JWKSTimeout:    jwksTimeout,
		ServiceAccount: input.ServiceAccount,
		Audiences:      audiences,
		Scopes:         scopes,
		ClaimMappings:  claimMappings,
		CreatedBy:      input.CreatedBy,
		UpdatedBy:      input.CreatedBy,
	}
}

// IssuerFilterInput are the optional filters for the GetAll method.
type IssuerFilterInput struct {
	IssuerURL *string
}

// Issuer is a runtime-managed external JWT issuer. It is a persistent mirror of
// the static ConfigMap IssuerConfig shape and is loaded into the same auth
// registry (map issuer_url -> JwksConfig) as ConfigMap issuers.
type Issuer struct {
	bun.BaseModel `bun:"table:issuer,alias:iss"`

	ID             uuid.UUID      `bun:"id,pk,type:uuid,default:gen_random_uuid()"`
	Origin         string         `bun:"origin,notnull,default:'custom'"`
	IssuerURL      string         `bun:"issuer_url,notnull"`
	JWKSUrl        string         `bun:"jwks_url,notnull"`
	JWKSTimeout    string         `bun:"jwks_timeout,notnull,default:'5s'"`
	ServiceAccount bool           `bun:"service_account,notnull"`
	Audiences      []string       `bun:"audiences,array,notnull"`
	Scopes         []string       `bun:"scopes,array,notnull"`
	ClaimMappings  []ClaimMapping `bun:"claim_mappings,type:jsonb,notnull,default:'[]'"`
	// JWKSKeys is the cached key set fetched from JWKSUrl, stored so a restarting
	// replica can serve tokens before reaching the IdP. It is deliberately absent from
	// Signature(): a refresh is not a configuration change, and counting it as one
	// would rebuild the live JwksConfig and discard the keys it just fetched.
	JWKSKeys json.RawMessage `bun:"jwks_keys,type:jsonb,nullzero"`
	// JWKSFetchedAt is when JWKSKeys was last successfully fetched. NULL means never.
	JWKSFetchedAt *time.Time `bun:"jwks_fetched_at,nullzero"`
	CreatedAt     time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt     time.Time  `bun:"updated_at,nullzero,notnull,default:current_timestamp"`
	CreatedBy     *uuid.UUID `bun:"created_by,type:uuid"`
	UpdatedBy     *uuid.UUID `bun:"updated_by,type:uuid"`
	Deleted       *time.Time `bun:"deleted,soft_delete"`
}

var _ bun.BeforeAppendModelHook = (*Issuer)(nil)

// BeforeAppendModel maintains the created_at/updated_at timestamps.
func (i *Issuer) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		i.CreatedAt = db.GetCurTime()
		i.UpdatedAt = db.GetCurTime()
	case *bun.UpdateQuery:
		i.UpdatedAt = db.GetCurTime()
	}
	return nil
}

// IssuerDAO is an interface for interacting with the Issuer model.
type IssuerDAO interface {
	Create(ctx context.Context, tx *db.Tx, input IssuerCreateInput) (*Issuer, error)
	GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID) (*Issuer, error)
	GetAll(ctx context.Context, tx *db.Tx, filter IssuerFilterInput) ([]Issuer, error)
	Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error
	UpdateJWKSCache(ctx context.Context, tx *db.Tx, id uuid.UUID, raw json.RawMessage, fetchedAt time.Time) error
}

// IssuerSQLDAO is the SQL implementation of the IssuerDAO interface.
type IssuerSQLDAO struct {
	dbSession *db.Session
	IssuerDAO
	tracerSpan *stracer.TracerSpan
}

// NewIssuerDAO returns a new IssuerDAO.
func NewIssuerDAO(dbSession *db.Session) IssuerDAO {
	return &IssuerSQLDAO{
		dbSession:  dbSession,
		tracerSpan: stracer.NewTracerSpan(),
	}
}

// Create inserts a new Issuer. Because there are two operations (INSERT, SELECT),
// this call must happen within a transaction.
func (isd IssuerSQLDAO) Create(ctx context.Context, tx *db.Tx, input IssuerCreateInput) (*Issuer, error) {
	ctx, issuerDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.Create")
	if issuerDAOSpan != nil {
		defer issuerDAOSpan.End()
	}

	i := input.ToIssuer()
	i.ID = uuid.New()

	_, err := db.GetIDB(tx, isd.dbSession).NewInsert().Model(&i).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return isd.GetByID(ctx, tx, i.ID)
}

// GetByID returns an Issuer by ID. Returns db.ErrDoesNotExist if not found.
func (isd IssuerSQLDAO) GetByID(ctx context.Context, tx *db.Tx, id uuid.UUID) (*Issuer, error) {
	ctx, issuerDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.GetByID")
	if issuerDAOSpan != nil {
		defer issuerDAOSpan.End()
		isd.tracerSpan.SetAttribute(issuerDAOSpan, "issuer_id", id.String())
	}

	i := &Issuer{}
	err := db.GetIDB(tx, isd.dbSession).NewSelect().Model(i).Where("iss.id = ?", id).Scan(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, db.ErrDoesNotExist
		}
		return nil, err
	}
	return i, nil
}

// GetAll returns all Issuers matching the optional filters. Soft-deleted rows are
// excluded automatically. If no records match, the returned slice is empty and
// error is nil.
func (isd IssuerSQLDAO) GetAll(ctx context.Context, tx *db.Tx, filter IssuerFilterInput) ([]Issuer, error) {
	ctx, issuerDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.GetAll")
	if issuerDAOSpan != nil {
		defer issuerDAOSpan.End()
	}

	issuers := []Issuer{}
	query := db.GetIDB(tx, isd.dbSession).NewSelect().Model(&issuers)

	if filter.IssuerURL != nil {
		query = query.Where("iss.issuer_url = ?", *filter.IssuerURL)
	}

	query = query.Order("iss.created_at ASC")

	if err := query.Scan(ctx); err != nil {
		return nil, err
	}
	return issuers, nil
}

// Delete soft-deletes an Issuer by ID. Idempotent: no error if the row is absent.
func (isd IssuerSQLDAO) Delete(ctx context.Context, tx *db.Tx, id uuid.UUID) error {
	ctx, issuerDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.Delete")
	if issuerDAOSpan != nil {
		defer issuerDAOSpan.End()
	}

	i := &Issuer{ID: id}
	_, err := db.GetIDB(tx, isd.dbSession).NewDelete().Model(i).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

// UpdateJWKSCache stores a freshly fetched key set for an issuer, when it is
// actually new. A refresh that returns the key set already stored writes nothing.
//
// The Column list keeps the SET clause to the two cache columns, so a background
// refresh does not touch updated_at or updated_by the way an operator edit does.
//
// Two predicates guard the write. The jwks_fetched_at comparison is the stale-write
// guard for two replicas refreshing concurrently: fetchedAt is when the caller
// issued the fetch, not when it completed, so it compares acquisition order. The
// jwks_keys comparison keeps a stable issuer from being rewritten every refresh
// interval by every replica; jsonb equality is semantic, so a re-serialized
// identical key set is correctly seen as unchanged. A NULL cache is distinct from
// any key set, so the first successful fetch always lands.
func (isd IssuerSQLDAO) UpdateJWKSCache(ctx context.Context, tx *db.Tx, id uuid.UUID, raw json.RawMessage, fetchedAt time.Time) error {
	ctx, issuerDAOSpan := isd.tracerSpan.CreateChildInCurrentContext(ctx, "IssuerDAO.UpdateJWKSCache")
	if issuerDAOSpan != nil {
		defer issuerDAOSpan.End()
		isd.tracerSpan.SetAttribute(issuerDAOSpan, "issuer_id", id.String())
	}

	if len(raw) == 0 {
		return errors.New("refusing to cache an empty JWKS key set")
	}

	i := Issuer{ID: id, JWKSKeys: raw, JWKSFetchedAt: &fetchedAt}
	_, err := db.GetIDB(tx, isd.dbSession).NewUpdate().Model(&i).
		Column("jwks_keys", "jwks_fetched_at").
		Where("id = ? AND (jwks_fetched_at IS NULL OR jwks_fetched_at < ?)", id, fetchedAt).
		Where("jwks_keys IS DISTINCT FROM ?::jsonb", string(raw)).
		Exec(ctx)
	return err
}

// HasCachedKeys reports whether the row carries a key set some replica fetched.
// Both fields are required: without a fetch time there is no defensible stamp to
// install the keys under, so hydration ignores them.
func (i Issuer) HasCachedKeys() bool {
	return len(i.JWKSKeys) > 0 && i.JWKSFetchedAt != nil
}

// HasDynamicMapping reports whether any claim mapping is attribute-driven
// (orgAttribute is set), meaning the token's own claims pick the org.
func (i Issuer) HasDynamicMapping() bool {
	for _, cm := range i.ClaimMappings {
		if cm.OrgAttribute != "" {
			return true
		}
	}
	return false
}

// Signature returns a stable SHA-256 content fingerprint covering every field
// that affects the live JwksConfig for this issuer. An unchanged signature means
// the registry entry and its cached JWKS keys can be kept as-is.
//
// JWKSKeys and JWKSFetchedAt are deliberately excluded. They are cached key
// material, not configuration: including them would make every refresh look like
// a config change, so every replica would rebuild its JwksConfig and discard the
// keys it had just fetched.
func (i Issuer) Signature() string {
	payload := struct {
		URL           string         `json:"u"`
		JWKS          string         `json:"j"`
		Origin        string         `json:"o"`
		Timeout       string         `json:"t"`
		SA            bool           `json:"s"`
		Aud           []string       `json:"a"`
		Scp           []string       `json:"c"`
		ClaimMappings []ClaimMapping `json:"m"`
	}{
		URL:           i.IssuerURL,
		JWKS:          i.JWKSUrl,
		Origin:        i.Origin,
		Timeout:       i.JWKSTimeout,
		SA:            i.ServiceAccount,
		Aud:           i.Audiences,
		Scp:           i.Scopes,
		ClaimMappings: i.ClaimMappings,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return i.UpdatedAt.String() + ":" + i.ID.String()
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
