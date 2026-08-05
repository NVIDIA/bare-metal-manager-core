// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"strings"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model/util"
	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
)

const (
	validationErrorIssuerDynamicClaimMapping = "dynamic claim attributes (orgAttribute/orgDisplayAttribute/rolesAttribute) are not permitted via the API; " +
		"only static orgName and roles claim mappings can be created"
	validationErrorIssuerClaimMappingOrgName = "orgName is required (only static org name claim mappings can be created via the API)"
)

// APIIssuerStatus reports whether an issuer can verify tokens yet. It is derived
// from the row's cached key set on every read, not stored.
type APIIssuerStatus string

const (
	// IssuerStatusPending means no signing keys have been fetched yet. Registration
	// never contacts the identity provider, so an issuer starts here and stays here
	// while its JWKS endpoint is unreachable; tokens it signs cannot be verified
	// until the background retry succeeds.
	IssuerStatusPending APIIssuerStatus = "Pending"
	// IssuerStatusReady means a key set has been fetched and tokens can be verified.
	IssuerStatusReady APIIssuerStatus = "Ready"
)

// APIIssuer is the API representation of a runtime-managed external JWT issuer.
type APIIssuer struct {
	// ID is the unique identifier of the issuer.
	ID string `json:"id"`
	// Origin selects the token processor (kas-legacy|kas-ssa|keycloak|custom).
	Origin string `json:"origin"`
	// IssuerURL is the expected JWT "iss" claim. Immutable after creation.
	IssuerURL string `json:"issuerUrl"`
	// JWKSUrl is where signing keys are fetched from.
	JWKSUrl string `json:"jwksUrl"`
	// JWKSTimeout is the JWKS fetch timeout (e.g. "5s").
	JWKSTimeout string `json:"jwksTimeout"`
	// ServiceAccount enables client-credentials flow (disconnected mode only).
	ServiceAccount bool `json:"serviceAccount"`
	// Audiences is the issuer-level allowed audience set (token needs at least one).
	Audiences []string `json:"audiences"`
	// Scopes is the issuer-level required scope set (token needs all).
	Scopes []string `json:"scopes"`
	// ClaimMappings is the org/role mapping array.
	ClaimMappings []cdbm.ClaimMapping `json:"claimMappings"`
	// Status reports whether signing keys have been fetched. A stored key set that
	// is present but unparseable reads as Ready; only an older or buggy writer can
	// produce one, and hydration logs it when it refuses the blob.
	Status APIIssuerStatus `json:"status"`
	// JWKSFetchedAt is when the signing keys were last fetched, absent if never.
	JWKSFetchedAt *time.Time `json:"jwksFetchedAt,omitempty"`
	// Created is the creation timestamp.
	Created time.Time `json:"created"`
	// Updated is the last-update timestamp.
	Updated time.Time `json:"updated"`
}

// NewAPIIssuer converts a DB Issuer into its API representation.
func NewAPIIssuer(dbIssuer *cdbm.Issuer) *APIIssuer {
	if dbIssuer == nil {
		return nil
	}

	claimMappings := dbIssuer.ClaimMappings
	if claimMappings == nil {
		claimMappings = []cdbm.ClaimMapping{}
	}
	audiences := dbIssuer.Audiences
	if audiences == nil {
		audiences = []string{}
	}
	scopes := dbIssuer.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	status := IssuerStatusPending
	if dbIssuer.HasCachedKeys() {
		status = IssuerStatusReady
	}

	return &APIIssuer{
		ID:             dbIssuer.ID.String(),
		Origin:         dbIssuer.Origin,
		IssuerURL:      dbIssuer.IssuerURL,
		JWKSUrl:        dbIssuer.JWKSUrl,
		JWKSTimeout:    dbIssuer.JWKSTimeout,
		ServiceAccount: dbIssuer.ServiceAccount,
		Audiences:      audiences,
		Scopes:         scopes,
		ClaimMappings:  claimMappings,
		Status:         status,
		JWKSFetchedAt:  dbIssuer.JWKSFetchedAt,
		Created:        dbIssuer.CreatedAt,
		Updated:        dbIssuer.UpdatedAt,
	}
}

// APIIssuerCreateRequest is the request body for creating an issuer. Origin is
// not accepted: API-created issuers are always custom.
type APIIssuerCreateRequest struct {
	IssuerURL      string              `json:"issuerUrl"`
	JWKSUrl        string              `json:"jwksUrl"`
	JWKSTimeout    string              `json:"jwksTimeout"`
	ServiceAccount bool                `json:"serviceAccount"`
	Audiences      []string            `json:"audiences"`
	Scopes         []string            `json:"scopes"`
	ClaimMappings  []cdbm.ClaimMapping `json:"claimMappings"`
}

// DefaultJWKSURL returns the JWKS URL, defaulting to {issuerUrl}/.well-known/jwks.json.
func DefaultJWKSURL(issuerURL, jwksURL string) string {
	if strings.TrimSpace(jwksURL) != "" {
		return jwksURL
	}
	return strings.TrimRight(issuerURL, "/") + "/.well-known/jwks.json"
}

// validateStaticOnlyClaimMapping enforces that issuers managed through the API
// carry only static claim mappings: a fixed orgName plus optional static roles.
// Attribute-driven fields let the token choose its own org and roles, a
// cross-tenant escalation risk, so those issuers must live in the ConfigMap.
func validateStaticOnlyClaimMapping(value interface{}) error {
	cm, ok := value.(cdbm.ClaimMapping)
	if !ok {
		return nil
	}
	if cm.OrgAttribute != "" || cm.OrgDisplayAttribute != "" || cm.RolesAttribute != "" {
		return errors.New(validationErrorIssuerDynamicClaimMapping)
	}
	if strings.TrimSpace(cm.OrgName) == "" {
		return errors.New(validationErrorIssuerClaimMappingOrgName)
	}
	return nil
}

// Validate performs lightweight, shape-level validation. Deep, cross-issuer rules
// (org uniqueness, single dynamic mapping, disconnected-only service accounts,
// role validity, ...) are enforced by config.ValidateIssuersConfig over the
// combined static+DB set in the handler.
func (r *APIIssuerCreateRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.IssuerURL,
			validation.Required.Error(validationErrorValueRequired),
			validation.Match(util.NotAllWhitespaceRegexp).Error(validationErrorValueRequired)),
		validation.Field(&r.ClaimMappings,
			validation.Each(validation.By(validateStaticOnlyClaimMapping))),
	)
}

// ToCreateInput builds the DAO create input from the request. Origin is always
// custom — runtime-managed issuers cannot select a privileged processor.
func (r *APIIssuerCreateRequest) ToCreateInput(createdBy *uuid.UUID) cdbm.IssuerCreateInput {
	claimMappings := r.ClaimMappings
	if claimMappings == nil {
		claimMappings = []cdbm.ClaimMapping{}
	}
	return cdbm.IssuerCreateInput{
		Origin:         cauth.TokenOriginCustom,
		IssuerURL:      r.IssuerURL,
		JWKSUrl:        DefaultJWKSURL(r.IssuerURL, r.JWKSUrl),
		JWKSTimeout:    r.JWKSTimeout,
		ServiceAccount: r.ServiceAccount,
		Audiences:      r.Audiences,
		Scopes:         r.Scopes,
		ClaimMappings:  claimMappings,
		CreatedBy:      createdBy,
	}
}
