// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"strings"
	"time"

	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/google/uuid"
)

// APIIssuer is the API representation of a runtime-managed external JWT issuer.
type APIIssuer struct {
	// ID is the unique identifier of the issuer.
	ID string `json:"id"`
	// Name is the unique issuer name.
	Name string `json:"name"`
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

	return &APIIssuer{
		ID:   dbIssuer.ID.String(),
		Name: dbIssuer.Name,
		Origin:                       dbIssuer.Origin,
		IssuerURL:                    dbIssuer.IssuerURL,
		JWKSUrl:                      dbIssuer.JWKSUrl,
		JWKSTimeout:                  dbIssuer.JWKSTimeout,
		ServiceAccount:               dbIssuer.ServiceAccount,
		Audiences:                    audiences,
		Scopes:                       scopes,
		ClaimMappings: claimMappings,
		Created:                      dbIssuer.CreatedAt,
		Updated:                      dbIssuer.UpdatedAt,
	}
}

// APIIssuerCreateRequest is the request body for creating an issuer. Origin is
// not accepted: API-created issuers are always custom.
type APIIssuerCreateRequest struct {
	Name                         string              `json:"name"`
	IssuerURL                    string              `json:"issuerUrl"`
	JWKSUrl                      string              `json:"jwksUrl"`
	JWKSTimeout                  string              `json:"jwksTimeout"`
	ServiceAccount               bool                `json:"serviceAccount"`
	Audiences                    []string            `json:"audiences"`
	Scopes                       []string            `json:"scopes"`
	ClaimMappings []cdbm.ClaimMapping `json:"claimMappings"`
}

// DefaultJWKSURL returns the JWKS URL, defaulting to {issuerUrl}/.well-known/jwks.json.
func DefaultJWKSURL(issuerURL, jwksURL string) string {
	if strings.TrimSpace(jwksURL) != "" {
		return jwksURL
	}
	return strings.TrimRight(issuerURL, "/") + "/.well-known/jwks.json"
}

// ValidateStaticOnlyClaimMappings enforces that issuers created/updated via the
// API may only carry fully STATIC claim mappings: fixed orgName plus optional
// static roles. Attribute-driven fields (orgAttribute, orgDisplayAttribute,
// rolesAttribute) let the token choose org/roles at runtime, which is a
// cross-tenant escalation risk for runtime-managed issuers — those must be
// defined in the trusted ConfigMap instead, and their presence there disables
// the issuer API entirely.
func ValidateStaticOnlyClaimMappings(mappings []cdbm.ClaimMapping) error {
	for i, cm := range mappings {
		if cm.OrgAttribute != "" || cm.OrgDisplayAttribute != "" || cm.RolesAttribute != "" {
			return fmt.Errorf("claimMapping %d: dynamic claim attributes (orgAttribute/orgDisplayAttribute/rolesAttribute) are not permitted via the API; "+
				"only static orgName and roles claim mappings can be created", i)
		}
		if strings.TrimSpace(cm.OrgName) == "" {
			return fmt.Errorf("claimMapping %d: orgName is required (only static org name claim mappings can be created via the API)", i)
		}
	}
	return nil
}

// Validate performs lightweight, shape-level validation. Deep, cross-issuer rules
// (org uniqueness, single dynamic mapping, disconnected-only service accounts,
// role validity, ...) are enforced by config.ValidateIssuersConfig over the
// combined static+DB set in the handler.
func (r *APIIssuerCreateRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(r.IssuerURL) == "" {
		return fmt.Errorf("issuerUrl is required")
	}
	// Runtime (API-created) issuers may only carry static orgName mappings.
	if err := ValidateStaticOnlyClaimMappings(r.ClaimMappings); err != nil {
		return err
	}
	return nil
}

// ToCreateInput builds the DAO create input from the request. Origin is always
// custom — runtime-managed issuers cannot select a privileged processor.
func (r *APIIssuerCreateRequest) ToCreateInput(createdBy *uuid.UUID) cdbm.IssuerCreateInput {
	claimMappings := r.ClaimMappings
	if claimMappings == nil {
		claimMappings = []cdbm.ClaimMapping{}
	}
	return cdbm.IssuerCreateInput{
		Name: r.Name,
		Origin:                       cauth.TokenOriginCustom,
		IssuerURL:                    r.IssuerURL,
		JWKSUrl:                      DefaultJWKSURL(r.IssuerURL, r.JWKSUrl),
		JWKSTimeout:                  r.JWKSTimeout,
		ServiceAccount:               r.ServiceAccount,
		Audiences:                    r.Audiences,
		Scopes:                       r.Scopes,
		ClaimMappings: claimMappings,
		CreatedBy:                    createdBy,
	}
}

