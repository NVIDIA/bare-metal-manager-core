// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultJWKSURL(t *testing.T) {
	assert.Equal(t, "https://idp.acme.com/.well-known/jwks.json", DefaultJWKSURL("https://idp.acme.com", ""))
	assert.Equal(t, "https://idp.acme.com/.well-known/jwks.json", DefaultJWKSURL("https://idp.acme.com/", ""))
	assert.Equal(t, "https://custom/jwks", DefaultJWKSURL("https://idp.acme.com", "https://custom/jwks"))
}

func TestAPIIssuerCreateRequest_Validate(t *testing.T) {
	assert.Error(t, (&APIIssuerCreateRequest{IssuerURL: "https://x"}).Validate()) // missing name
	assert.Error(t, (&APIIssuerCreateRequest{Name: "x"}).Validate())              // missing issuerUrl
	assert.NoError(t, (&APIIssuerCreateRequest{Name: "x", IssuerURL: "https://x"}).Validate())
}

func TestNewAPIIssuer(t *testing.T) {
	assert.Nil(t, NewAPIIssuer(nil))

	id := uuid.New()
	db := &cdbm.Issuer{
		ID:            id,
		Name:          "acme-idp",
		Origin:        "custom",
		IssuerURL:     "https://idp.acme.com",
		JWKSUrl:       "https://idp.acme.com/jwks",
		JWKSTimeout:   "5s",
		Audiences:     []string{"api"},
		Scopes:        []string{"carbide"},
		ClaimMappings: []cdbm.ClaimMapping{{OrgName: "acme", Roles: []string{"TENANT_ADMIN"}}},
	}
	api := NewAPIIssuer(db)
	require.NotNil(t, api)
	assert.Equal(t, id.String(), api.ID)
	assert.Equal(t, "https://idp.acme.com", api.IssuerURL)
	require.Len(t, api.ClaimMappings, 1)
	assert.Equal(t, "acme", api.ClaimMappings[0].OrgName)

	// nil slices are normalized to empty (stable JSON output)
	empty := NewAPIIssuer(&cdbm.Issuer{ID: id})
	assert.NotNil(t, empty.Audiences)
	assert.NotNil(t, empty.Scopes)
	assert.NotNil(t, empty.ClaimMappings)
}

func TestToCreateInput(t *testing.T) {
	creator := uuid.New()
	req := &APIIssuerCreateRequest{
		Name:          "acme-idp",
		IssuerURL:     "https://idp.acme.com",
		ClaimMappings: nil,
	}
	in := req.ToCreateInput(&creator)
	assert.Equal(t, "https://idp.acme.com/.well-known/jwks.json", in.JWKSUrl)
	assert.Equal(t, &creator, in.CreatedBy)
	assert.Equal(t, "custom", in.Origin)
	assert.NotNil(t, in.ClaimMappings)
}

func TestValidateStaticOnlyClaimMappings(t *testing.T) {
	// static orgName + roles mapping is allowed
	assert.NoError(t, ValidateStaticOnlyClaimMappings([]cdbm.ClaimMapping{{OrgName: "acme", Roles: []string{"TENANT_ADMIN"}}}))
	// dynamic orgAttribute mapping is rejected
	assert.Error(t, ValidateStaticOnlyClaimMappings([]cdbm.ClaimMapping{{OrgAttribute: "org", RolesAttribute: "roles"}}))
	// orgDisplayAttribute (dynamic) is rejected
	assert.Error(t, ValidateStaticOnlyClaimMappings([]cdbm.ClaimMapping{{OrgName: "acme", OrgDisplayAttribute: "org_display"}}))
	// rolesAttribute (dynamic roles) is rejected even with static orgName
	assert.Error(t, ValidateStaticOnlyClaimMappings([]cdbm.ClaimMapping{{OrgName: "acme", RolesAttribute: "roles"}}))
	// missing orgName is rejected (must be static)
	assert.Error(t, ValidateStaticOnlyClaimMappings([]cdbm.ClaimMapping{{Roles: []string{"TENANT_ADMIN"}}}))

	// Create request rejects a dynamic mapping, accepts a static one.
	assert.Error(t, (&APIIssuerCreateRequest{Name: "x", IssuerURL: "https://x",
		ClaimMappings: []cdbm.ClaimMapping{{OrgAttribute: "org"}}}).Validate())
	assert.Error(t, (&APIIssuerCreateRequest{Name: "x", IssuerURL: "https://x",
		ClaimMappings: []cdbm.ClaimMapping{{OrgName: "acme", RolesAttribute: "roles"}}}).Validate())
	assert.NoError(t, (&APIIssuerCreateRequest{Name: "x", IssuerURL: "https://x",
		ClaimMappings: []cdbm.ClaimMapping{{OrgName: "acme", Roles: []string{"TENANT_ADMIN"}}}}).Validate())
}

