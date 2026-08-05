// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"testing"
	"time"

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
	tests := []struct {
		name    string
		req     APIIssuerCreateRequest
		wantErr bool
	}{
		{
			name:    "missing_issuer_url",
			req:     APIIssuerCreateRequest{},
			wantErr: true,
		},
		{
			name:    "whitespace_issuer_url",
			req:     APIIssuerCreateRequest{IssuerURL: "   "},
			wantErr: true,
		},
		{
			name: "issuer_url_without_claim_mappings",
			req:  APIIssuerCreateRequest{IssuerURL: "https://idp.acme.com"},
		},
		{
			name: "static_org_name_and_roles",
			req: APIIssuerCreateRequest{IssuerURL: "https://idp.acme.com",
				ClaimMappings: []cdbm.ClaimMapping{{OrgName: "acme", Roles: []string{"TENANT_ADMIN"}}}},
		},
		{
			name: "org_attribute_rejected",
			req: APIIssuerCreateRequest{IssuerURL: "https://idp.acme.com",
				ClaimMappings: []cdbm.ClaimMapping{{OrgAttribute: "org", RolesAttribute: "roles"}}},
			wantErr: true,
		},
		{
			name: "org_display_attribute_rejected",
			req: APIIssuerCreateRequest{IssuerURL: "https://idp.acme.com",
				ClaimMappings: []cdbm.ClaimMapping{{OrgName: "acme", OrgDisplayAttribute: "org_display"}}},
			wantErr: true,
		},
		{
			name: "roles_attribute_rejected",
			req: APIIssuerCreateRequest{IssuerURL: "https://idp.acme.com",
				ClaimMappings: []cdbm.ClaimMapping{{OrgName: "acme", RolesAttribute: "roles"}}},
			wantErr: true,
		},
		{
			name: "missing_org_name",
			req: APIIssuerCreateRequest{IssuerURL: "https://idp.acme.com",
				ClaimMappings: []cdbm.ClaimMapping{{Roles: []string{"TENANT_ADMIN"}}}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestNewAPIIssuer(t *testing.T) {
	assert.Nil(t, NewAPIIssuer(nil))

	id := uuid.New()
	db := &cdbm.Issuer{
		ID:            id,
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

// TestNewAPIIssuer_Status covers the readiness an operator polls for after a
// create the identity provider was not part of: the status is derived from the
// row's cached key set, and it takes both the keys and the fetch time, because
// hydration refuses a key set it cannot stamp.
func TestNewAPIIssuer_Status(t *testing.T) {
	fetchedAt := time.Now().UTC()
	keys := json.RawMessage(`{"keys":[{"kty":"RSA","use":"sig","kid":"key-1","alg":"RS256","n":"n","e":"AQAB"}]}`)

	tests := []struct {
		name       string
		keys       json.RawMessage
		fetchedAt  *time.Time
		wantStatus APIIssuerStatus
	}{
		{
			name:       "never_fetched_is_pending",
			wantStatus: IssuerStatusPending,
		},
		{
			name:       "cached_key_set_is_ready",
			keys:       keys,
			fetchedAt:  &fetchedAt,
			wantStatus: IssuerStatusReady,
		},
		{
			name:       "keys_without_fetch_time_are_pending",
			keys:       keys,
			wantStatus: IssuerStatusPending,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := NewAPIIssuer(&cdbm.Issuer{ID: uuid.New(), JWKSKeys: tt.keys, JWKSFetchedAt: tt.fetchedAt})
			require.NotNil(t, api)
			assert.Equal(t, tt.wantStatus, api.Status)
			assert.Equal(t, tt.fetchedAt, api.JWKSFetchedAt)
		})
	}
}

func TestToCreateInput(t *testing.T) {
	creator := uuid.New()
	req := &APIIssuerCreateRequest{
		IssuerURL:     "https://idp.acme.com",
		ClaimMappings: nil,
	}
	in := req.ToCreateInput(&creator)
	assert.Equal(t, "https://idp.acme.com/.well-known/jwks.json", in.JWKSUrl)
	assert.Equal(t, &creator, in.CreatedBy)
	assert.Equal(t, "custom", in.Origin)
	assert.NotNil(t, in.ClaimMappings)
}
