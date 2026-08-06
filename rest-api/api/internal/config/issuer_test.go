// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"fmt"
	"testing"

	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	dbutil "github.com/NVIDIA/infra-controller/rest-api/db/pkg/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func staticIssuerConfig(t *testing.T) *Config {
	t.Helper()
	c, err := NewConfigFromYAML(`
issuers:
  - name: static-idp
    issuer: https://static.example.com
    jwks: https://static.example.com/jwks
    origin: custom
    claimMappings:
      - orgName: static-org
        roles: [TENANT_ADMIN]
`)
	require.NoError(t, err)
	return c
}

func mustConfigFromYAML(t *testing.T, yamlDoc string) *Config {
	t.Helper()
	c, err := NewConfigFromYAML(yamlDoc)
	require.NoError(t, err)
	return c
}

// ~~~~~ pure helpers (no DB) ~~~~~ //

func TestIsStaticIssuer(t *testing.T) {
	c := staticIssuerConfig(t)
	assert.True(t, c.IsStaticIssuer("https://static.example.com", ""), "match by issuer URL")
	assert.True(t, c.IsStaticIssuer("https://other.example.com", "static-idp"), "match by name")
	assert.False(t, c.IsStaticIssuer("https://idp.acme.com", "acme-idp"), "no match")
}

func TestHasPrivilegedStaticIssuerOrigins(t *testing.T) {
	assert.False(t, staticIssuerConfig(t).HasPrivilegedStaticIssuerOrigins(), "custom-only static set")
	assert.False(t, mustConfigFromYAML(t, `issuers: []`).HasPrivilegedStaticIssuerOrigins(), "empty set")

	for _, origin := range []string{"keycloak", "kas-legacy", "kas-ssa"} {
		c := mustConfigFromYAML(t, fmt.Sprintf(`
issuers:
  - name: privileged
    issuer: https://privileged.example.com
    jwks: https://privileged.example.com/jwks
    origin: %s
`, origin))
		assert.True(t, c.HasPrivilegedStaticIssuerOrigins(), origin)
	}
}

func TestHasDynamicConfigMapIssuers(t *testing.T) {
	assert.False(t, staticIssuerConfig(t).HasDynamicConfigMapIssuers(), "static orgName mappings only")
	assert.False(t, mustConfigFromYAML(t, `issuers: []`).HasDynamicConfigMapIssuers(), "empty set")

	cases := []struct {
		name string
		yaml string
	}{
		{"orgAttribute", `
issuers:
  - name: dyn
    issuer: https://dyn.example.com
    jwks: https://dyn.example.com/jwks
    origin: custom
    claimMappings:
      - orgAttribute: org
        orgDisplayAttribute: org_display
        rolesAttribute: roles
`},
		{"rolesAttribute-only", `
issuers:
  - name: dyn-roles
    issuer: https://dyn-roles.example.com
    jwks: https://dyn-roles.example.com/jwks
    origin: custom
    claimMappings:
      - orgName: acme
        rolesAttribute: roles
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, mustConfigFromYAML(t, tc.yaml).HasDynamicConfigMapIssuers())
		})
	}
}

func TestConvertClaimMappings_LowercasesOrgName(t *testing.T) {
	out := convertClaimMappings([]cdbm.ClaimMapping{
		{OrgName: "ACME-Corp", Roles: []string{"TENANT_ADMIN"}},
		{OrgAttribute: "org", OrgDisplayAttribute: "org_display", RolesAttribute: "roles"},
	})
	require.Len(t, out, 2)
	assert.Equal(t, "acme-corp", out[0].OrgName)
	assert.Equal(t, "org", out[1].OrgAttribute)
	assert.Equal(t, "", out[1].OrgName)
}

func TestComputeReservedOrgNames(t *testing.T) {
	reserved := computeReservedOrgNames([]IssuerConfig{
		{ClaimMappings: []cauth.ClaimMapping{{OrgName: "Acme"}, {OrgAttribute: "org"}}},
		{ClaimMappings: []cauth.ClaimMapping{{OrgName: "beta"}}},
	})
	assert.True(t, reserved["acme"])
	assert.True(t, reserved["beta"])
	assert.False(t, reserved["org"]) // dynamic attribute is not a reserved static name
}

func TestIssuerHasDynamicMapping(t *testing.T) {
	assert.True(t, (cdbm.Issuer{ClaimMappings: []cdbm.ClaimMapping{{OrgAttribute: "org"}}}).HasDynamicMapping())
	assert.False(t, (cdbm.Issuer{ClaimMappings: []cdbm.ClaimMapping{{OrgName: "acme"}}}).HasDynamicMapping())
}

func TestDBIssuerSignature_ChangeDetection(t *testing.T) {
	base := cdbm.Issuer{
		IssuerURL:     "https://idp.acme.com",
		JWKSUrl:       "https://idp.acme.com/jwks",
		Origin:        "custom",
		JWKSTimeout:   "5s",
		Audiences:     []string{"api"},
		ClaimMappings: []cdbm.ClaimMapping{{OrgName: "acme", Roles: []string{"TENANT_ADMIN"}}},
	}
	sig1 := base.Signature()
	assert.Equal(t, sig1, base.Signature(), "same input → same signature")

	changed := base
	changed.ClaimMappings = []cdbm.ClaimMapping{{OrgName: "acme", Roles: []string{"PROVIDER_ADMIN"}}}
	assert.NotEqual(t, sig1, changed.Signature(), "claim mapping change → new signature")

	changed2 := base
	changed2.JWKSUrl = "https://idp.acme.com/jwks/v2"
	assert.NotEqual(t, sig1, changed2.Signature(), "JWKS URL change → new signature")
}

func TestIssuerConfigFromDB(t *testing.T) {
	di := cdbm.Issuer{
		Name:          "acme-idp",
		Origin:        "custom",
		IssuerURL:     "https://idp.acme.com",
		JWKSUrl:       "https://idp.acme.com/jwks",
		JWKSTimeout:   "10s",
		Audiences:     []string{"api"},
		Scopes:        []string{"carbide"},
		ClaimMappings: []cdbm.ClaimMapping{{OrgName: "Acme", Roles: []string{"TENANT_ADMIN"}}},
	}
	ic := issuerConfigFromDB(di)
	assert.Equal(t, "acme-idp", ic.Name)
	assert.Equal(t, "https://idp.acme.com", ic.Issuer)
	assert.Equal(t, "https://idp.acme.com/jwks", ic.JWKS)
	assert.Equal(t, "10s", ic.JWKSTimeout)
	require.Len(t, ic.ClaimMappings, 1)
	assert.Equal(t, "acme", ic.ClaimMappings[0].OrgName) // normalized
}

// ~~~~~ DB-backed: seed, static-wins, convergence ~~~~~ //

func TestSeedAndReloadDBIssuers(t *testing.T) {
	ctx := context.Background()
	c := staticIssuerConfig(t)

	// Registry pre-populated with the static issuer, as GetOrInit would have done.
	reg := cauth.NewJWTOriginConfig()
	reg.AddJwksConfig(cauth.NewJwksConfig("static-idp", "https://static.example.com/jwks", "https://static.example.com", "custom", false, nil, nil))
	c.JwtOriginConfig = reg

	dbSession := dbutil.GetTestDBSession(t, false)
	defer dbSession.Close()
	require.NoError(t, dbSession.DB.ResetModel(ctx, (*cdbm.Issuer)(nil)))
	dao := cdbm.NewIssuerDAO(dbSession)

	// A valid DB issuer (unreachable JWKS URL so the fetch fails fast & non-fatally).
	err := cdb.WithTx(ctx, dbSession, func(tx *cdb.Tx) error {
		_, derr := dao.Create(ctx, tx, cdbm.IssuerCreateInput{
			
			Name:                     "acme-idp",
			Origin:                   "custom",
			IssuerURL:                "https://idp.acme.com",
			JWKSUrl:                  "http://127.0.0.1:1/jwks",
			ClaimMappings:            []cdbm.ClaimMapping{{OrgName: "acme", Roles: []string{"TENANT_ADMIN"}}},
		})
		return derr
	})
	require.NoError(t, err)

	// Seed → DB issuer present, static preserved.
	require.NoError(t, c.ReloadDBIssuers(ctx, dbSession))
	assert.NotNil(t, reg.GetConfig("https://idp.acme.com"), "DB issuer loaded into registry")
	assert.NotNil(t, reg.GetConfig("https://static.example.com"), "static issuer preserved")

	// Insert a DB row that conflicts with the static issuer URL → must be skipped
	// (static wins) and must NOT overwrite the static config.
	err = cdb.WithTx(ctx, dbSession, func(tx *cdb.Tx) error {
		_, derr := dao.Create(ctx, tx, cdbm.IssuerCreateInput{
			
			Name:                     "shadow-attempt",
			Origin:                   "custom",
			IssuerURL:                "https://static.example.com",
			JWKSUrl:                  "http://127.0.0.1:1/jwks",
			ClaimMappings:            []cdbm.ClaimMapping{{OrgName: "shadow", Roles: []string{"TENANT_ADMIN"}}},
		})
		return derr
	})
	require.NoError(t, err)

	require.NoError(t, c.ReloadDBIssuers(ctx, dbSession))
	staticCfg := reg.GetConfig("https://static.example.com")
	require.NotNil(t, staticCfg, "static issuer still present after conflicting DB row")
	assert.Equal(t, "static-idp", staticCfg.Name, "static config was NOT overwritten by the DB row")

	// Delete the DB issuer → convergence removes it; static remains.
	var acme *cdbm.Issuer
	acme, err = firstByURL(ctx, dao, "https://idp.acme.com")
	require.NoError(t, err)
	require.NotNil(t, acme)
	err = cdb.WithTx(ctx, dbSession, func(tx *cdb.Tx) error {
		return dao.Delete(ctx, tx, acme.ID)
	})
	require.NoError(t, err)

	require.NoError(t, c.ReloadDBIssuers(ctx, dbSession))
	assert.Nil(t, reg.GetConfig("https://idp.acme.com"), "deleted DB issuer removed from registry")
	assert.NotNil(t, reg.GetConfig("https://static.example.com"), "static issuer still present")
}

// TestReloadSkipsDynamicDBIssuer verifies the hard security boundary: a DB issuer
// carrying a dynamic (orgAttribute) mapping — e.g. inserted out-of-band — is never
// applied to the live registry.
func TestReloadSkipsDynamicDBIssuer(t *testing.T) {
	ctx := context.Background()
	c, err := NewConfigFromYAML("issuers: []\n")
	require.NoError(t, err)
	reg := cauth.NewJWTOriginConfig()
	c.JwtOriginConfig = reg

	dbSession := dbutil.GetTestDBSession(t, false)
	defer dbSession.Close()
	require.NoError(t, dbSession.DB.ResetModel(ctx, (*cdbm.Issuer)(nil)))
	dao := cdbm.NewIssuerDAO(dbSession)

	// A DB issuer with a DYNAMIC mapping (DAO.Create does not validate — simulates
	// a row inserted out-of-band, bypassing the API guard).
	require.NoError(t, cdb.WithTx(ctx, dbSession, func(tx *cdb.Tx) error {
		_, e := dao.Create(ctx, tx, cdbm.IssuerCreateInput{
			
			Name:                     "dyn-idp",
			Origin:                   "custom",
			IssuerURL:                "http://localhost:8082/realms/dyn",
			JWKSUrl:                  "http://127.0.0.1:1/jwks",
			ClaimMappings:            []cdbm.ClaimMapping{{OrgAttribute: "org", OrgDisplayAttribute: "org_display", RolesAttribute: "roles"}},
		})
		return e
	}))

	require.NoError(t, c.ReloadDBIssuers(ctx, dbSession))
	assert.Nil(t, reg.GetConfig("http://localhost:8082/realms/dyn"),
		"a dynamic DB issuer must be skipped, never applied to the registry")
}

func firstByURL(ctx context.Context, dao cdbm.IssuerDAO, url string) (*cdbm.Issuer, error) {
	all, err := dao.GetAll(ctx, nil, cdbm.IssuerFilterInput{IssuerURL: &url})
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, nil
	}
	return &all[0], nil
}
