// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/extra/bundebug"
)

func testIssuerInitDB(t *testing.T) *db.Session {
	dbSession := util.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv(""),
	))
	return dbSession
}

// testIssuerSetupSchema resets the issuer table and adds the partial unique
// indexes that the migration creates (ResetModel builds only from struct tags).
func testIssuerSetupSchema(t *testing.T, dbSession *db.Session) {
	ctx := context.Background()
	require.NoError(t, dbSession.DB.ResetModel(ctx, (*Issuer)(nil)))
	_, err := dbSession.DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS issuer_issuer_url_idx ON issuer(issuer_url) WHERE deleted IS NULL")
	require.NoError(t, err)
	_, err = dbSession.DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS issuer_name_idx ON issuer(name) WHERE deleted IS NULL")
	require.NoError(t, err)
}

func TestIssuerSQLDAO_CRUD(t *testing.T) {
	ctx := context.Background()
	dbSession := testIssuerInitDB(t)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	creator := uuid.New()

	// Create
	var created *Issuer
	err := db.WithTx(ctx, dbSession, func(tx *db.Tx) error {
		var derr error
		created, derr = dao.Create(ctx, tx, IssuerCreateInput{
			Name:        "acme-idp",
			Origin:      "custom",
			IssuerURL:   "https://idp.acme.com",
			JWKSUrl:     "https://idp.acme.com/.well-known/jwks.json",
			JWKSTimeout: "5s",
			Audiences:   []string{"api.acme.com"},
			Scopes:      []string{"carbide"},
			ClaimMappings: []ClaimMapping{
				{OrgName: "acme", OrgDisplayName: "ACME", Roles: []string{"TENANT_ADMIN"}},
			},
			CreatedBy: &creator,
		})
		return derr
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Equal(t, "acme-idp", created.Name)
	assert.Equal(t, "https://idp.acme.com", created.IssuerURL)
	require.Len(t, created.ClaimMappings, 1)
	assert.Equal(t, "acme", created.ClaimMappings[0].OrgName)
	assert.Equal(t, []string{"TENANT_ADMIN"}, created.ClaimMappings[0].Roles)
	assert.Equal(t, []string{"api.acme.com"}, created.Audiences)

	// GetByID
	got, err := dao.GetByID(ctx, nil, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	require.Len(t, got.ClaimMappings, 1)
	assert.Equal(t, "acme", got.ClaimMappings[0].OrgName)

	// GetAll
	all, err := dao.GetAll(ctx, nil, IssuerFilterInput{})
	require.NoError(t, err)
	require.Len(t, all, 1)

	// Delete (soft) → GetByID returns ErrDoesNotExist
	err = db.WithTx(ctx, dbSession, func(tx *db.Tx) error {
		return dao.Delete(ctx, tx, created.ID)
	})
	require.NoError(t, err)
	_, err = dao.GetByID(ctx, nil, created.ID)
	assert.ErrorIs(t, err, db.ErrDoesNotExist)
}

func TestIssuerSQLDAO_DuplicateURLRejected(t *testing.T) {
	ctx := context.Background()
	dbSession := testIssuerInitDB(t)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)

	mk := func(name, url string) error {
		return db.WithTx(ctx, dbSession, func(tx *db.Tx) error {
			_, derr := dao.Create(ctx, tx, IssuerCreateInput{
				Name:      name,
				IssuerURL: url,
				JWKSUrl:   url + "/jwks",
			})
			return derr
		})
	}

	require.NoError(t, mk("issuer-a", "https://idp.example.com"))

	// Same URL, different name → unique violation on issuer_url.
	err := mk("issuer-b", "https://idp.example.com")
	require.Error(t, err)
	assert.True(t, (&db.PostgresErrorChecker{}).IsUniqueConstraintError(err), "expected unique constraint error, got: %v", err)
}

