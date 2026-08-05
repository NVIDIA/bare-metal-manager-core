// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/extra/bundebug"
)

const testJWKSBlob = `{"keys":[{"kty":"RSA","use":"sig","kid":"key-1","alg":"RS256","n":"n","e":"AQAB"}]}`

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
}

func createTestIssuer(t *testing.T, ctx context.Context, dbSession *db.Session, dao IssuerDAO) *Issuer {
	t.Helper()

	creator := uuid.New()
	var created *Issuer
	err := db.WithTx(ctx, dbSession, func(tx *db.Tx) error {
		var derr error
		created, derr = dao.Create(ctx, tx, IssuerCreateInput{
			Origin:      "custom",
			IssuerURL:   "https://idp.jwks-cache.test",
			JWKSUrl:     "https://idp.jwks-cache.test/.well-known/jwks.json",
			JWKSTimeout: "5s",
			ClaimMappings: []ClaimMapping{
				{OrgName: "acme", OrgDisplayName: "ACME", Roles: []string{"TENANT_ADMIN"}},
			},
			CreatedBy: &creator,
		})
		return derr
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	return created
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

	mk := func(url, jwksURL string) error {
		return db.WithTx(ctx, dbSession, func(tx *db.Tx) error {
			_, derr := dao.Create(ctx, tx, IssuerCreateInput{
				IssuerURL: url,
				JWKSUrl:   jwksURL,
			})
			return derr
		})
	}

	require.NoError(t, mk("https://idp.example.com", "https://idp.example.com/jwks"))

	// Same issuer URL, different JWKS URL → unique violation on issuer_url.
	err := mk("https://idp.example.com", "https://other.example.com/jwks")
	require.Error(t, err)
	assert.True(t, (&db.PostgresErrorChecker{}).IsUniqueConstraintError(err), "expected unique constraint error, got: %v", err)
}

func TestIssuerSQLDAO_UpdateJWKSCache(t *testing.T) {
	ctx := context.Background()
	dbSession := testIssuerInitDB(t)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	created := createTestIssuer(t, ctx, dbSession, dao)

	require.Empty(t, created.JWKSKeys, "a new issuer has no cached key set")
	require.Nil(t, created.JWKSFetchedAt)

	fetchedAt := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, dao.UpdateJWKSCache(ctx, nil, created.ID, json.RawMessage(testJWKSBlob), fetchedAt))

	stored, err := dao.GetByID(ctx, nil, created.ID)
	require.NoError(t, err)
	assert.JSONEq(t, testJWKSBlob, string(stored.JWKSKeys))
	require.NotNil(t, stored.JWKSFetchedAt)
	assert.WithinDuration(t, fetchedAt, *stored.JWKSFetchedAt, time.Millisecond)

	// The audit fields describe operator edits. A background key refresh is not
	// one, so the restricted column list must have kept them out of the SET clause.
	assert.Equal(t, created.UpdatedAt.UTC(), stored.UpdatedAt.UTC(), "updated_at must not move on a key refresh")
	assert.Equal(t, created.UpdatedBy, stored.UpdatedBy, "updated_by must not move on a key refresh")
}

// TestIssuerSQLDAO_UpdateJWKSCacheStaleWriteGuard covers two replicas refreshing
// the same issuer at once: the fetch that finishes second with older keys must
// not clobber the newer set.
func TestIssuerSQLDAO_UpdateJWKSCacheStaleWriteGuard(t *testing.T) {
	ctx := context.Background()
	dbSession := testIssuerInitDB(t)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	created := createTestIssuer(t, ctx, dbSession, dao)

	newer := time.Now().UTC()
	older := newer.Add(-time.Minute)
	staleBlob := `{"keys":[{"kty":"RSA","use":"sig","kid":"stale-key","alg":"RS256","n":"n","e":"AQAB"}]}`

	require.NoError(t, dao.UpdateJWKSCache(ctx, nil, created.ID, json.RawMessage(testJWKSBlob), newer))
	require.NoError(t, dao.UpdateJWKSCache(ctx, nil, created.ID, json.RawMessage(staleBlob), older),
		"a losing stale write is a no-op, not an error")

	stored, err := dao.GetByID(ctx, nil, created.ID)
	require.NoError(t, err)
	assert.JSONEq(t, testJWKSBlob, string(stored.JWKSKeys), "the newer key set must survive")
	assert.WithinDuration(t, newer, *stored.JWKSFetchedAt, time.Millisecond)
}

// TestIssuerSQLDAO_UpdateJWKSCacheSkipsUnchangedKeys covers the steady state: an
// issuer that has not rotated is refreshed every interval by every replica, and
// none of those refreshes may write. A rotation still lands, and the same key set
// re-serialized differently is not a rotation, because jsonb equality is semantic.
func TestIssuerSQLDAO_UpdateJWKSCacheSkipsUnchangedKeys(t *testing.T) {
	ctx := context.Background()
	dbSession := testIssuerInitDB(t)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	created := createTestIssuer(t, ctx, dbSession, dao)

	first := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, dao.UpdateJWKSCache(ctx, nil, created.ID, json.RawMessage(testJWKSBlob), first))

	// Same key set, later fetch: the stale-write predicate would allow this write, so
	// only the key comparison can stop it.
	require.NoError(t, dao.UpdateJWKSCache(ctx, nil, created.ID, json.RawMessage(testJWKSBlob), time.Now().UTC()),
		"an unchanged key set is a no-op, not an error")

	stored, err := dao.GetByID(ctx, nil, created.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, first, *stored.JWKSFetchedAt, time.Millisecond,
		"nothing was written, so the stamp still describes the fetch that stored these keys")

	// Reordered fields and added whitespace are the same key set.
	reserialized := `{"keys": [ {"e":"AQAB","alg":"RS256","kid":"key-1","kty":"RSA","n":"n","use":"sig"} ]}`
	require.NoError(t, dao.UpdateJWKSCache(ctx, nil, created.ID, json.RawMessage(reserialized), time.Now().UTC()))

	stored, err = dao.GetByID(ctx, nil, created.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, first, *stored.JWKSFetchedAt, time.Millisecond,
		"a re-serialized identical key set must not count as a rotation")

	// A real rotation writes.
	rotated := `{"keys":[{"kty":"RSA","use":"sig","kid":"key-2","alg":"RS256","n":"n","e":"AQAB"}]}`
	rotatedAt := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, dao.UpdateJWKSCache(ctx, nil, created.ID, json.RawMessage(rotated), rotatedAt))

	stored, err = dao.GetByID(ctx, nil, created.ID)
	require.NoError(t, err)
	assert.JSONEq(t, rotated, string(stored.JWKSKeys))
	assert.WithinDuration(t, rotatedAt, *stored.JWKSFetchedAt, time.Millisecond)
}

func TestIssuerSQLDAO_UpdateJWKSCacheRejectsEmpty(t *testing.T) {
	ctx := context.Background()
	dbSession := testIssuerInitDB(t)
	defer dbSession.Close()
	testIssuerSetupSchema(t, dbSession)

	dao := NewIssuerDAO(dbSession)
	created := createTestIssuer(t, ctx, dbSession, dao)

	assert.Error(t, dao.UpdateJWKSCache(ctx, nil, created.ID, nil, time.Now().UTC()))
}

// TestIssuerSignatureIgnoresJWKSCache is the guard for the invariant that makes
// the whole cache viable. If the cached key set entered the signature, every
// refresh would read as a config change and every replica would rebuild its
// JwksConfig, discarding the keys it had just fetched.
func TestIssuerSignatureIgnoresJWKSCache(t *testing.T) {
	fetchedAt := time.Now().UTC()
	base := Issuer{
		ID:            uuid.New(),
		Origin:        "custom",
		IssuerURL:     "https://idp.acme.com",
		JWKSUrl:       "https://idp.acme.com/.well-known/jwks.json",
		JWKSTimeout:   "5s",
		Audiences:     []string{"api.acme.com"},
		Scopes:        []string{"carbide"},
		ClaimMappings: []ClaimMapping{{OrgName: "acme", Roles: []string{"TENANT_ADMIN"}}},
	}

	withKeys := base
	withKeys.JWKSKeys = json.RawMessage(testJWKSBlob)
	withKeys.JWKSFetchedAt = &fetchedAt

	assert.Equal(t, base.Signature(), withKeys.Signature(),
		"caching a key set must not look like a configuration change")

	// A real configuration change must still be detected.
	changed := base
	changed.JWKSUrl = "https://idp.acme.com/other/jwks.json"
	assert.NotEqual(t, base.Signature(), changed.Signature())
}
