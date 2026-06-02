// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	otrace "go.opentelemetry.io/otel/trace"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	stracer "github.com/NVIDIA/infra-controller-rest/db/pkg/tracer"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	"github.com/google/uuid"
	"github.com/uptrace/bun/extra/bundebug"
)

func testDomainInitDB(t *testing.T) *db.Session {
	dbSession := util.GetTestDBSession(t, false)
	dbSession.DB.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv(""),
	))
	return dbSession
}

// reset the tables needed for Domain tests
func testDomainSetupSchema(t *testing.T, dbSession *db.Session) {
	// create user table
	err := dbSession.DB.ResetModel(context.Background(), (*User)(nil))
	assert.Nil(t, err)
	// create Domain table
	err = dbSession.DB.ResetModel(context.Background(), (*Domain)(nil))
	assert.Nil(t, err)
}

func testDomainBuildUser(t *testing.T, dbSession *db.Session, starfleetID string) *User {
	user := &User{
		ID:          uuid.New(),
		StarfleetID: db.GetStrPtr(starfleetID),
		Email:       db.GetStrPtr("jdoe@test.com"),
		FirstName:   db.GetStrPtr("John"),
		LastName:    db.GetStrPtr("Doe"),
	}
	_, err := dbSession.DB.NewInsert().Model(user).Exec(context.Background())
	assert.Nil(t, err)
	return user
}

func TestDomainSQLDAO_CreateFromParams(t *testing.T) {
	ctx := context.Background()
	dbSession := testDomainInitDB(t)
	defer dbSession.Close()
	testDomainSetupSchema(t, dbSession)
	user := testDomainBuildUser(t, dbSession, "testUser")
	controllerDomainID := uuid.New()

	dsd := NewDomainDAO(dbSession)
	tx1, err := db.BeginTx(context.Background(), dbSession, &sql.TxOptions{})
	assert.Nil(t, err)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		ds                 []Domain
		expectError        bool
		tx                 *db.Tx
		verifyChildSpanner bool
	}{
		{
			desc: "create one",
			ds: []Domain{
				{
					Hostname: "test.com", Org: "testOrg", ControllerDomainID: &controllerDomainID, Status: DomainStatusPending,
				},
			},
			expectError:        false,
			tx:                 nil,
			verifyChildSpanner: true,
		},
		{
			desc: "create multiple, some with null controllerDomainID field",
			ds: []Domain{
				{
					Hostname: "test1.com", Org: "testOrg1", ControllerDomainID: &controllerDomainID, Status: DomainStatusPending, CreatedBy: user.ID,
				},
				{
					Hostname: "test2.com", Org: "testOrg2", ControllerDomainID: nil, Status: DomainStatusPending, CreatedBy: user.ID,
				},
				{
					Hostname: "test3.com", Org: "testOrg3", ControllerDomainID: &controllerDomainID, Status: DomainStatusPending, CreatedBy: user.ID,
				},
			},
			expectError: false,
			tx:          nil,
		},
		{
			desc: "create multiple, within transaction",
			ds: []Domain{
				{
					Hostname: "test4.com", Org: "testOrg1", ControllerDomainID: &controllerDomainID, Status: DomainStatusPending, CreatedBy: user.ID,
				},
				{
					Hostname: "test5.com", Org: "testOrg2", ControllerDomainID: nil, Status: DomainStatusPending, CreatedBy: user.ID,
				},
				{
					Hostname: "test6.com", Org: "testOrg3", ControllerDomainID: &controllerDomainID, Status: DomainStatusPending, CreatedBy: user.ID,
				},
			},
			expectError: false,
			tx:          tx1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			for _, i := range tc.ds {
				d, err := dsd.CreateFromParams(
					ctx, tc.tx, i.Hostname, i.Org, i.ControllerDomainID, i.Status, i.CreatedBy,
				)
				assert.Equal(t, tc.expectError, err != nil)
				if !tc.expectError {
					assert.NotNil(t, d)
				}
			}
			if tc.tx != nil {
				tc.tx.Commit()
			}

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestDomainSQLDAO_GetByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testDomainInitDB(t)
	defer dbSession.Close()
	testDomainSetupSchema(t, dbSession)
	user := testDomainBuildUser(t, dbSession, "testUser")
	controllerDomainID := uuid.New()

	dsd := NewDomainDAO(dbSession)
	domain1, err := dsd.CreateFromParams(ctx, nil, "test.com", "testOrg", &controllerDomainID, DomainStatusPending, user.ID)
	assert.Nil(t, err)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		id                 uuid.UUID
		expectedDomain     *Domain
		expectedError      bool
		expectedErrVal     error
		verifyChildSpanner bool
	}{
		{
			desc:               "GetByID success when found",
			id:                 domain1.ID,
			expectedDomain:     domain1,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:           "GetByID error when not found",
			id:             uuid.New(),
			expectedDomain: nil,
			expectedError:  true,
			expectedErrVal: db.ErrDoesNotExist,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := dsd.GetByID(ctx, nil, tc.id, nil)
			assert.Equal(t, tc.expectedError, err != nil)
			if !tc.expectedError {
				assert.Equal(t, tc.expectedDomain.ID, got.ID)
				assert.Equal(t, tc.expectedDomain.Hostname, got.Hostname)
			} else {
				assert.Equal(t, tc.expectedErrVal, err)
				assert.Nil(t, got)
			}
			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestDomainSQLDAO_GetAll(t *testing.T) {
	ctx := context.Background()
	dbSession := testDomainInitDB(t)
	defer dbSession.Close()
	testDomainSetupSchema(t, dbSession)
	user := testDomainBuildUser(t, dbSession, "testUser")
	controllerDomainID := uuid.New()

	dsd := NewDomainDAO(dbSession)
	domain1, err := dsd.CreateFromParams(ctx, nil, "test1.com", "testOrg1", &controllerDomainID, DomainStatusPending, user.ID)
	assert.Nil(t, err)
	assert.NotNil(t, domain1)
	domain2, err := dsd.CreateFromParams(ctx, nil, "test1.com", "testOrg2", &controllerDomainID, DomainStatusPending, user.ID)
	assert.Nil(t, err)
	assert.NotNil(t, domain2)
	domain3, err := dsd.CreateFromParams(ctx, nil, "test2.com", "testOrg2", &controllerDomainID, DomainStatusPending, user.ID)
	assert.Nil(t, err)
	assert.NotNil(t, domain3)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		hostname           *string
		org                *string
		controllerDomainID *uuid.UUID
		status             *string
		expectedCnt        int
		expectedError      bool
		verifyChildSpanner bool
	}{
		{
			desc:               "GetAll with no filters returns objects",
			hostname:           nil,
			org:                nil,
			controllerDomainID: nil,
			expectedCnt:        3,
			expectedError:      false,
			verifyChildSpanner: true,
		},
		{
			desc:               "GetAll with hostname filter returns objects",
			hostname:           db.GetStrPtr("test1.com"),
			org:                nil,
			controllerDomainID: nil,
			expectedCnt:        2,
			expectedError:      false,
		},
		{
			desc:               "GetAll with org filter returns objects",
			hostname:           nil,
			org:                db.GetStrPtr("testOrg2"),
			controllerDomainID: nil,
			expectedCnt:        2,
			expectedError:      false,
		},
		{
			desc:               "GetAll with controllerDomainID filter returns objects",
			hostname:           nil,
			org:                nil,
			controllerDomainID: &controllerDomainID,
			expectedCnt:        3,
			expectedError:      false,
		},
		{
			desc:               "GetAll with multiple filters returns objects",
			hostname:           db.GetStrPtr("test1.com"),
			org:                db.GetStrPtr("testOrg1"),
			controllerDomainID: &controllerDomainID,
			expectedCnt:        1,
			expectedError:      false,
		},
		{
			desc:               "GetAll with multiple filters returns no objects",
			hostname:           db.GetStrPtr("notfound.com"),
			org:                db.GetStrPtr("testOrg1"),
			controllerDomainID: &controllerDomainID,
			expectedCnt:        0,
			expectedError:      false,
		},
		{
			desc:               "GetAll with DomainStatusPending status returns objects",
			hostname:           nil,
			org:                nil,
			controllerDomainID: nil,
			expectedCnt:        3,
			status:             db.GetStrPtr(DomainStatusPending),
			expectedError:      false,
		},
		{
			desc:               "GetAll with DomainStatusError status returns no objects",
			hostname:           nil,
			org:                nil,
			controllerDomainID: nil,
			expectedCnt:        0,
			status:             db.GetStrPtr(DomainStatusError),
			expectedError:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			tmp, err := dsd.GetAll(ctx, nil, tc.hostname, tc.org, tc.controllerDomainID, tc.status, nil)
			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				assert.Equal(t, nil, tmp)
			} else {
				assert.Equal(t, tc.expectedCnt, len(tmp))
			}

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestDomainSQLDAO_UpdateFromParams(t *testing.T) {
	ctx := context.Background()
	dbSession := testDomainInitDB(t)
	defer dbSession.Close()
	testDomainSetupSchema(t, dbSession)
	user := testDomainBuildUser(t, dbSession, "testUser")
	controllerDomainID := uuid.New()
	updatedControllerDomainID := uuid.New()
	dsd := NewDomainDAO(dbSession)
	domain, err := dsd.CreateFromParams(ctx, nil, "test.com", "testOrg", &controllerDomainID, DomainStatusPending, user.ID)
	assert.Nil(t, err)
	domain2, err := dsd.CreateFromParams(ctx, nil, "test2.com", "testOrg2", &controllerDomainID, DomainStatusPending, user.ID)
	assert.Nil(t, err)
	tx1, err := db.BeginTx(context.Background(), dbSession, &sql.TxOptions{})
	assert.Nil(t, err)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc string
		id   uuid.UUID

		paramDomain             *Domain
		paramHostname           *string
		paramOrg                *string
		paramControllerDomainID *uuid.UUID
		paramStatus             *string

		expectedError              bool
		expectedHostname           *string
		expectedOrg                *string
		expectedControllerDomainID *uuid.UUID
		expectedStatus             *string
		tx                         *db.Tx
		verifyChildSpanner         bool
	}{
		{
			desc:                       "can update hostname",
			id:                         domain.ID,
			paramDomain:                domain,
			paramHostname:              db.GetStrPtr("updated.com"),
			paramOrg:                   nil,
			paramControllerDomainID:    nil,
			paramStatus:                nil,
			expectedError:              false,
			expectedHostname:           db.GetStrPtr("updated.com"),
			expectedOrg:                &domain.Org,
			expectedControllerDomainID: domain.ControllerDomainID,
			expectedStatus:             &domain.Status,
			verifyChildSpanner:         true,
		},
		{
			desc:                       "error when updating object doesnt exist",
			id:                         uuid.New(),
			paramDomain:                domain,
			paramHostname:              db.GetStrPtr("updated.com"),
			paramOrg:                   nil,
			paramControllerDomainID:    nil,
			paramStatus:                nil,
			expectedError:              true,
			expectedHostname:           db.GetStrPtr("updated.com"),
			expectedOrg:                &domain.Org,
			expectedControllerDomainID: domain.ControllerDomainID,
			expectedStatus:             &domain.Status,
		},
		{
			desc:                       "can update org",
			id:                         domain.ID,
			paramDomain:                domain,
			paramHostname:              nil,
			paramOrg:                   db.GetStrPtr("updatedOrg"),
			paramControllerDomainID:    nil,
			paramStatus:                nil,
			expectedError:              false,
			expectedHostname:           db.GetStrPtr("updated.com"),
			expectedOrg:                db.GetStrPtr("updatedOrg"),
			expectedControllerDomainID: domain.ControllerDomainID,
			expectedStatus:             &domain.Status,
		},
		{
			desc:                       "can update controllerDomainID",
			id:                         domain.ID,
			paramDomain:                domain,
			paramHostname:              nil,
			paramOrg:                   nil,
			paramControllerDomainID:    &updatedControllerDomainID,
			paramStatus:                nil,
			expectedError:              false,
			expectedHostname:           db.GetStrPtr("updated.com"),
			expectedOrg:                db.GetStrPtr("updatedOrg"),
			expectedControllerDomainID: &updatedControllerDomainID,
			expectedStatus:             &domain.Status,
		},
		{
			desc:                       "can update status",
			id:                         domain.ID,
			paramDomain:                domain,
			paramHostname:              nil,
			paramOrg:                   nil,
			paramControllerDomainID:    nil,
			paramStatus:                db.GetStrPtr(DomainStatusReady),
			expectedError:              false,
			expectedHostname:           db.GetStrPtr("updated.com"),
			expectedOrg:                db.GetStrPtr("updatedOrg"),
			expectedControllerDomainID: &updatedControllerDomainID,
			expectedStatus:             db.GetStrPtr(DomainStatusReady),
		},
		{
			desc:                       "can update multiple fields",
			id:                         domain2.ID,
			paramDomain:                domain2,
			paramHostname:              db.GetStrPtr("updated.com"),
			paramOrg:                   db.GetStrPtr("updatedOrg"),
			paramControllerDomainID:    &updatedControllerDomainID,
			paramStatus:                db.GetStrPtr(DomainStatusReady),
			expectedError:              false,
			expectedHostname:           db.GetStrPtr("updated.com"),
			expectedOrg:                db.GetStrPtr("updatedOrg"),
			expectedControllerDomainID: &updatedControllerDomainID,
			expectedStatus:             db.GetStrPtr(DomainStatusReady),
			tx:                         tx1,
		},
		{
			desc:                       "noop when no fields are specified",
			id:                         domain2.ID,
			paramDomain:                domain2,
			paramHostname:              nil,
			paramOrg:                   nil,
			paramControllerDomainID:    nil,
			paramStatus:                nil,
			expectedError:              false,
			expectedHostname:           db.GetStrPtr("updated.com"),
			expectedOrg:                db.GetStrPtr("updatedOrg"),
			expectedControllerDomainID: &updatedControllerDomainID,
			expectedStatus:             db.GetStrPtr(DomainStatusReady),
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := dsd.UpdateFromParams(ctx, tc.tx, tc.id, tc.paramHostname, tc.paramOrg, tc.paramControllerDomainID, tc.paramStatus)
			assert.Equal(t, tc.expectedError, err != nil)
			if err == nil {
				assert.NotNil(t, got)

				assert.Equal(t, *tc.expectedHostname, got.Hostname)
				assert.Equal(t, *tc.expectedOrg, got.Org)

				assert.Equal(t, tc.expectedControllerDomainID == nil, got.ControllerDomainID == nil)
				if tc.expectedControllerDomainID != nil {
					assert.Equal(t, *tc.expectedControllerDomainID, *got.ControllerDomainID)
				}

				if got.Updated.String() == tc.paramDomain.Updated.String() {
					t.Errorf("got.Updated = %v, want different value", got.Updated)
				}

			}
			if tc.tx != nil {
				assert.Nil(t, tc.tx.Commit())
			}

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestDomainSQLDAO_ClearFromParams(t *testing.T) {
	ctx := context.Background()
	dbSession := testDomainInitDB(t)
	defer dbSession.Close()
	testDomainSetupSchema(t, dbSession)
	user := testDomainBuildUser(t, dbSession, "testUser")
	controllerDomainID := uuid.New()
	dsd := NewDomainDAO(dbSession)
	domain, err := dsd.CreateFromParams(ctx, nil, "test.com", "testOrg", &controllerDomainID, DomainStatusPending, user.ID)
	assert.Nil(t, err)
	domain2, err := dsd.CreateFromParams(ctx, nil, "test.com", "testOrg", &controllerDomainID, DomainStatusPending, user.ID)
	assert.Nil(t, err)
	tx1, err := db.BeginTx(context.Background(), dbSession, &sql.TxOptions{})
	assert.Nil(t, err)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc   string
		domain *Domain

		paramControllerDomainID    bool
		expectedUpdate             bool
		expectedError              bool
		expectedControllerDomainID *uuid.UUID
		tx                         *db.Tx
		verifyChildSpanner         bool
	}{
		{
			desc:                       "can clear controllerDomainID",
			domain:                     domain,
			paramControllerDomainID:    true,
			expectedUpdate:             true,
			expectedError:              false,
			expectedControllerDomainID: nil,
			tx:                         tx1,
			verifyChildSpanner:         true,
		},
		{
			desc:                       "can clear controllerDomainID when it is already nil",
			domain:                     domain,
			paramControllerDomainID:    true,
			expectedUpdate:             true,
			expectedError:              false,
			expectedControllerDomainID: nil,
		},
		{
			desc:                       "noop when nothing cleared",
			domain:                     domain2,
			paramControllerDomainID:    false,
			expectedUpdate:             false,
			expectedError:              false,
			expectedControllerDomainID: domain2.ControllerDomainID,
		},
		{
			desc:                       "error when updating object doesnt exist",
			domain:                     &Domain{ID: uuid.New()},
			paramControllerDomainID:    true,
			expectedError:              true,
			expectedControllerDomainID: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := dsd.ClearFromParams(ctx, tc.tx, tc.domain.ID, tc.paramControllerDomainID)
			assert.Equal(t, tc.expectedError, err != nil)
			if err == nil {
				assert.NotNil(t, got)
				assert.Equal(t, tc.expectedControllerDomainID == nil, got.ControllerDomainID == nil)
				if tc.expectedControllerDomainID != nil {
					assert.Equal(t, *tc.expectedControllerDomainID, *got.ControllerDomainID)
				}
				if tc.expectedUpdate {
					assert.True(t, got.Updated.After(tc.domain.Updated))
				}
			}
			if tc.tx != nil {
				assert.Nil(t, tc.tx.Commit())
			}

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}

func TestDomainSQLDAO_DeleteByID(t *testing.T) {
	ctx := context.Background()
	dbSession := testDomainInitDB(t)
	defer dbSession.Close()
	testDomainSetupSchema(t, dbSession)
	user := testDomainBuildUser(t, dbSession, "testUser")
	controllerDomainID := uuid.New()
	dsd := NewDomainDAO(dbSession)
	domain, err := dsd.CreateFromParams(ctx, nil, "test.com", "testOrg", &controllerDomainID, DomainStatusPending, user.ID)
	assert.Nil(t, err)
	tx1, err := db.BeginTx(context.Background(), dbSession, &sql.TxOptions{})
	assert.Nil(t, err)

	// OTEL Spanner configuration
	_, _, ctx = testCommonTraceProviderSetup(t, ctx)

	tests := []struct {
		desc               string
		id                 uuid.UUID
		expectedError      bool
		tx                 *db.Tx
		verifyChildSpanner bool
	}{
		{
			desc:               "can delete existing object",
			id:                 domain.ID,
			expectedError:      false,
			tx:                 tx1,
			verifyChildSpanner: true,
		},
		{
			desc:          "delete non-existing object",
			id:            uuid.New(),
			expectedError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := dsd.DeleteByID(ctx, tc.tx, tc.id)
			assert.Equal(t, tc.expectedError, err != nil)
			if !tc.expectedError {
				tmp, err := dsd.GetByID(ctx, tc.tx, tc.id, nil)
				assert.NotNil(t, err)
				assert.Nil(t, tmp)
			}
			if tc.tx != nil {
				assert.Nil(t, tc.tx.Commit())
			}

			if tc.verifyChildSpanner {
				span := otrace.SpanFromContext(ctx)
				assert.True(t, span.SpanContext().IsValid())
				_, ok := ctx.Value(stracer.TracerKey).(otrace.Tracer)
				assert.True(t, ok)
			}
		})
	}
}
