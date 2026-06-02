// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"

	"github.com/NVIDIA/infra-controller-rest/api/internal/config"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	_ "github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller-rest/api/pkg/client/site"
	cconfig "github.com/NVIDIA/infra-controller-rest/common/pkg/config"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cdbu "github.com/NVIDIA/infra-controller-rest/db/pkg/util"
	echo "github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	temporalClient "go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
)

func Test_InitAPIServer(t *testing.T) {
	type args struct {
		cfg       *config.Config
		dbSession *cdb.Session
		tc        temporalClient.Client
		tnc       temporalClient.NamespaceClient
		scp       *sc.ClientPool
	}

	cfg := common.GetTestConfig()

	dbSession := cdbu.GetTestDBSession(t, true)
	defer dbSession.Close()

	tc := &tmocks.Client{}
	tnc := &tmocks.NamespaceClient{}

	tcfg, _ := cfg.GetTemporalConfig()

	scp := sc.NewClientPool(tcfg)

	t.Setenv("SENTRY_DSN", "https://bfe69b59461e44059a533274a6393155@glitchtip.test.com/3")

	tests := []struct {
		name string
		args args
		want *echo.Echo
	}{
		{
			name: "test initAPIServer success",
			args: args{
				cfg:       cfg,
				dbSession: dbSession,
				tc:        tc,
				tnc:       tnc,
				scp:       scp,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			InitAPIServer(tt.args.cfg, tt.args.dbSession, tt.args.tc, tt.args.tnc, tt.args.scp)
		})
	}
}

func Test_InitTemporalClients(t *testing.T) {
	keyPath, certPath := config.SetupTestCerts(t)
	defer os.Remove(keyPath)
	defer os.Remove(certPath)

	cfg := common.GetTestConfig()
	cfg.SetTemporalCertPath(certPath)
	cfg.SetTemporalKeyPath(keyPath)
	cfg.SetTemporalCaPath(certPath)

	tcfg, err := cfg.GetTemporalConfig()
	assert.NoError(t, err)
	defer cfg.Close()

	type args struct {
		tConfig *cconfig.TemporalConfig
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "test initTemporalClient success",
			args: args{
				tConfig: tcfg,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			InitTemporalClients(tt.args.tConfig, true)
		})
	}
}

func Test_InitMetricsServer(t *testing.T) {
	type args struct {
		e   *echo.Echo
		cfg *config.Config
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test initMetricsServer success",
			args: args{
				e:   echo.New(),
				cfg: common.GetTestConfig(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			InitMetricsServer(tt.args.e, tt.args.cfg)
		})
	}
}

func testAuditSetupSchema(t *testing.T, dbSession *cdb.Session) {
	err := dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil))
	assert.Nil(t, err)
	err = dbSession.DB.ResetModel(context.Background(), (*cdbm.AuditEntry)(nil))
	assert.Nil(t, err)
}

func Test_Audit(t *testing.T) {
	cfg := common.GetTestConfig()

	dbSession := cdbu.GetTestDBSession(t, true)
	defer dbSession.Close()
	testAuditSetupSchema(t, dbSession)

	tc := &tmocks.Client{}
	tnc := &tmocks.NamespaceClient{}

	tcfg, _ := cfg.GetTemporalConfig()

	scp := sc.NewClientPool(tcfg)

	t.Setenv("SENTRY_DSN", "https://bfe69b59461e44059a533274a6393155@glitchtip.test.com/3")

	srv := InitAPIServer(cfg, dbSession, tc, tnc, scp)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/org/wdksahew1rqv/%s/site", cfg.GetAPIRouteVersion(), cfg.GetAPIName()), nil)
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	// check if the audit log entry was created
	aeDAO := cdbm.NewAuditEntryDAO(dbSession)
	entries, count, err := aeDAO.GetAll(context.Background(), nil, cdbm.AuditEntryFilterInput{OrgName: cdb.GetStrPtr("wdksahew1rqv")}, paginator.PageInput{})
	assert.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, count, 1)
	assert.Equal(t, entries[0].OrgName, "wdksahew1rqv")
	assert.Equal(t, entries[0].StatusCode, 401)
}

func Test_BodyLimit(t *testing.T) {
	cfg := common.GetTestConfig()
	dbSession := cdbu.GetTestDBSession(t, true)
	defer dbSession.Close()

	tc := &tmocks.Client{}
	tnc := &tmocks.NamespaceClient{}

	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	srv := InitAPIServer(cfg, dbSession, tc, tnc, scp)

	oversizedBody := make([]byte, 11<<20) // 11 MiB, exceeds the 10 MiB limit
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/org/test-org/%s/site", cfg.GetAPIRouteVersion(), cfg.GetAPIName()), bytes.NewReader(oversizedBody))
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

	normalBody := []byte(`{"name":"test"}`)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/org/test-org/%s/site", cfg.GetAPIRouteVersion(), cfg.GetAPIName()), bytes.NewReader(normalBody))
	req2.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec2, req2)
	assert.NotEqual(t, http.StatusRequestEntityTooLarge, rec2.Code)
}

func Test_NotFoundHandler(t *testing.T) {
	cfg := common.GetTestConfig()
	dbSession := cdbu.GetTestDBSession(t, true)
	defer dbSession.Close()

	tc := &tmocks.Client{}
	tnc := &tmocks.NamespaceClient{}

	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	srv := InitAPIServer(cfg, dbSession, tc, tnc, scp)
	rec := httptest.NewRecorder()

	// Arbitrary path that should return 404
	req := httptest.NewRequest(http.MethodGet, "/test/notfound", nil)
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Valid route should match but return unauthorized since no auth token is provided
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s/org/test-org/%s/metadata", cfg.GetAPIRouteVersion(), cfg.GetAPIName()), nil)
	srv.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code)
}
