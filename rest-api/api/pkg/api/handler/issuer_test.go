// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	authz "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/otelecho"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testIssuerConfig builds a Config from an in-memory issuers block, so a test
// controls the static configuration the handlers gate on.
func testIssuerConfig(t *testing.T, yamlDoc string) *config.Config {
	t.Helper()
	cfg, err := config.NewConfigFromYAML(yamlDoc)
	require.NoError(t, err)
	return cfg
}

// customOnlyIssuerConfig is a Config with no privileged and no dynamic static
// issuers, so the runtime issuer API is available.
func customOnlyIssuerConfig(t *testing.T) *config.Config {
	t.Helper()
	return testIssuerConfig(t, `
keycloak:
  enabled: false
issuers: []
env:
  disconnected: true
`)
}

// testIssuerFixture is the Provider Admin caller used by Issuer handler tests.
type testIssuerFixture struct {
	org       string
	user      *cdbm.User
	dbSession *cdb.Session
	cfg       *config.Config
}

func testIssuerSetup(t *testing.T, cfg *config.Config) testIssuerFixture {
	t.Helper()

	dbSession := common.TestInitDB(t)
	t.Cleanup(dbSession.Close)
	common.TestSetupSchema(t, dbSession)
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Issuer)(nil)))

	org := "issuer-test-org"
	user := common.TestBuildUser(t, dbSession, "issuer-test-starfleet-id", org, []string{authz.ProviderAdminRole})

	return testIssuerFixture{org: org, user: user, dbSession: dbSession, cfg: cfg}
}

// request invokes an Issuer handler as the fixture's Provider Admin.
func (f testIssuerFixture) request(t *testing.T, handler echo.HandlerFunc, method, issuerID, body string) *httptest.ResponseRecorder {
	t.Helper()

	e := echo.New()
	req := httptest.NewRequest(method, "/v2/org/"+f.org+"/nico/issuer", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ec := e.NewContext(req, rec)
	ec.SetParamNames("orgName", "issuerId")
	ec.SetParamValues(f.org, issuerID)
	ec.Set("user", f.user)

	require.NoError(t, handler(ec))
	return rec
}

// createIssuerRequest is a create body with a single static org claim mapping.
func createIssuerRequest(name, issuerURL, orgName string) string {
	return fmt.Sprintf(`{"name":%q,"issuerUrl":%q,"jwksUrl":%q,"claimMappings":[{"orgName":%q,"roles":[%q]}]}`,
		name, issuerURL, issuerURL+"/jwks", orgName, authz.TenantAdminRole)
}

// createIssuer creates an Issuer through the API and returns the response body.
func (f testIssuerFixture) createIssuer(t *testing.T, name, issuerURL, orgName string) model.APIIssuer {
	t.Helper()

	rec := f.request(t, NewCreateIssuerHandler(f.dbSession, f.cfg).Handle, http.MethodPut, "",
		createIssuerRequest(name, issuerURL, orgName))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	apiIssuer := model.APIIssuer{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiIssuer))
	return apiIssuer
}

// TestIssuerHandler_TenantAdminForbidden verifies the provider-admin gate: a
// Tenant Admin (org member, but not Provider Admin) is rejected with 403 before
// any DB access, so issuer management is provider-only.
func TestIssuerHandler_TenantAdminForbidden(t *testing.T) {
	ctx := context.Background()
	tracer, _, ctx := common.TestCommonTraceProviderSetup(t, ctx)

	org := "acme-org"
	user := &cdbm.User{
		ID:          uuid.New(),
		AuxiliaryID: cutil.GetPtr("aux-tenant-admin"),
		OrgData: cdbm.OrgData{
			org: cdbm.Org{Name: org, Roles: []string{authz.TenantAdminRole}},
		},
	}

	// dbSession is never touched on the 403 path (the gate rejects first).
	h := NewCreateIssuerHandler(&cdb.Session{}, customOnlyIssuerConfig(t))

	e := echo.New()
	body := `{"name":"acme-idp","issuerUrl":"https://idp.acme.com"}`
	req := httptest.NewRequest(http.MethodPut, "/v2/org/"+org+"/nico/issuer", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ec := e.NewContext(req, rec)
	ec.SetParamNames("orgName")
	ec.SetParamValues(org)
	ec.Set("user", user)

	ctx = context.WithValue(ctx, otelecho.TracerKey, tracer)
	ec.SetRequest(ec.Request().WithContext(ctx))

	err := h.Handle(ec)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCreateIssuerRejectsPrivilegedStaticOrigins(t *testing.T) {
	f := testIssuerSetup(t, testIssuerConfig(t, `
env:
  disconnected: true
issuers:
  - name: kas
    origin: kas-legacy
    jwks: https://authn.example.com/jwks
    issuer: authn.example.com
`))

	rec := f.request(t, NewCreateIssuerHandler(f.dbSession, f.cfg).Handle, http.MethodPut, "",
		createIssuerRequest("custom-idp", "https://idp.acme.com", "acme"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "kas-legacy")
}

// TestIssuerAPIUnavailableWithDynamicConfigMapIssuers verifies that a dynamic
// ConfigMap issuer disables the whole API, reads included.
func TestIssuerAPIUnavailableWithDynamicConfigMapIssuers(t *testing.T) {
	f := testIssuerSetup(t, testIssuerConfig(t, `
env:
  disconnected: true
issuers:
  - name: dyn
    origin: custom
    jwks: https://dyn.example.com/jwks
    issuer: https://dyn.example.com
    claimMappings:
      - orgAttribute: org
        rolesAttribute: roles
`))

	createRec := f.request(t, NewCreateIssuerHandler(f.dbSession, f.cfg).Handle, http.MethodPut, "",
		createIssuerRequest("static-custom", "https://static.example.com", "acme"))
	assert.Equal(t, http.StatusBadRequest, createRec.Code)
	assert.Contains(t, createRec.Body.String(), "dynamic issuer")

	getAllRec := f.request(t, NewGetAllIssuerHandler(f.dbSession, f.cfg).Handle, http.MethodGet, "", "")
	assert.Equal(t, http.StatusBadRequest, getAllRec.Code)
	assert.Contains(t, getAllRec.Body.String(), "dynamic issuer")
}

func TestCreateIssuerRejectsDynamicClaimMappings(t *testing.T) {
	f := testIssuerSetup(t, customOnlyIssuerConfig(t))

	body := `{"name":"dyn-attempt","issuerUrl":"https://dyn-attempt.example.com","claimMappings":[{"orgName":"acme","rolesAttribute":"roles"}]}`
	rec := f.request(t, NewCreateIssuerHandler(f.dbSession, f.cfg).Handle, http.MethodPut, "", body)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "rolesAttribute")
}

// TestCreateIssuerForcesCustomOrigin verifies that an origin supplied in the
// request body cannot select a privileged token processor.
func TestCreateIssuerForcesCustomOrigin(t *testing.T) {
	f := testIssuerSetup(t, customOnlyIssuerConfig(t))

	body := fmt.Sprintf(`{"name":"forced-custom","issuerUrl":"https://forced-custom.example.com","origin":%q}`, cauth.TokenOriginKeycloak)
	rec := f.request(t, NewCreateIssuerHandler(f.dbSession, f.cfg).Handle, http.MethodPut, "", body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	apiIssuer := model.APIIssuer{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiIssuer))
	assert.Equal(t, cauth.TokenOriginCustom, apiIssuer.Origin)
}

func TestCreateIssuerSerializesCombinedValidation(t *testing.T) {
	f := testIssuerSetup(t, customOnlyIssuerConfig(t))

	orgName := "concurrent-create-" + uuid.NewString()
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)

	for i, issuerURL := range []string{"https://create-a.example.com", "https://create-b.example.com"} {
		go func(i int, issuerURL string) {
			<-start
			results <- f.request(t, NewCreateIssuerHandler(f.dbSession, f.cfg).Handle, http.MethodPut, "",
				createIssuerRequest(fmt.Sprintf("concurrent-create-%d", i), issuerURL, orgName))
		}(i, issuerURL)
	}
	close(start)

	assertOneIssuerMutationConflict(t, http.StatusCreated, <-results, <-results)
	issuers, err := cdbm.NewIssuerDAO(f.dbSession).GetAll(context.Background(), nil, cdbm.IssuerFilterInput{})
	require.NoError(t, err)
	assert.Len(t, issuers, 1)
}

func TestDeleteIssuerSerializesWithConflictingCreate(t *testing.T) {
	f := testIssuerSetup(t, customOnlyIssuerConfig(t))

	orgName := "concurrent-delete-" + uuid.NewString()
	existing := f.createIssuer(t, "concurrent-delete-existing", "https://delete-existing.example.com", orgName)

	start := make(chan struct{})
	deleteResult := make(chan *httptest.ResponseRecorder, 1)
	createResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		<-start
		deleteResult <- f.request(t, NewDeleteIssuerHandler(f.dbSession, f.cfg).Handle, http.MethodDelete, existing.ID, "")
	}()
	go func() {
		<-start
		createResult <- f.request(t, NewCreateIssuerHandler(f.dbSession, f.cfg).Handle, http.MethodPut, "",
			createIssuerRequest("concurrent-delete-replacement", "https://delete-replacement.example.com", orgName))
	}()
	close(start)

	deleteRec := <-deleteResult
	require.Equal(t, http.StatusOK, deleteRec.Code, deleteRec.Body.String())

	// The create either lands after the delete (201) or is rejected because the
	// org name is still claimed by the Issuer being deleted.
	createRec := <-createResult
	if createRec.Code != http.StatusCreated {
		assert.Equal(t, http.StatusBadRequest, createRec.Code)
		assert.Contains(t, createRec.Body.String(), "duplicate org name")
	}

	issuers, err := cdbm.NewIssuerDAO(f.dbSession).GetAll(context.Background(), nil, cdbm.IssuerFilterInput{})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(issuers), 1)
}

// assertOneIssuerMutationConflict asserts that exactly one of two concurrent
// mutations succeeded and the other was rejected for claiming the same static
// org name, which is what the issuer organization-mapping lock guarantees.
func assertOneIssuerMutationConflict(t *testing.T, successCode int, recs ...*httptest.ResponseRecorder) {
	t.Helper()
	successes := 0
	conflicts := 0
	for _, rec := range recs {
		if rec.Code == successCode {
			successes++
			continue
		}
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "duplicate org name")
		conflicts++
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, 1, conflicts)
}
