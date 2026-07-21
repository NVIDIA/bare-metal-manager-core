// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"
)

func TestToolName(t *testing.T) {
	cases := []struct {
		operationID string
		want        string
	}{
		{"get-metadata", "nico_get_metadata"},
		{"get-all-site", "nico_get_all_site"},
		{"get-site-status-history", "nico_get_site_status_history"},
		{"get-current-tenant", "nico_get_current_tenant"},
		{"validate-rack", "nico_validate_rack"},
		{"validate-trays", "nico_validate_trays"},
		{"getFooStatus", "nico_get_foo_status"},
		{"GetAllSite", "nico_get_all_site"},
		{"get_already_snake", "nico_get_already_snake"},
	}
	for _, c := range cases {
		t.Run(c.operationID, func(t *testing.T) {
			require.Equal(t, c.want, toolName(c.operationID))
		})
	}
}

func TestToolDescription(t *testing.T) {
	t.Run("summary and description", func(t *testing.T) {
		op := &openapi3.Operation{
			OperationID: "get-foo",
			Summary:     "Retrieve Foo",
			Description: "More detail on Foo.",
		}
		require.Equal(t, "Retrieve Foo\n\nMore detail on Foo.", toolDescription(op))
	})
	t.Run("summary only", func(t *testing.T) {
		op := &openapi3.Operation{OperationID: "get-foo", Summary: "Retrieve Foo"}
		require.Equal(t, "Retrieve Foo", toolDescription(op))
	})
	t.Run("operationID fallback", func(t *testing.T) {
		op := &openapi3.Operation{OperationID: "get-foo"}
		require.Equal(t, "get-foo", toolDescription(op))
	})
}

func TestSameOrigin(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "same_origin", a: "https://example.com/a", b: "https://example.com/b", want: true},
		{name: "host_is_case_insensitive", a: "https://EXAMPLE.com/a", b: "https://example.com/b", want: true},
		{name: "implicit_and_explicit_default_port", a: "https://example.com/a", b: "https://example.com:443/b", want: true},
		{name: "different_scheme", a: "http://example.com/a", b: "https://example.com/b", want: false},
		{name: "different_host", a: "https://one.example.com/a", b: "https://two.example.com/b", want: false},
		{name: "different_effective_port", a: "https://example.com/a", b: "https://example.com:8443/b", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := url.Parse(tt.a)
			require.NoError(t, err)
			b, err := url.Parse(tt.b)
			require.NoError(t, err)
			require.Equal(t, tt.want, sameOrigin(a, b))
		})
	}
}

func TestSplitArgs(t *testing.T) {
	params := []*openapi3.Parameter{
		{Name: "org", In: "path"},
		{Name: "siteId", In: "path"},
		{Name: "pageNumber", In: "query"},
		{Name: "pageSize", In: "query"},
	}
	in := map[string]any{
		"siteId":     "abc-123",
		"pageNumber": float64(5),
		"pageSize":   float64(50),
		"org":        "should-not-appear-here",
		"token":      "should-be-ignored-by-splitArgs",
		"base_url":   "should-be-ignored",
		"unknown":    "ignored",
	}
	pathParams, queryParams, err := splitArgs(in, params)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"siteId": "abc-123"}, pathParams)
	require.Equal(t, map[string]string{"pageNumber": "5", "pageSize": "50"}, queryParams)
}

func TestSplitArgs_UnsupportedType(t *testing.T) {
	params := []*openapi3.Parameter{
		{Name: "tags", In: "query"},
	}
	in := map[string]any{
		"tags": []string{"a", "b"},
	}
	_, _, err := splitArgs(in, params)
	require.Error(t, err)
	require.Contains(t, err.Error(), "tags")
}

func TestCoerceToString(t *testing.T) {
	cases := []struct {
		name   string
		in     any
		want   string
		wantOK bool
	}{
		{"string", "foo", "foo", true},
		{"empty_string", "", "", true},
		{"int_as_float64", float64(42), "42", true},
		{"negative_int_as_float64", float64(-3), "-3", true},
		{"float_with_fraction", float64(3.14), "3.14", true},
		{"bool_true", true, "true", true},
		{"bool_false", false, "false", true},
		{"int", 7, "7", true},
		{"int64", int64(99), "99", true},
		{"json_number", json.Number("12345"), "12345", true},
		{"nil", nil, "", true},
		{"unsupported_slice", []int{1, 2}, "", false},
		{"unsupported_map", map[string]any{"a": 1}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := coerceToString(c.in)
			require.Equal(t, c.wantOK, ok)
			require.Equal(t, c.want, got)
		})
	}
}

func TestSortedPaths(t *testing.T) {
	paths := map[string]*openapi3.PathItem{
		"/z": {}, "/a": {}, "/m": {},
	}
	require.Equal(t, []string{"/a", "/m", "/z"}, sortedPaths(paths))
}

func TestPaginationMeta(t *testing.T) {
	t.Run("absent header is nil", func(t *testing.T) {
		require.Nil(t, paginationMeta(http.Header{}))
		require.Nil(t, paginationMeta(nil))
	})
	t.Run("json header parsed into structured fields", func(t *testing.T) {
		h := http.Header{"X-Pagination": []string{`{"pageNumber":1,"pageSize":50,"total":1234,"orderBy":null}`}}
		m := paginationMeta(h)
		require.NotNil(t, m)
		p, ok := m["pagination"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, float64(1234), p["total"])
		require.Equal(t, float64(1), p["pageNumber"])
	})
	t.Run("non-json header falls back to raw string", func(t *testing.T) {
		h := http.Header{"X-Pagination": []string{"weird-value"}}
		require.Equal(t, "weird-value", paginationMeta(h)["pagination"])
	})
}

func TestJSONResult_AttachesPagination(t *testing.T) {
	res := jsonResult([]byte(`[{"id":"a"}]`), http.Header{"X-Pagination": []string{`{"total":7}`}})
	require.Len(t, res.Content, 1)
	require.Equal(t, float64(7), res.Meta["pagination"].(map[string]any)["total"])

	// No pagination header -> no _meta attached.
	require.Nil(t, jsonResult([]byte(`[]`), http.Header{}).Meta)
}

// TestBuildServer_SyntheticSpec exercises BuildServer end-to-end on a
// hand-crafted YAML spec to assert tool registration does not panic and
// no error escapes for any combination of GET, POST, and parameterless
// path items. The downstream tool list is verified at the HTTP layer
// in transport_test.go.
func TestBuildServer_SyntheticSpec(t *testing.T) {
	specYAML := []byte(`
openapi: 3.0.0
info:
  title: Test
  version: 0.0.1
paths:
  /v2/org/{org}/nico/foo:
    parameters:
      - name: org
        in: path
        required: true
        schema: {type: string}
    get:
      operationId: get-all-foo
      summary: List foos
      parameters:
        - name: pageSize
          in: query
          schema: {type: integer}
  /v2/org/{org}/nico/foo/{fooId}:
    parameters:
      - name: org
        in: path
        required: true
        schema: {type: string}
      - name: fooId
        in: path
        required: true
        schema: {type: string}
    get:
      operationId: get-foo
      summary: Retrieve a foo
  /v2/org/{org}/nico/foo/{fooId}/status-history:
    parameters:
      - name: org
        in: path
        required: true
        schema: {type: string}
      - name: fooId
        in: path
        required: true
        schema: {type: string}
    get:
      operationId: get-foo-status-history
      summary: Foo status history
  /v2/org/{org}/nico/skip:
    parameters:
      - name: org
        in: path
        required: true
    post:
      operationId: create-skip
      summary: Excluded mutation
`)

	server, err := BuildServer(specYAML, Options{BaseURL: "http://example.test", Org: "demo"})
	require.NoError(t, err)
	require.NotNil(t, server)
}

func TestBuildServer_RejectsInvalidSpec(t *testing.T) {
	_, err := BuildServer([]byte("not: valid: yaml: ::"), Options{})
	require.Error(t, err)
}

func TestRegisterHandler_ValidPath(t *testing.T) {
	mux := http.NewServeMux()
	err := registerHandler(mux, "/mcp", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	require.NoError(t, err)
}

func TestRegisterHandler_InvalidPatternReturnsError(t *testing.T) {
	mux := http.NewServeMux()
	err := registerHandler(mux, "/{", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid --path")
}
