// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSitePrerequisiteManifestValidation(t *testing.T) {
	valid := `
apiVersion: nico.nvidia.com/v1alpha1
kind: SitePrerequisites
provider:
  org: provider-org
tenant:
  org: tenant-org
site:
  request:
    name: test-site
`

	tests := []struct {
		name      string
		manifest  string
		errString string
	}{
		{name: "valid", manifest: valid},
		{name: "wrong api version", manifest: strings.Replace(valid, sitePrerequisiteAPIVersion, "v1", 1), errString: "apiVersion must be"},
		{name: "wrong kind", manifest: strings.Replace(valid, sitePrerequisiteKind, "Site", 1), errString: "kind must be"},
		{name: "tenant org required", manifest: strings.Replace(valid, "tenant-org", "", 1), errString: "tenant.org is required"},
		{name: "site required", manifest: strings.Replace(valid, "site:\n  request:\n    name: test-site\n", "", 1), errString: "site is required"},
		{name: "resource name required", manifest: strings.Replace(valid, "name: test-site", "description: missing-name", 1), errString: "site.request.name is required"},
		{name: "unknown field", manifest: valid + "unknown: true\n", errString: "field unknown not found"},
		{name: "multiple documents", manifest: valid + "---\n{}\n", errString: "multiple YAML documents"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, err := readSitePrerequisiteManifest("-", strings.NewReader(test.manifest))
			if test.errString == "" {
				require.NoError(t, err)
				assert.Equal(t, "test-site", manifest.Site.Request["name"])
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errString)
		})
	}
}

func TestSitePrerequisiteExampleManifestParses(t *testing.T) {
	manifest, err := readSitePrerequisiteManifest("../examples/site-prerequisites.yaml", nil)
	require.NoError(t, err)
	assert.Equal(t, "sjc4", manifest.Site.Request["name"])
	assert.Contains(t, manifest.Instances, "worker")
}

func TestResolveBootstrapValue(t *testing.T) {
	context := map[string]any{
		"site": map[string]any{"id": "site-1"},
		"allocations": map[string]any{
			"network": map[string]any{
				"allocationConstraints": []any{
					map[string]any{"derivedResourceId": "ipblock-derived-1"},
				},
			},
		},
	}

	tests := []struct {
		name      string
		input     any
		expected  any
		errString string
	}{
		{name: "whole value", input: "${site.id}", expected: "site-1"},
		{name: "embedded value", input: "site-${site.id}", expected: "site-site-1"},
		{name: "array traversal", input: "${allocations.network.allocationConstraints.0.derivedResourceId}", expected: "ipblock-derived-1"},
		{name: "nested object", input: map[string]any{"siteId": "${site.id}"}, expected: map[string]any{"siteId": "site-1"}},
		{name: "missing reference", input: "${vpcs.default.id}", errString: "does not exist"},
		{name: "invalid array index", input: "${allocations.network.allocationConstraints.4.derivedResourceId}", errString: "does not exist"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := resolveBootstrapValue(test.input, context)
			if test.errString == "" {
				require.NoError(t, err)
				assert.Equal(t, test.expected, actual)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errString)
		})
	}
}

func TestBootstrapSitePrerequisitesCreatesAndReusesResources(t *testing.T) {
	api := newBootstrapTestAPI()
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

	manifest := completeBootstrapTestManifest()
	client := NewClient(server.URL, "original-org", "token", nil, false)
	var progress bytes.Buffer

	require.NoError(t, bootstrapSitePrerequisites(client, manifest, &progress))
	assert.Equal(t, "original-org", client.Org)
	assert.Equal(t, []string{
		"provider-org/site",
		"provider-org/ipblock",
		"provider-org/instance/type",
		"provider-org/allocation",
		"tenant-org/vpc",
		"tenant-org/vpc-prefix",
		"tenant-org/instance",
	}, api.postOrder)
	assert.Equal(t, "provider-id", manifest.Provider.ID)
	assert.Equal(t, "tenant-id", manifest.Tenant.ID)
	assert.Equal(t, "site-1", manifest.Site.ID)
	assert.Equal(t, "ipblock-1", manifest.IPBlocks["fabric"].ID)
	assert.Equal(t, "instance-type-1", manifest.InstanceTypes["compute"].ID)
	assert.Equal(t, "allocation-1", manifest.Allocations["network"].ID)
	assert.Equal(t, "vpc-1", manifest.VPCs["tenant"].ID)
	assert.Equal(t, "vpc-prefix-1", manifest.VPCPrefixes["tenant"].ID)
	assert.Equal(t, "instance-1", manifest.Instances["worker"].ID)

	vpcPrefixRequest := api.postRequest("tenant-org/vpc-prefix")
	assert.Equal(t, "vpc-1", vpcPrefixRequest["vpcId"])
	assert.Equal(t, "tenant-ipblock-1", vpcPrefixRequest["ipBlockId"])
	instanceRequest := api.postRequest("tenant-org/instance")
	assert.Equal(t, "tenant-id", instanceRequest["tenantId"])
	assert.Equal(t, "instance-type-1", instanceRequest["instanceTypeId"])
	assert.Equal(t, "vpc-1", instanceRequest["vpcId"])

	firstPostCount := len(api.postOrder)
	progress.Reset()
	require.NoError(t, bootstrapSitePrerequisites(client, manifest, &progress))
	assert.Len(t, api.postOrder, firstPostCount)
	assert.Contains(t, progress.String(), "reused site test-site (site-1)")
	assert.Contains(t, progress.String(), "reused instance worker-1 (instance-1)")
}

func TestBootstrapSitePrerequisitesRecoversWhenRecordedIDIsMissing(t *testing.T) {
	api := newBootstrapTestAPI()
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

	manifest := completeBootstrapTestManifest()
	manifest.Site.ID = "site-from-another-installation"
	client := NewClient(server.URL, "provider-org", "token", nil, false)

	require.NoError(t, bootstrapSitePrerequisites(client, manifest, nil))
	assert.Equal(t, "site-1", manifest.Site.ID)
	assert.Contains(t, api.postOrder, "provider-org/site")
}

func TestBootstrapSitePrerequisitesRejectsExistingResourceDrift(t *testing.T) {
	api := newBootstrapTestAPI()
	api.put("provider-org", "site", map[string]any{
		"id":          "site-existing",
		"name":        "test-site",
		"description": "different description",
	})
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

	manifest := completeBootstrapTestManifest()
	manifest.Site.Request["description"] = "expected description"
	client := NewClient(server.URL, "provider-org", "token", nil, false)

	err := bootstrapSitePrerequisites(client, manifest, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "existing site \"site\" does not match")
	assert.Contains(t, err.Error(), "description is different description, want expected description")
	assert.Empty(t, api.postOrder)
}

func TestNewAppIncludesSiteBootstrapCommand(t *testing.T) {
	app, err := NewApp(openapi.Spec)
	require.NoError(t, err)

	var siteCommandFound bool
	var bootstrapCommandFound bool
	for _, command := range app.Commands {
		if command.Name != "site" {
			continue
		}
		siteCommandFound = true
		for _, subcommand := range command.Subcommands {
			if subcommand.Name == "bootstrap" {
				bootstrapCommandFound = true
				break
			}
		}
		break
	}
	assert.True(t, siteCommandFound)
	assert.True(t, bootstrapCommandFound)
}

func TestSiteBootstrapEndpointsMatchEmbeddedSpec(t *testing.T) {
	spec, err := ParseSpec(openapi.Spec)
	require.NoError(t, err)

	for _, endpoint := range []bootstrapEndpoint{
		bootstrapSiteEndpoint,
		bootstrapIPBlockEndpoint,
		bootstrapInstanceTypeEndpoint,
		bootstrapAllocationEndpoint,
		bootstrapVPCEndpoint,
		bootstrapVPCPrefixEndpoint,
		bootstrapInstanceEndpoint,
	} {
		collection, ok := spec.Paths[endpoint.collectionPath]
		require.Truef(t, ok, "collection path %s is missing", endpoint.collectionPath)
		assert.NotNilf(t, collection.Get, "collection GET %s is missing", endpoint.collectionPath)
		assert.NotNilf(t, collection.Post, "collection POST %s is missing", endpoint.collectionPath)

		item, ok := spec.Paths[endpoint.itemPath]
		require.Truef(t, ok, "item path %s is missing", endpoint.itemPath)
		assert.NotNilf(t, item.Get, "item GET %s is missing", endpoint.itemPath)
	}
}

func TestSiteBootstrapCommandWritesReplayableManifest(t *testing.T) {
	api := newBootstrapTestAPI()
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

	input := `
apiVersion: nico.nvidia.com/v1alpha1
kind: SitePrerequisites
provider:
  org: provider-org
tenant:
  org: tenant-org
site:
  request:
    name: command-site
`
	app, err := NewApp(openapi.Spec)
	require.NoError(t, err)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app.Reader = strings.NewReader(input)
	app.Writer = &stdout
	app.ErrWriter = &stderr

	err = app.Run([]string{
		"nicocli",
		"--base-url", server.URL,
		"--token", "test-token",
		"site", "bootstrap",
		"--file", "-",
		"--output-file", "-",
	})
	require.NoError(t, err)
	assert.Contains(t, stderr.String(), "created site command-site (site-1)")

	resolved, err := readSitePrerequisiteManifest("-", strings.NewReader(stdout.String()))
	require.NoError(t, err)
	assert.Equal(t, "provider-org", resolved.Provider.Org)
	assert.Equal(t, "provider-id", resolved.Provider.ID)
	assert.Equal(t, "tenant-id", resolved.Tenant.ID)
	assert.Equal(t, "site-1", resolved.Site.ID)
}

func completeBootstrapTestManifest() *sitePrerequisiteManifest {
	return &sitePrerequisiteManifest{
		APIVersion: sitePrerequisiteAPIVersion,
		Kind:       sitePrerequisiteKind,
		Provider:   bootstrapOrganization{Org: "provider-org"},
		Tenant:     bootstrapOrganization{Org: "tenant-org"},
		Site: &bootstrapResource{Request: map[string]any{
			"name": "test-site",
		}},
		IPBlocks: map[string]*bootstrapResource{
			"fabric": {Request: map[string]any{
				"name":            "fabric-network",
				"siteId":          "${site.id}",
				"routingType":     "DatacenterOnly",
				"prefix":          "10.0.0.0",
				"prefixLength":    16,
				"protocolVersion": "IPv4",
			}},
		},
		InstanceTypes: map[string]*bootstrapResource{
			"compute": {Request: map[string]any{
				"name":                "compute-large",
				"siteId":              "${site.id}",
				"machineCapabilities": []any{},
			}},
		},
		Allocations: map[string]*bootstrapResource{
			"network": {Request: map[string]any{
				"name":     "tenant-network",
				"tenantId": "${tenant.id}",
				"siteId":   "${site.id}",
				"allocationConstraints": []any{
					map[string]any{
						"resourceType":    "IPBlock",
						"resourceTypeId":  "${ipBlocks.fabric.id}",
						"constraintType":  "OnDemand",
						"constraintValue": 24,
					},
				},
			}},
		},
		VPCs: map[string]*bootstrapResource{
			"tenant": {Request: map[string]any{
				"name":   "tenant-vpc",
				"siteId": "${site.id}",
			}},
		},
		VPCPrefixes: map[string]*bootstrapResource{
			"tenant": {Request: map[string]any{
				"name":         "tenant-prefix",
				"vpcId":        "${vpcs.tenant.id}",
				"ipBlockId":    "${allocations.network.allocationConstraints.0.derivedResourceId}",
				"prefixLength": 24,
			}},
		},
		Instances: map[string]*bootstrapResource{
			"worker": {Request: map[string]any{
				"name":           "worker-1",
				"tenantId":       "${tenant.id}",
				"instanceTypeId": "${instanceTypes.compute.id}",
				"vpcId":          "${vpcs.tenant.id}",
				"interfaces": []any{
					map[string]any{
						"vpcPrefixId": "${vpcPrefixes.tenant.id}",
						"isPhysical":  true,
					},
				},
			}},
		},
	}
}

type bootstrapTestAPI struct {
	resources   map[string]map[string]map[string]any
	postOrder   []string
	postBodies  map[string][]map[string]any
	nextIDByKey map[string]int
}

func newBootstrapTestAPI() *bootstrapTestAPI {
	return &bootstrapTestAPI{
		resources:   map[string]map[string]map[string]any{},
		postBodies:  map[string][]map[string]any{},
		nextIDByKey: map[string]int{},
	}
}

func (api *bootstrapTestAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v2/org/"), "/nico/")
	if len(parts) != 2 {
		http.NotFound(response, request)
		return
	}
	org, resourcePath := parts[0], parts[1]

	if request.Method == http.MethodGet && resourcePath == "infrastructure-provider/current" {
		writeBootstrapTestJSON(response, map[string]any{"id": "provider-id", "org": org})
		return
	}
	if request.Method == http.MethodGet && resourcePath == "tenant/current" {
		writeBootstrapTestJSON(response, map[string]any{"id": "tenant-id", "org": org})
		return
	}

	collection, id := splitBootstrapTestResourcePath(resourcePath)
	if collection == "" {
		http.NotFound(response, request)
		return
	}

	switch request.Method {
	case http.MethodGet:
		if id != "" {
			item := api.get(org, collection, id)
			if item == nil {
				response.WriteHeader(http.StatusNotFound)
				writeBootstrapTestJSON(response, map[string]any{"message": "not found"})
				return
			}
			writeBootstrapTestJSON(response, item)
			return
		}
		name := request.URL.Query().Get("query")
		items := []map[string]any{}
		for _, item := range api.collection(org, collection) {
			if name == "" || strings.Contains(fmt.Sprint(item["name"]), name) {
				items = append(items, item)
			}
		}
		writeBootstrapTestJSON(response, items)
	case http.MethodPost:
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(response, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}
		key := org + "/" + collection
		api.nextIDByKey[key]++
		prefix := strings.ReplaceAll(collection, "/", "-")
		id := fmt.Sprintf("%s-%d", prefix, api.nextIDByKey[key])
		item := cloneBootstrapTestMap(body)
		item["id"] = id
		if collection == "allocation" {
			constraints, _ := item["allocationConstraints"].([]any)
			for index, rawConstraint := range constraints {
				constraint, _ := rawConstraint.(map[string]any)
				constraint["id"] = fmt.Sprintf("constraint-%d", index+1)
				constraint["allocationId"] = id
				if constraint["resourceType"] == "IPBlock" {
					constraint["derivedResourceId"] = "tenant-ipblock-1"
				}
			}
		}
		api.put(org, collection, item)
		api.postOrder = append(api.postOrder, key)
		api.postBodies[key] = append(api.postBodies[key], cloneBootstrapTestMap(body))
		response.WriteHeader(http.StatusCreated)
		writeBootstrapTestJSON(response, item)
	default:
		response.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func splitBootstrapTestResourcePath(resourcePath string) (string, string) {
	for _, collection := range []string{"instance/type", "vpc-prefix", "ipblock", "allocation", "instance", "site", "vpc"} {
		if resourcePath == collection {
			return collection, ""
		}
		if strings.HasPrefix(resourcePath, collection+"/") {
			return collection, strings.TrimPrefix(resourcePath, collection+"/")
		}
	}
	return "", ""
}

func (api *bootstrapTestAPI) collection(org, collection string) map[string]map[string]any {
	key := org + "/" + collection
	if api.resources[key] == nil {
		api.resources[key] = map[string]map[string]any{}
	}
	return api.resources[key]
}

func (api *bootstrapTestAPI) put(org, collection string, item map[string]any) {
	api.collection(org, collection)[fmt.Sprint(item["id"])] = cloneBootstrapTestMap(item)
}

func (api *bootstrapTestAPI) get(org, collection, id string) map[string]any {
	item := api.collection(org, collection)[id]
	if item == nil {
		return nil
	}
	return cloneBootstrapTestMap(item)
}

func (api *bootstrapTestAPI) postRequest(key string) map[string]any {
	requests := api.postBodies[key]
	if len(requests) == 0 {
		return nil
	}
	return requests[len(requests)-1]
}

func cloneBootstrapTestMap(value map[string]any) map[string]any {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(data, &cloned); err != nil {
		panic(err)
	}
	return cloned
}

func writeBootstrapTestJSON(response http.ResponseWriter, value any) {
	if err := json.NewEncoder(response).Encode(value); err != nil {
		panic(err)
	}
}
