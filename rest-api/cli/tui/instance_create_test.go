// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	appcli "github.com/NVIDIA/infra-controller/rest-api/cli/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSession_fetchVPCsPreservesNetworkVirtualizationType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/org/acme/nico/vpc", r.URL.Path)
		assert.Equal(t, "site-1", r.URL.Query().Get("siteId"))
		_, err := io.WriteString(w, `[{"id":"vpc-1","name":"ethernet-vpc","siteId":"site-1","status":"Ready","networkVirtualizationType":"ETHERNET_VIRTUALIZER"}]`)
		require.NoError(t, err)
	}))
	defer server.Close()

	session := NewSession(
		appcli.NewClient(server.URL, "acme", "token", nil, false),
		"acme",
		"",
	)
	session.Scope.SiteID = "site-1"

	vpcs, err := session.fetchVPCs(context.Background())

	require.NoError(t, err)
	require.Len(t, vpcs, 1)
	assert.Equal(t, "ETHERNET_VIRTUALIZER", vpcs[0].Extra["networkVirtualizationType"])
	assert.Equal(t, "site-1", vpcs[0].Extra["siteId"])
}

func TestInstanceNetworkConfigForVPC(t *testing.T) {
	tests := []struct {
		name               string
		virtualizationType string
		want               instanceNetworkConfig
		wantErr            string
	}{
		{
			name:               "Ethernet virtualizer uses subnets",
			virtualizationType: "ETHERNET_VIRTUALIZER",
			want: instanceNetworkConfig{
				resourceType: "subnet",
				singular:     "Subnet",
				plural:       "subnets",
				selectorKey:  "subnetId",
			},
		},
		{
			name:               "FNN uses VPC prefixes",
			virtualizationType: "FNN",
			want: instanceNetworkConfig{
				detectMultiDPU: true,
				resourceType:   "vpc-prefix",
				reuseResources: true,
				singular:       "VPC prefix",
				plural:         "VPC prefixes",
				selectorKey:    "vpcPrefixId",
			},
		},
		{
			name:               "flat VPC uses automatic networking",
			virtualizationType: "FLAT",
			want: instanceNetworkConfig{
				autoNetwork: true,
			},
		},
		{
			name:               "unknown type is rejected",
			virtualizationType: "UNKNOWN",
			wantErr:            `does not support VPC network virtualization type "UNKNOWN"`,
		},
		{
			name:    "missing type is rejected",
			wantErr: "selected VPC has no network virtualization type",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vpc := &NamedItem{
				Extra: map[string]string{
					"networkVirtualizationType": test.virtualizationType,
				},
			}

			got, err := instanceNetworkConfigForVPC(vpc)

			if test.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}

	t.Run("missing VPC is rejected", func(t *testing.T) {
		_, err := instanceNetworkConfigForVPC(nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "selected VPC is missing")
	})
}

func TestFetchInstanceDPUCapability(t *testing.T) {
	tests := []struct {
		name         string
		responseBody string
		status       int
		want         *instanceDPUCapability
		wantErr      string
	}{
		{
			name: "finds dual DPU network capability",
			responseBody: `{
				"machineCapabilities":[
					{"type":"GPU","name":"H100","count":8},
					{"type":"Network","name":"BlueField-3","deviceType":"DPU","count":2}
				]
			}`,
			status: http.StatusOK,
			want: &instanceDPUCapability{
				name:  "BlueField-3",
				count: 2,
			},
		},
		{
			name: "ignores a single DPU",
			responseBody: `{
				"machineCapabilities":[
					{"type":"Network","name":"BlueField-3","deviceType":"DPU","count":1}
				]
			}`,
			status: http.StatusOK,
		},
		{
			name: "ignores non-DPU network capability",
			responseBody: `{
				"machineCapabilities":[
					{"type":"Network","name":"ConnectX-7","deviceType":"NVLink","count":2}
				]
			}`,
			status: http.StatusOK,
		},
		{
			name:         "reports malformed machine response",
			responseBody: `{`,
			status:       http.StatusOK,
			wantErr:      "parsing capabilities for machine machine-1",
		},
		{
			name:         "reports machine lookup failure",
			responseBody: `{"message":"machine unavailable"}`,
			status:       http.StatusInternalServerError,
			wantErr:      "fetching capabilities for machine machine-1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v2/org/acme/nico/machine/machine-1", r.URL.Path)
				w.WriteHeader(test.status)
				_, err := io.WriteString(w, test.responseBody)
				require.NoError(t, err)
			}))
			defer server.Close()

			session := NewSession(
				appcli.NewClient(server.URL, "acme", "token", nil, false),
				"acme",
				"",
			)
			got, err := fetchInstanceDPUCapability(session, "machine-1")

			if test.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestPromptRequiredVirtualFunctionID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		used  map[int]bool
		want  int
	}{
		{
			name:  "blank is retried",
			input: "\n0\n",
			want:  0,
		},
		{
			name:  "zero is accepted",
			input: "0\n",
			want:  0,
		},
		{
			name:  "fifteen is accepted",
			input: "15\n",
			want:  15,
		},
		{
			name:  "invalid values are retried",
			input: "not-a-number\n-1\n16\n7\n",
			want:  7,
		},
		{
			name:  "duplicate IDs are retried",
			input: "3\n4\n",
			used: map[int]bool{
				3: true,
			},
			want: 4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			used := test.used
			if used == nil {
				used = make(map[int]bool)
			}
			var got int
			_, err := withStdin(t, test.input, func() (string, error) {
				var promptErr error
				got, promptErr = promptRequiredVirtualFunctionID(used)
				return "", promptErr
			})

			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestPromptDeviceVirtualFunctionID(t *testing.T) {
	t.Run("IDs are required and unique", func(t *testing.T) {
		vfIDs := &deviceVirtualFunctionIDs{
			used: make(map[int]bool),
		}
		var first int
		_, err := withStdin(t, "3\n", func() (string, error) {
			var promptErr error
			first, promptErr = promptDeviceVirtualFunctionID(0, vfIDs)
			return "", promptErr
		})
		require.NoError(t, err)
		assert.Equal(t, 3, first)

		var second int
		_, err = withStdin(t, "\n3\n4\n", func() (string, error) {
			var promptErr error
			second, promptErr = promptDeviceVirtualFunctionID(0, vfIDs)
			return "", promptErr
		})
		require.NoError(t, err)
		assert.Equal(t, 4, second)
	})
}

func TestDeviceVirtualFunctionIDsExhausted(t *testing.T) {
	vfIDs := deviceVirtualFunctionIDs{
		used: make(map[int]bool),
	}
	for virtualFunctionID := virtualFunctionIDMinimum; virtualFunctionID < virtualFunctionIDMaximum; virtualFunctionID++ {
		vfIDs.used[virtualFunctionID] = true
	}
	assert.False(t, vfIDs.exhausted())

	vfIDs.used[virtualFunctionIDMaximum] = true
	assert.True(t, vfIDs.exhausted())
}

func TestPromptMultiDPUInstanceInterfaces(t *testing.T) {
	cache := NewCache()
	resolver := NewResolver(cache)
	session := &Session{
		Cache:    cache,
		Resolver: resolver,
	}
	networkConfig := instanceNetworkConfig{
		dpuCapability: &instanceDPUCapability{
			name:  "dual-dpu-network",
			count: 2,
		},
		plural:      "VPC prefixes",
		selectorKey: "vpcPrefixId",
		singular:    "VPC prefix",
	}

	t.Run("reuses one prefix across physical interfaces on multiple DPUs", func(t *testing.T) {
		readyItems := []NamedItem{
			{
				ID:     "prefix-1",
				Name:   "prefix-one",
				Status: "Ready",
			},
		}

		var got []map[string]interface{}
		_, err := withStdin(t, "n\ny\nn\n", func() (string, error) {
			var promptErr error
			got, promptErr = promptMultiDPUInstanceInterfaces(session, networkConfig, readyItems)
			return "", promptErr
		})

		require.NoError(t, err)
		assert.Equal(t, []map[string]interface{}{
			{
				"device":         "dual-dpu-network",
				"deviceInstance": 0,
				"isPhysical":     true,
				"vpcPrefixId":    "prefix-1",
			},
			{
				"device":         "dual-dpu-network",
				"deviceInstance": 1,
				"isPhysical":     true,
				"vpcPrefixId":    "prefix-1",
			},
		}, got)
	})
}

func TestTargetedInstanceCreationAtSite(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []interface{}
		siteID       string
		want         bool
	}{
		{
			name: "enabled by account default",
			capabilities: []interface{}{
				map[string]interface{}{
					"targetedInstanceCreation": true,
				},
			},
			siteID: "site-1",
			want:   true,
		},
		{
			name: "disabled by account default",
			capabilities: []interface{}{
				map[string]interface{}{
					"targetedInstanceCreation": false,
				},
			},
			siteID: "site-1",
		},
		{
			name: "site override enables disabled default",
			capabilities: []interface{}{
				map[string]interface{}{
					"targetedInstanceCreation": false,
				},
				map[string]interface{}{
					"siteIds": []interface{}{
						"site-1",
					},
					"targetedInstanceCreation": true,
				},
			},
			siteID: "site-1",
			want:   true,
		},
		{
			name: "site override disables enabled default",
			capabilities: []interface{}{
				map[string]interface{}{
					"targetedInstanceCreation": true,
				},
				map[string]interface{}{
					"siteIds": []interface{}{
						"site-1",
					},
					"targetedInstanceCreation": false,
				},
			},
			siteID: "site-1",
		},
		{
			name: "unrelated site override preserves default",
			capabilities: []interface{}{
				map[string]interface{}{
					"targetedInstanceCreation": true,
				},
				map[string]interface{}{
					"siteIds": []interface{}{
						"site-2",
					},
					"targetedInstanceCreation": false,
				},
			},
			siteID: "site-1",
			want:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account := map[string]interface{}{
				"siteCapabilities": test.capabilities,
			}

			got := targetedInstanceCreationAtSite(account, test.siteID)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestPromptInstanceInterfaces(t *testing.T) {
	tests := []struct {
		name               string
		virtualizationType string
		resourceType       string
		items              []NamedItem
		fetchErr           error
		input              string
		want               []map[string]interface{}
		wantErr            string
	}{
		{
			name:               "Ethernet virtualizer selects a Ready subnet",
			virtualizationType: "ETHERNET_VIRTUALIZER",
			resourceType:       "subnet",
			items: []NamedItem{
				{
					Name:   "pending-subnet",
					ID:     "subnet-pending",
					Status: "Pending",
				},
				{
					Name:   "tenant-subnet",
					ID:     "subnet-1",
					Status: "Ready",
				},
			},
			input: "n\n",
			want: []map[string]interface{}{
				{
					"isPhysical": true,
					"subnetId":   "subnet-1",
				},
			},
		},
		{
			name:               "FNN selects a Ready VPC prefix",
			virtualizationType: "FNN",
			resourceType:       "vpc-prefix",
			items: []NamedItem{
				{
					Name:   "provisioning-prefix",
					ID:     "vpc-prefix-provisioning",
					Status: "Provisioning",
				},
				{
					Name:   "tenant-prefix",
					ID:     "vpc-prefix-1",
					Status: "Ready",
				},
			},
			input: "n\n",
			want: []map[string]interface{}{
				{
					"isPhysical":  true,
					"vpcPrefixId": "vpc-prefix-1",
				},
			},
		},
		{
			name:               "device-less FNN reuses a Ready VPC prefix",
			virtualizationType: "FNN",
			resourceType:       "vpc-prefix",
			items: []NamedItem{
				{
					Name:   "tenant-prefix",
					ID:     "vpc-prefix-1",
					Status: "Ready",
				},
			},
			input: "y\n3\nn\n",
			want: []map[string]interface{}{
				{
					"isPhysical":  true,
					"vpcPrefixId": "vpc-prefix-1",
				},
				{
					"isPhysical":        false,
					"virtualFunctionId": 3,
					"vpcPrefixId":       "vpc-prefix-1",
				},
			},
		},
		{
			name:               "missing Ready subnet returns a local error",
			virtualizationType: "ETHERNET_VIRTUALIZER",
			resourceType:       "subnet",
			wantErr:            "no Ready subnets available for selected VPC",
		},
		{
			name:               "only non-Ready VPC prefixes returns a local error",
			virtualizationType: "FNN",
			resourceType:       "vpc-prefix",
			items: []NamedItem{
				{
					Name:   "provisioning-prefix",
					ID:     "vpc-prefix-provisioning",
					Status: "Provisioning",
				},
			},
			wantErr: "no Ready VPC prefixes available for selected VPC",
		},
		{
			name:               "VPC prefix lookup failure returns a local error",
			virtualizationType: "FNN",
			resourceType:       "vpc-prefix",
			fetchErr:           errors.New("API unavailable"),
			wantErr:            "listing VPC prefixes for selected VPC: API unavailable",
		},
		{
			name:               "flat VPC does not fetch explicit interface resources",
			virtualizationType: "FLAT",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache := NewCache()
			resolver := NewResolver(cache)
			fetchedResourceTypes := []string{}
			resourceTypes := []string{"subnet", "vpc-prefix"}
			for _, resourceType := range resourceTypes {
				registeredResourceType := resourceType
				resolver.RegisterFetcher(registeredResourceType, func(context.Context) ([]NamedItem, error) {
					fetchedResourceTypes = append(fetchedResourceTypes, registeredResourceType)
					if registeredResourceType != test.resourceType {
						return nil, errors.New("unexpected resource fetch")
					}
					return test.items, test.fetchErr
				})
			}
			session := &Session{
				Cache:    cache,
				Resolver: resolver,
			}
			vpc := &NamedItem{
				Extra: map[string]string{
					"networkVirtualizationType": test.virtualizationType,
				},
			}
			networkConfig, configErr := instanceNetworkConfigForVPC(vpc)
			require.NoError(t, configErr)
			var got []map[string]interface{}

			_, err := withStdin(t, test.input, func() (string, error) {
				var promptErr error
				got, promptErr = promptInstanceInterfaces(session, context.Background(), networkConfig)
				return "", promptErr
			})

			if test.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.want, got)
			}
			if test.resourceType == "" {
				assert.Empty(t, fetchedResourceTypes)
			} else {
				assert.Equal(t, []string{test.resourceType}, fetchedResourceTypes)
			}
		})
	}
}
