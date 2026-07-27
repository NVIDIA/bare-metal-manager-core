// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	appcli "github.com/NVIDIA/infra-controller/rest-api/cli/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAllSuggestions_GeneratedResourcesUseCanonicalFetchers(t *testing.T) {
	tests := []struct {
		name         string
		command      string
		input        string
		resourceType string
		item         NamedItem
	}{
		{
			name:         "InfiniBand acronym",
			command:      "infiniband-partition delete",
			input:        "infiniband-partition delete fab",
			resourceType: "infiniband-partition",
			item:         NamedItem{Name: "fabric-a", ID: "ib-1"},
		},
		{
			name:         "NVLink acronym",
			command:      "nvlink-logical-partition update",
			input:        "nvlink-logical-partition update train",
			resourceType: "nvlink-logical-partition",
			item:         NamedItem{Name: "training-fabric", ID: "nvlink-1"},
		},
		{
			name:         "newly registered iPXE resource",
			command:      "ipxe-template get",
			input:        "ipxe-template get boot",
			resourceType: "ipxe-template",
			item:         NamedItem{Name: "boot-template", ID: "ipxe-1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache := NewCache()
			resolver := NewResolver(cache)
			resolver.RegisterFetcher(
				test.resourceType,
				func(context.Context) ([]NamedItem, error) {
					return []NamedItem{test.item}, nil
				},
			)
			session := &Session{Cache: cache, Resolver: resolver}

			suggestions := getAllSuggestions(
				session,
				test.input,
				[]string{test.command},
			)

			assert.Equal(t, []string{test.command + " " + test.item.Name}, suggestions)
		})
	}
}

func TestGetAllSuggestions_GeneratedDependentSecondPathUsesResolvedParent(t *testing.T) {
	requestPath := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"allocationConstraints": [{
				"id": "constraint-1",
				"resourceType": "InstanceType",
				"resourceTypeId": "instance-type-1",
				"instanceType": {"name": "gpu.large"},
				"constraintType": "ExactMatch"
			}]
		}`)
	}))
	defer server.Close()

	client := appcli.NewClient(server.URL, "acme", "token", nil, false)
	session := NewSession(client, "acme", "")
	session.Resolver.RegisterFetcher(
		"allocation",
		func(context.Context) ([]NamedItem, error) {
			return []NamedItem{{Name: "workload-a", ID: "allocation-1"}}, nil
		},
	)

	suggestions := getAllSuggestions(
		session,
		"allocation constraint update workload-a gpu",
		[]string{"allocation constraint update"},
	)

	require.Equal(
		t,
		[]string{`allocation constraint update workload-a "InstanceType / gpu.large"`},
		suggestions,
	)
	assert.Equal(
		t,
		"/v2/org/acme/nico/allocation/allocation-1",
		<-requestPath,
	)
	args, err := splitCommandArguments(
		suggestions[0][len("allocation constraint update "):],
	)
	require.NoError(t, err)
	assert.Equal(t, []string{"workload-a", "InstanceType / gpu.large"}, args)
}

func TestGetAllSuggestions_GeneratedAssociationUsesParentScopedMachineNames(t *testing.T) {
	requestPath := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(
			w,
			`[{"id":"association-1","machineId":"machine-1"}]`,
		)
	}))
	defer server.Close()

	client := appcli.NewClient(server.URL, "acme", "token", nil, false)
	session := NewSession(client, "acme", "")
	session.Resolver.RegisterFetcher(
		"instance-type",
		func(context.Context) ([]NamedItem, error) {
			return []NamedItem{{Name: "gpu.large", ID: "instance-type-1"}}, nil
		},
	)
	session.Resolver.RegisterFetcher(
		"machine",
		func(context.Context) ([]NamedItem, error) {
			return []NamedItem{{Name: "host-one", ID: "machine-1"}}, nil
		},
	)

	suggestions := getAllSuggestions(
		session,
		"instance-type machine-association delete gpu.large host",
		[]string{"instance-type machine-association delete"},
	)

	assert.Equal(
		t,
		[]string{"instance-type machine-association delete gpu.large host-one"},
		suggestions,
	)
	assert.Equal(
		t,
		"/v2/org/acme/nico/instance/type/instance-type-1/machine",
		<-requestPath,
	)
}

func TestGetAllSuggestions_PreservesManualAliasCompletion(t *testing.T) {
	cache := NewCache()
	resolver := NewResolver(cache)
	resolver.RegisterFetcher("machine", func(context.Context) ([]NamedItem, error) {
		return []NamedItem{{Name: "host-one", ID: "machine-1"}}, nil
	})
	session := &Session{Cache: cache, Resolver: resolver}

	suggestions := getAllSuggestions(
		session,
		"machine dpu get host",
		[]string{"machine dpu get"},
	)

	assert.Equal(t, []string{"machine dpu get host-one"}, suggestions)
}
