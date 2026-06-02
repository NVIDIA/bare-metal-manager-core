// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package simple

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateUsesConfiguredAPIName(t *testing.T) {
	visitedPaths := map[string]int{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visitedPaths[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/v2/org/test-org/nico/metadata":
			_, _ = io.WriteString(w, `{"version":"0.2.86"}`)
		case "/v2/org/test-org/nico/infrastructure-provider/current":
			_, _ = io.WriteString(w, `{"id":"provider-1"}`)
		case "/v2/org/test-org/nico/tenant/current":
			_, _ = io.WriteString(w, `{"id":"tenant-1"}`)
		case "/v2/org/test-org/nico/site":
			_, _ = io.WriteString(w, `[{"id":"site-1","name":"site-1"}]`)
		case "/v2/org/test-org/nico/vpc":
			_, _ = io.WriteString(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL: server.URL,
		Org:     "test-org",
		APIName: "nico",
		Token:   "test-token",
		Logger:  NewNoOpLogger(),
	})
	require.NoError(t, err)

	err = client.Authenticate(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 1, visitedPaths["/v2/org/test-org/nico/metadata"])
	assert.Equal(t, 1, visitedPaths["/v2/org/test-org/nico/infrastructure-provider/current"])
	assert.Equal(t, 1, visitedPaths["/v2/org/test-org/nico/tenant/current"])
	assert.Equal(t, 1, visitedPaths["/v2/org/test-org/nico/site"])
	assert.Equal(t, 1, visitedPaths["/v2/org/test-org/nico/vpc"])
	assert.Zero(t, visitedPaths["/v2/org/test-org/nico/metadata"])
}

func TestNewClientFromEnvReadsAPIName(t *testing.T) {
	t.Setenv("NICO_BASE_URL", "https://example.com")
	t.Setenv("NICO_ORG", "test-org")
	t.Setenv("NICO_API_NAME", "nico")
	t.Setenv("NICO_TOKEN", "test-token")

	client, err := NewClientFromEnv()
	require.NoError(t, err)

	assert.Equal(t, "https://example.com", client.Config.BaseURL)
	assert.Equal(t, "test-org", client.Config.Org)
	assert.Equal(t, "nico", client.Config.APIName)
	assert.Equal(t, "test-token", client.Config.Token)
}
