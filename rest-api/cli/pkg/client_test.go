// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientDoRefreshesTokenOnUnauthorizedAndRetries(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			http.Error(w, `{"message":"expired"}`, http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer refreshed-token" {
			require.Equal(t, "Bearer refreshed-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	refreshes := 0
	client := NewClient(server.URL, "test-org", "stale-token", nil, false)
	client.TokenRefresh = func() (string, error) {
		refreshes++
		return "refreshed-token", nil
	}

	body, _, err := client.Do("GET", "/v2/org/{org}/nico/test", nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, `{"ok":true}`, string(body))
	require.Equal(t, 2, requests)
	require.Equal(t, 1, refreshes)
}

func TestClientDoRetriesUnauthorizedAtMostThreeTimes(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, `{"message":"expired"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	var events []AuthRetryEvent
	refreshes := 0
	client := NewClient(server.URL, "test-org", "stale-token", nil, false)
	client.TokenRefresh = func() (string, error) {
		refreshes++
		return "still-invalid-token", nil
	}
	client.AuthRetryNotify = func(event AuthRetryEvent) {
		events = append(events, event)
	}

	_, _, err := client.Do("GET", "/v2/org/{org}/nico/test", nil, nil, nil)
	apiErr, ok := err.(*APIError)
	require.True(t, ok, "err = %T, want *APIError", err)
	require.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
	require.Equal(t, 4, requests)
	require.Equal(t, 3, refreshes)
	require.Len(t, events, 6)
	for i := 0; i < 3; i++ {
		login := events[i*2]
		retry := events[i*2+1]
		require.Equal(t, AuthRetryActionLogin, login.Action)
		require.Equal(t, AuthRetryActionRetry, retry.Action)
		require.Equal(t, i+1, login.Attempt)
		require.Equal(t, i+1, retry.Attempt)
		require.Equal(t, 3, login.MaxAttempts)
		require.Equal(t, 3, retry.MaxAttempts)
	}
}

func TestClientDoDoesNotReplayNonIdempotentRequestAfterUnauthorized(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, `{"message":"expired"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	var events []AuthRetryEvent
	refreshes := 0
	client := NewClient(server.URL, "test-org", "stale-token", nil, false)
	client.TokenRefresh = func() (string, error) {
		refreshes++
		return "new-token", nil
	}
	client.AuthRetryNotify = func(event AuthRetryEvent) {
		events = append(events, event)
	}

	_, _, err := client.Do("POST", "/v2/org/{org}/nico/test", nil, nil, []byte(`{"name":"x"}`))
	apiErr, ok := err.(*APIError)
	require.True(t, ok, "err = %T, want *APIError", err)
	require.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
	require.Equal(t, 1, requests)
	require.Equal(t, 0, refreshes)
	require.Len(t, events, 1)
	require.Equal(t, AuthRetryActionSkip, events[0].Action)
	require.Equal(t, http.MethodPost, events[0].Method)
}

func TestClientDoReturnsRefreshErrorWithoutRetrying(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, `{"message":"expired"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	refreshes := 0
	client := NewClient(server.URL, "test-org", "stale-token", nil, false)
	client.TokenRefresh = func() (string, error) {
		refreshes++
		return "", errors.New("refresh failed")
	}

	_, _, err := client.Do("GET", "/v2/org/{org}/nico/test", nil, nil, nil)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "refresh failed"), "err = %v", err)
	require.Equal(t, 1, requests)
	require.Equal(t, 1, refreshes)
}

func TestClientDoReturnsEmptyTokenErrorWithoutRetrying(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, `{"message":"expired"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	refreshes := 0
	client := NewClient(server.URL, "test-org", "stale-token", nil, false)
	client.TokenRefresh = func() (string, error) {
		refreshes++
		return "", nil
	}

	_, _, err := client.Do("GET", "/v2/org/{org}/nico/test", nil, nil, nil)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "no token returned"), "err = %v", err)
	require.Equal(t, 1, requests)
	require.Equal(t, 1, refreshes)
}

func TestClientDoReturnsUnauthorizedWhenNoRefreshFunc(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"expired"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-org", "stale-token", nil, false)
	_, _, err := client.Do("GET", "/v2/org/{org}/nico/test", nil, nil, nil)
	apiErr, ok := err.(*APIError)
	require.True(t, ok, "err = %T, want *APIError", err)
	require.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}

func TestClientDoDoesNotRefreshOnForbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"forbidden"}`, http.StatusForbidden)
	}))
	defer server.Close()

	refreshes := 0
	client := NewClient(server.URL, "test-org", "token", nil, false)
	client.TokenRefresh = func() (string, error) {
		refreshes++
		return "new-token", nil
	}

	_, _, err := client.Do("GET", "/v2/org/{org}/nico/test", nil, nil, nil)
	apiErr, ok := err.(*APIError)
	require.True(t, ok, "err = %T, want *APIError", err)
	require.Equal(t, http.StatusForbidden, apiErr.StatusCode)
	require.Equal(t, 0, refreshes)
}
