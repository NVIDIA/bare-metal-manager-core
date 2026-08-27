// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dpsclient "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/dps"
)

type policyProviderStub struct {
	profiles []string
	err      error
	calls    int
}

func (s *policyProviderStub) ListPowerProfiles(context.Context) ([]string, error) {
	s.calls++
	return s.profiles, s.err
}

func TestValidatePowerProfile(t *testing.T) {
	providerFailure := errors.New("DPS unavailable")
	tests := []struct {
		name        string
		dpsEnabled  bool
		profile     *string
		provider    dpsclient.PolicyProvider
		wantProfile *string
		wantCode    int
		wantCalls   int
	}{
		{
			name:        "disabled DPS trusts profile without calling DPS",
			profile:     stringPointer("launchlayer-profile"),
			provider:    &policyProviderStub{err: providerFailure},
			wantProfile: stringPointer("launchlayer-profile"),
		},
		{
			name:       "enabled DPS preserves omitted profile",
			dpsEnabled: true,
			provider:   &policyProviderStub{err: providerFailure},
		},
		{
			name:        "enabled DPS preserves explicit clear",
			dpsEnabled:  true,
			profile:     stringPointer(""),
			provider:    &policyProviderStub{err: providerFailure},
			wantProfile: stringPointer(""),
		},
		{
			name:        "enabled DPS validates and normalizes set profile",
			dpsEnabled:  true,
			profile:     stringPointer("  efficient  "),
			provider:    &policyProviderStub{profiles: []string{"efficient"}},
			wantProfile: stringPointer("efficient"),
			wantCalls:   1,
		},
		{
			name:        "enabled DPS rejects unknown profile",
			dpsEnabled:  true,
			profile:     stringPointer("unknown"),
			provider:    &policyProviderStub{profiles: []string{"efficient"}},
			wantProfile: stringPointer("unknown"),
			wantCode:    http.StatusBadRequest,
			wantCalls:   1,
		},
		{
			name:        "enabled DPS rejects whitespace-only set profile",
			dpsEnabled:  true,
			profile:     stringPointer("   "),
			provider:    &policyProviderStub{profiles: []string{"efficient"}},
			wantProfile: stringPointer("   "),
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "enabled DPS reports discovery failure",
			dpsEnabled:  true,
			profile:     stringPointer("efficient"),
			provider:    &policyProviderStub{err: providerFailure},
			wantProfile: stringPointer("efficient"),
			wantCode:    http.StatusServiceUnavailable,
			wantCalls:   1,
		},
		{
			name:        "enabled DPS reports missing client",
			dpsEnabled:  true,
			profile:     stringPointer("efficient"),
			wantProfile: stringPointer("efficient"),
			wantCode:    http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := validatePowerProfile(context.Background(), tt.dpsEnabled, tt.provider, tt.profile)
			if tt.wantCode == 0 {
				require.Nil(t, apiErr)
			} else {
				require.Error(t, apiErr)
				assert.Equal(t, tt.wantCode, apiErr.Code)
			}
			assert.Equal(t, tt.wantProfile, tt.profile)
			provider, ok := tt.provider.(*policyProviderStub)
			if ok {
				assert.Equal(t, tt.wantCalls, provider.calls)
			}
		})
	}
}

func stringPointer(value string) *string {
	return &value
}
