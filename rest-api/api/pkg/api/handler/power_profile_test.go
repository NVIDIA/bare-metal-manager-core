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

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
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
		mode        string
		profile     *string
		provider    dpsclient.PolicyProvider
		wantProfile *string
		wantCode    int
		wantCalls   int
	}{
		{
			name:        "external mode trusts profile without calling DPS",
			mode:        config.PowerProvisioningModeExternal,
			profile:     stringPointer("launchlayer-profile"),
			provider:    &policyProviderStub{err: providerFailure},
			wantProfile: stringPointer("launchlayer-profile"),
		},
		{
			name:     "DPS mode preserves omitted profile",
			mode:     config.PowerProvisioningModeDPS,
			provider: &policyProviderStub{err: providerFailure},
		},
		{
			name:        "DPS mode preserves explicit clear",
			mode:        config.PowerProvisioningModeDPS,
			profile:     stringPointer(""),
			provider:    &policyProviderStub{err: providerFailure},
			wantProfile: stringPointer(""),
		},
		{
			name:        "DPS mode validates and normalizes set profile",
			mode:        config.PowerProvisioningModeDPS,
			profile:     stringPointer("  efficient  "),
			provider:    &policyProviderStub{profiles: []string{"efficient"}},
			wantProfile: stringPointer("efficient"),
			wantCalls:   1,
		},
		{
			name:        "DPS mode rejects unknown profile",
			mode:        config.PowerProvisioningModeDPS,
			profile:     stringPointer("unknown"),
			provider:    &policyProviderStub{profiles: []string{"efficient"}},
			wantProfile: stringPointer("unknown"),
			wantCode:    http.StatusBadRequest,
			wantCalls:   1,
		},
		{
			name:        "DPS mode rejects whitespace-only set profile",
			mode:        config.PowerProvisioningModeDPS,
			profile:     stringPointer("   "),
			provider:    &policyProviderStub{profiles: []string{"efficient"}},
			wantProfile: stringPointer("   "),
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "DPS mode reports discovery failure",
			mode:        config.PowerProvisioningModeDPS,
			profile:     stringPointer("efficient"),
			provider:    &policyProviderStub{err: providerFailure},
			wantProfile: stringPointer("efficient"),
			wantCode:    http.StatusServiceUnavailable,
			wantCalls:   1,
		},
		{
			name:        "DPS mode reports missing client",
			mode:        config.PowerProvisioningModeDPS,
			profile:     stringPointer("efficient"),
			wantProfile: stringPointer("efficient"),
			wantCode:    http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := validatePowerProfile(context.Background(), tt.mode, tt.provider, tt.profile)
			if tt.wantCode == 0 {
				require.Nil(t, apiErr)
			} else {
				require.Error(t, apiErr)
				assert.Equal(t, tt.wantCode, apiErr.Code)
			}
			assert.Equal(t, tt.wantProfile, tt.profile)
			if provider, ok := tt.provider.(*policyProviderStub); ok {
				assert.Equal(t, tt.wantCalls, provider.calls)
			}
		})
	}
}

func stringPointer(value string) *string {
	return &value
}
