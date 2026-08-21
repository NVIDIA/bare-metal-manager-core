// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"net/http"
	"testing"

	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSitePowerManagement(t *testing.T) {
	value := "balanced"
	empty := ""
	whitespace := "   "

	tests := []struct {
		name       string
		config     *cdbm.SiteConfig
		value      *string
		wantReject bool
	}{
		{name: "missing config rejects value", value: &value, wantReject: true},
		{name: "disabled rejects value", config: &cdbm.SiteConfig{}, value: &value, wantReject: true},
		{name: "enabled accepts value", config: &cdbm.SiteConfig{DPSPowerManagement: true}, value: &value},
		{name: "disabled accepts omission", config: &cdbm.SiteConfig{}},
		{name: "disabled accepts clear", config: &cdbm.SiteConfig{}, value: &empty},
		{name: "disabled rejects whitespace value", config: &cdbm.SiteConfig{}, value: &whitespace, wantReject: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := ValidateSitePowerManagement(tt.config, tt.value)
			if !tt.wantReject {
				assert.Nil(t, apiErr)
				return
			}
			require.NotNil(t, apiErr)
			assert.Equal(t, http.StatusPreconditionFailed, apiErr.Code)
		})
	}
}
