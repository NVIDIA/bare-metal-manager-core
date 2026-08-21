// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net/http"
	"testing"

	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSitePowerProvisioning(t *testing.T) {
	value := "balanced"
	empty := ""
	whitespace := "   "

	tests := []struct {
		name       string
		config     *cdbm.SiteConfig
		value      *string
		wantReject bool
	}{
		{name: "missing config fails safe", value: &value, wantReject: true},
		{name: "missing mode fails safe", config: &cdbm.SiteConfig{}, value: &value, wantReject: true},
		{name: "disabled mode rejects value", config: &cdbm.SiteConfig{PowerProvisioning: cdbm.SitePowerProvisioningDisabled}, value: &value, wantReject: true},
		{name: "unknown mode fails safe", config: &cdbm.SiteConfig{PowerProvisioning: "unknown"}, value: &value, wantReject: true},
		{name: "external mode accepts value", config: &cdbm.SiteConfig{PowerProvisioning: cdbm.SitePowerProvisioningExternal}, value: &value},
		{name: "unsupported DPS mode rejects value", config: &cdbm.SiteConfig{PowerProvisioning: "dps"}, value: &value, wantReject: true},
		{name: "disabled mode accepts omission", config: &cdbm.SiteConfig{PowerProvisioning: cdbm.SitePowerProvisioningDisabled}},
		{name: "disabled mode accepts clear", config: &cdbm.SiteConfig{PowerProvisioning: cdbm.SitePowerProvisioningDisabled}, value: &empty},
		{name: "disabled mode rejects whitespace value", config: &cdbm.SiteConfig{PowerProvisioning: cdbm.SitePowerProvisioningDisabled}, value: &whitespace, wantReject: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := validateSitePowerProvisioning(tt.config, tt.value)
			if !tt.wantReject {
				assert.Nil(t, apiErr)
				return
			}
			require.NotNil(t, apiErr)
			assert.Equal(t, http.StatusPreconditionFailed, apiErr.Code)
		})
	}
}
