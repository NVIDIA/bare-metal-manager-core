// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"net/http"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

// ValidateSitePowerManagement checks whether a site accepts a power-management
// value. Omission preserves the current value, and an explicit empty string
// clears it, so both remain valid when DPS power management is disabled.
func ValidateSitePowerManagement(siteConfig *cdbm.SiteConfig, value *string) *cutil.APIError {
	if value == nil || *value == "" {
		return nil
	}
	if siteConfig == nil || !siteConfig.DPSPowerManagement {
		return cutil.NewAPIError(http.StatusPreconditionFailed, "Site does not have DPS power management enabled", nil)
	}
	return nil
}
