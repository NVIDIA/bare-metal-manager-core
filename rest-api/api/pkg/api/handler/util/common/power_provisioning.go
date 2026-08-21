// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"net/http"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

// ValidateSitePowerProvisioning checks whether a site accepts a power
// provisioning value. Omission preserves the current value, and an explicit
// empty string clears it, so both remain valid when provisioning is disabled.
func ValidateSitePowerProvisioning(siteConfig *cdbm.SiteConfig, value *string) *cutil.APIError {
	if value == nil || *value == "" {
		return nil
	}
	if siteConfig.PowerProvisioningMode() == cdbm.SitePowerProvisioningDisabled {
		return cutil.NewAPIError(http.StatusPreconditionFailed, "Site is not configured to accept power provisioning values", nil)
	}
	return nil
}
