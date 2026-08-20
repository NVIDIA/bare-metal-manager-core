// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net/http"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

func validateSitePowerProvisioning(siteConfig *cdbm.SiteConfig, value *string) *cutil.APIError {
	// Omission preserves the current value, and an explicit empty string clears
	// it. Both remain valid when power provisioning is disabled.
	if value == nil || *value == "" {
		return nil
	}
	if siteConfig.PowerProvisioningMode() == cdbm.SitePowerProvisioningDisabled {
		return cutil.NewAPIError(http.StatusPreconditionFailed, "Site is not configured to accept power provisioning values", nil)
	}
	return nil
}
