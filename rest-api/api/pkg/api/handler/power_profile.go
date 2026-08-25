// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
	dpsclient "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/dps"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
)

// validatePowerProfile validates and normalizes set operations when NICo owns
// DPS integration. Omitted values and explicit clears do not require policy
// discovery, and external mode deliberately never calls DPS.
func validatePowerProfile(ctx context.Context, mode string, provider dpsclient.PolicyProvider, powerProfile *string) *cutil.APIError {
	if mode != config.PowerProvisioningModeDPS || powerProfile == nil || *powerProfile == "" {
		return nil
	}
	if provider == nil {
		return cutil.NewAPIError(http.StatusServiceUnavailable, "DPS power-profile validation is unavailable", nil)
	}

	normalized, err := dpsclient.ValidatePowerProfile(ctx, provider, *powerProfile)
	if err == nil {
		*powerProfile = normalized
		return nil
	}
	if errors.Is(err, dpsclient.ErrPowerProfileRequired) {
		return cutil.NewAPIError(http.StatusBadRequest, "Power profile must not be empty", nil)
	}
	if errors.Is(err, dpsclient.ErrPowerProfileNotFound) {
		return cutil.NewAPIError(http.StatusBadRequest, "Power profile does not exist in DPS", nil)
	}

	return cutil.NewAPIError(http.StatusServiceUnavailable, "Failed to validate power profile with DPS", nil)
}
