// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"slices"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
)

const (
	validationErrorInvalidSiteCapabilityScope = "scope must be global or limited"
	validationErrorGlobalSiteIDsNotAllowed    = "siteIds must be omitted or empty when scope is global"
	validationErrorLimitedSiteIDsRequired     = "siteIds must be specified when scope is limited"
	validationErrorDuplicateGlobalScope       = "only one global siteCapabilities entry is allowed"
	validationErrorDuplicateSiteID            = "duplicate siteIds are not allowed across siteCapabilities entries"
)

// TenantAccountSiteCapabilityScope identifies whether a capability entry applies globally
// or to an explicit set of sites.
type TenantAccountSiteCapabilityScope string

const (
	TenantAccountSiteCapabilityScopeGlobal  TenantAccountSiteCapabilityScope = "global"
	TenantAccountSiteCapabilityScopeLimited TenantAccountSiteCapabilityScope = "limited"
)

var tenantAccountSiteCapabilityScopes = []interface{}{
	TenantAccountSiteCapabilityScopeGlobal,
	TenantAccountSiteCapabilityScopeLimited,
}

// APITenantAccountSiteCapability describes the TargetedInstanceCreation capability for
// either all sites (global) or an explicit site list (limited).
type APITenantAccountSiteCapability struct {
	SiteIDs                  []string                         `json:"siteIds,omitempty"`
	Scope                    TenantAccountSiteCapabilityScope `json:"scope"`
	TargetedInstanceCreation bool                             `json:"targetedInstanceCreation"`
}

// APITenantAccountSiteCapabilitiesUpdateRequest is the replace payload for Provider Admin
// capability updates on a TenantAccount.
type APITenantAccountSiteCapabilitiesUpdateRequest []APITenantAccountSiteCapability

// Validate ensures the replace payload is structurally valid.
func (caps APITenantAccountSiteCapabilitiesUpdateRequest) Validate() error {
	if len(caps) == 0 {
		return validation.Errors{"siteCapabilities": fmt.Errorf("siteCapabilities must contain at least one entry")}
	}

	globalCount := 0
	seenSiteIDs := map[string]struct{}{}

	for i, cap := range caps {
		prefix := fmt.Sprintf("[%d]", i)
		if err := validation.ValidateStruct(&cap,
			validation.Field(&cap.Scope,
				validation.Required.Error(validationErrorValueRequired),
				validation.In(tenantAccountSiteCapabilityScopes...).Error(validationErrorInvalidSiteCapabilityScope)),
			validation.Field(&cap.SiteIDs,
				validation.When(cap.Scope == TenantAccountSiteCapabilityScopeGlobal,
					validation.By(func(value interface{}) error {
						siteIDs, ok := value.([]string)
						if !ok {
							return nil
						}
						if len(siteIDs) > 0 {
							return fmt.Errorf(validationErrorGlobalSiteIDsNotAllowed)
						}
						return nil
					})),
				validation.When(cap.Scope == TenantAccountSiteCapabilityScopeLimited,
					validation.By(func(value interface{}) error {
						siteIDs, ok := value.([]string)
						if !ok || len(siteIDs) == 0 {
							return fmt.Errorf(validationErrorLimitedSiteIDsRequired)
						}
						return nil
					}),
					validation.Each(validationis.UUID.Error(validationErrorInvalidUUID)),
				),
			),
		); err != nil {
			return validation.Errors{prefix: err}
		}

		if cap.Scope == TenantAccountSiteCapabilityScopeGlobal {
			globalCount++
		}

		for _, siteID := range cap.SiteIDs {
			if _, ok := seenSiteIDs[siteID]; ok {
				return validation.Errors{"siteCapabilities": fmt.Errorf(validationErrorDuplicateSiteID)}
			}
			seenSiteIDs[siteID] = struct{}{}
		}
	}

	if globalCount != 1 {
		return validation.Errors{"siteCapabilities": fmt.Errorf(validationErrorDuplicateGlobalScope)}
	}

	return nil
}

func tenantAccountSiteCapabilitiesToAPI(ta *cdbm.TenantAccount, tenantSites []cdbm.TenantSite) []APITenantAccountSiteCapability {
	if ta == nil {
		return nil
	}

	global := ta.Config.TargetedInstanceCreation
	caps := []APITenantAccountSiteCapability{
		{
			Scope:                    TenantAccountSiteCapabilityScopeGlobal,
			TargetedInstanceCreation: global,
		},
	}

	enabledSiteIDs := []string{}
	disabledSiteIDs := []string{}

	for _, ts := range tenantSites {
		if ts.Config.TargetedInstanceCreation == nil {
			continue
		}
		override := *ts.Config.TargetedInstanceCreation
		if override == global {
			continue
		}
		if override {
			enabledSiteIDs = append(enabledSiteIDs, ts.SiteID.String())
		} else {
			disabledSiteIDs = append(disabledSiteIDs, ts.SiteID.String())
		}
	}

	slices.Sort(enabledSiteIDs)
	slices.Sort(disabledSiteIDs)

	if len(enabledSiteIDs) > 0 {
		caps = append(caps, APITenantAccountSiteCapability{
			Scope:                    TenantAccountSiteCapabilityScopeLimited,
			SiteIDs:                  enabledSiteIDs,
			TargetedInstanceCreation: true,
		})
	}
	if len(disabledSiteIDs) > 0 {
		caps = append(caps, APITenantAccountSiteCapability{
			Scope:                    TenantAccountSiteCapabilityScopeLimited,
			SiteIDs:                  disabledSiteIDs,
			TargetedInstanceCreation: false,
		})
	}

	return caps
}

func filterTenantSitesForAccount(ta *cdbm.TenantAccount, tenantSites []cdbm.TenantSite) []cdbm.TenantSite {
	if ta == nil || ta.TenantID == nil {
		return nil
	}

	filtered := make([]cdbm.TenantSite, 0, len(tenantSites))
	for _, ts := range tenantSites {
		if ts.Site != nil && ts.Site.InfrastructureProviderID == ta.InfrastructureProviderID {
			filtered = append(filtered, ts)
			continue
		}
		if ts.Site == nil {
			filtered = append(filtered, ts)
		}
	}
	return filtered
}

func parseSiteCapabilitySiteIDs(caps APITenantAccountSiteCapabilitiesUpdateRequest) ([]uuid.UUID, error) {
	siteIDs := []uuid.UUID{}
	for _, cap := range caps {
		if cap.Scope != TenantAccountSiteCapabilityScopeLimited {
			continue
		}
		for _, siteIDStr := range cap.SiteIDs {
			siteID, err := uuid.Parse(siteIDStr)
			if err != nil {
				return nil, err
			}
			siteIDs = append(siteIDs, siteID)
		}
	}
	return siteIDs, nil
}

func GlobalTargetedInstanceCreationFromRequest(caps APITenantAccountSiteCapabilitiesUpdateRequest) *bool {
	for _, cap := range caps {
		if cap.Scope == TenantAccountSiteCapabilityScopeGlobal {
			return cutil.GetPtr(cap.TargetedInstanceCreation)
		}
	}
	return nil
}
