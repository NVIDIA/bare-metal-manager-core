// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"slices"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

const (
	// ErrTenantIDOrOrgRequired is returned when no tenant ID or tenant org is provided
	validationErrorTenantIDOrOrgRequired = "Either Tenant ID or Tenant Org must be specified"

	validationErrorInvalidSiteCapabilityScope = "scope must be global or limited"
	validationErrorGlobalSiteIDsNotAllowed    = "siteIds must be omitted or empty when scope is global"
	validationErrorLimitedSiteIDsRequired     = "siteIds must be specified when scope is limited"
	validationErrorDuplicateGlobalScope       = "only one global siteCapabilities entry is allowed"
	validationErrorMissingGlobalScope         = "exactly one global siteCapabilities entry is required"
	validationErrorDuplicateSiteID            = "duplicate siteIds are not allowed across siteCapabilities entries"
)

var (
	// Time when the AccountNumber, SubscriptionID, and SubscriptionTier attributes will be deprecated
	accountNumberSubscriptionIDTierDeprecationTime = time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)

	tenantAccountDeprecations = []DeprecatedEntity{
		{
			OldValue:     "accountNumber",
			Type:         DeprecationTypeAttribute,
			TakeActionBy: accountNumberSubscriptionIDTierDeprecationTime,
		},
		{
			OldValue:     "subscriptionId",
			Type:         DeprecationTypeAttribute,
			TakeActionBy: accountNumberSubscriptionIDTierDeprecationTime,
		},
		{
			OldValue:     "subscriptionTier",
			Type:         DeprecationTypeAttribute,
			TakeActionBy: accountNumberSubscriptionIDTierDeprecationTime,
		},
	}

	tenantAccountSiteCapabilityScopes = []interface{}{
		TenantAccountSiteCapabilityScopeGlobal,
		TenantAccountSiteCapabilityScopeLimited,
	}
)

// APITenantAccountCreateRequest is the data structure to capture user request to create a new Tenant
type APITenantAccountCreateRequest struct {
	// InfrastructureProviderID is the ID of the infrastructureProvider in the org
	InfrastructureProviderID string `json:"infrastructureProviderId"`
	// TenantID is the ID of the tenant
	TenantID *string `json:"tenantId"`
	// TenantOrg is the org of the tenant
	TenantOrg *string `json:"tenantOrg"`
}

// Validate ensure the values passed in request are acceptable
func (tacr APITenantAccountCreateRequest) Validate() error {
	return validation.ValidateStruct(&tacr,
		validation.Field(&tacr.InfrastructureProviderID,
			validation.When(tacr.InfrastructureProviderID != "", validationis.UUID.Error(validationErrorInvalidUUID))),
		validation.Field(&tacr.TenantID,
			validation.When(tacr.TenantOrg == nil, validation.Required.Error(validationErrorTenantIDOrOrgRequired)),
			validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&tacr.TenantOrg,
			validation.When(tacr.TenantID == nil, validation.Required.Error(validationErrorTenantIDOrOrgRequired)),
			validation.Length(2, 256).Error(validationErrorStringLength)),
	)
}

// APITenantAccountUpdateRequest is the data structure to capture user request to update a TenantAccount
type APITenantAccountUpdateRequest struct {
	// TenantContactID is the ID of the requesting user
	TenantContactID *string `json:"tenantContactId"`
	// SiteCapabilities replaces the provider-scoped capability configuration for the
	// TenantAccount. It is a pointer so an omitted payload (nil) is distinguishable
	// from a supplied-but-empty payload (non-nil, zero length), which is rejected.
	SiteCapabilities *APITenantAccountSiteCapabilitiesUpdateRequest `json:"siteCapabilities"`
}

// Validate ensure the values passed in request are acceptable
func (taur APITenantAccountUpdateRequest) Validate() error {
	return validation.ValidateStruct(&taur,
		validation.Field(&taur.TenantContactID,
			validationis.UUID.Error(validationErrorInvalidUUID)),
	)
}

// HasSiteCapabilities reports whether the request supplied a siteCapabilities replace
// payload at all. A supplied payload (including an explicit empty array) is considered
// present; only an omitted or JSON-null field is treated as absent.
func (taur APITenantAccountUpdateRequest) HasSiteCapabilities() bool {
	return taur.SiteCapabilities != nil
}

// TenantAccountSiteCapabilityScope identifies whether a capability entry applies globally
// or to an explicit set of sites.
type TenantAccountSiteCapabilityScope string

const (
	TenantAccountSiteCapabilityScopeGlobal  TenantAccountSiteCapabilityScope = "global"
	TenantAccountSiteCapabilityScopeLimited TenantAccountSiteCapabilityScope = "limited"
)

// APITenantAccountSiteCapability describes the TargetedInstanceCreation capability for
// either all sites (global) or an explicit site list (limited). Used in responses.
type APITenantAccountSiteCapability struct {
	SiteIDs                  []string                         `json:"siteIds,omitempty"`
	Scope                    TenantAccountSiteCapabilityScope `json:"scope"`
	TargetedInstanceCreation bool                             `json:"targetedInstanceCreation"`
}

// APITenantAccountSiteCapabilityUpdate is the replace payload entry for Provider Admin
// capability updates. targetedInstanceCreation must be present on every entry so an
// omitted field cannot silently bind as false.
type APITenantAccountSiteCapabilityUpdate struct {
	SiteIDs                  []string                         `json:"siteIds,omitempty"`
	Scope                    TenantAccountSiteCapabilityScope `json:"scope"`
	TargetedInstanceCreation *bool                            `json:"targetedInstanceCreation"`
}

// APITenantAccountSiteCapabilitiesUpdateRequest is the replace payload for Provider Admin
// capability updates on a TenantAccount.
type APITenantAccountSiteCapabilitiesUpdateRequest []APITenantAccountSiteCapabilityUpdate

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
			validation.Field(&cap.TargetedInstanceCreation,
				validation.Required.Error(validationErrorValueRequired)),
			validation.Field(&cap.SiteIDs,
				validation.When(cap.Scope == TenantAccountSiteCapabilityScopeGlobal,
					validation.Empty.Error(validationErrorGlobalSiteIDsNotAllowed)),
				validation.When(cap.Scope == TenantAccountSiteCapabilityScopeLimited,
					validation.Required.Error(validationErrorLimitedSiteIDsRequired),
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
			// Normalize to the canonical UUID string so differently formatted
			// representations of the same Site (case, urn prefix) dedupe. The
			// values are already validated as UUIDs above, so parsing succeeds.
			parsed, perr := uuid.Parse(siteID)
			if perr != nil {
				return validation.Errors{prefix: fmt.Errorf(validationErrorInvalidUUID)}
			}
			key := parsed.String()
			if _, ok := seenSiteIDs[key]; ok {
				return validation.Errors{"siteCapabilities": fmt.Errorf(validationErrorDuplicateSiteID)}
			}
			seenSiteIDs[key] = struct{}{}
		}
	}

	if globalCount == 0 {
		return validation.Errors{"siteCapabilities": fmt.Errorf(validationErrorMissingGlobalScope)}
	}
	if globalCount > 1 {
		return validation.Errors{"siteCapabilities": fmt.Errorf(validationErrorDuplicateGlobalScope)}
	}

	return nil
}

// APITenantAccount is the data structure to capture API representation of a TenantAccount
type APITenantAccount struct {
	// ID is the unique UUID v4 identifier for the TenantAccount
	ID string `json:"id"`
	// AccountNumber is the account number of the TenantAccount
	AccountNumberDeprecated *string `json:"accountNumber,omitempty"`
	// InfrastructureProviderID is the ID of the InfrastructureProvider
	InfrastructureProviderID string `json:"infrastructureProviderId"`
	// InfrastructureProvider is the summary of the InfrastructureProvider
	InfrastructureProvider *APIInfrastructureProviderSummary `json:"infrastructureProvider,omitempty"`
	// InfrastructureProviderOrg is the org of the InfrastructureProvider
	InfrastructureProviderOrg string `json:"infrastructureProviderOrg"`
	// SubscriptionID is the ID of the subscription
	SubscriptionIDDeprecated *string `json:"subscriptionId,omitempty"`
	// SubscriptionTier is the tier of the subscription
	SubscriptionTierDeprecated *string `json:"subscriptionTier,omitempty"`
	// TenantID is the ID of the Tenant
	TenantID *string `json:"tenantId"`
	// Tenant is the summary of the Tenant
	Tenant *APITenantSummary `json:"tenant,omitempty"`
	// TenantOrg is the org of the Tenant
	TenantOrg string `json:"tenantOrg"`
	// TenantContact is the the contact user for the tenant
	TenantContact *APIUser `json:"tenantContact"`
	// AllocationCount is the number of allocations for the TenantAccount
	AllocationCount int `json:"allocationCount"`
	// Status is the status of the TenantAccount
	Status string `json:"status"`
	// StatusHistory is the history of statuses for the TenantAccount
	StatusHistory []APIStatusDetail `json:"statusHistory"`
	// CreatedAt indicates the ISO datetime string for when the entity was created
	Created time.Time `json:"created"`
	// UpdatedAt indicates the ISO datetime string for when the entity was last updated
	Updated time.Time `json:"updated"`
	// Deprecations is the list of deprecations for the TenantAccount
	Deprecations []APIDeprecation `json:"deprecations"`
	// SiteCapabilities describes provider-scoped TargetedInstanceCreation settings
	SiteCapabilities []APITenantAccountSiteCapability `json:"siteCapabilities,omitempty"`
}

// APITenantAccountStats is a data structure to capture information about a TenantAccount stats at the API layer
type APITenantAccountStats struct {
	// Total is the total number of the TenantAccount object in NICo Cloud
	Total int `json:"total"`
	// Pending is the total number of pending TenantAccount object in NICo Cloud
	Pending int `json:"pending"`
	// Invited is the total number of provisioning TenantAccount object in NICo Cloud
	Invited int `json:"invited"`
	// Ready is the total number of ready TenantAccount object in NICo Cloud
	Ready int `json:"ready"`
	// Error is the total number of error TenantAccount object in NICo Cloud
	Error int `json:"error"`
}

// NewAPITenantAccount accepts a DB layer TenantAccount object returns an API layer object
func NewAPITenantAccount(dbta *cdbm.TenantAccount, dbsds []cdbm.StatusDetail, allocationCount int, tenantSites []cdbm.TenantSite) *APITenantAccount {
	apiTenantAccount := APITenantAccount{
		ID:                        dbta.ID.String(),
		InfrastructureProviderID:  dbta.InfrastructureProviderID.String(),
		InfrastructureProviderOrg: dbta.InfrastructureProviderOrg,
		TenantOrg:                 dbta.TenantOrg,
		AllocationCount:           allocationCount,
		Status:                    dbta.Status,
		Created:                   dbta.Created,
		Updated:                   dbta.Updated,
	}

	if dbta.TenantID != nil {
		apiTenantAccount.TenantID = cutil.GetPtr(dbta.TenantID.String())
	}

	if dbta.TenantContact != nil {
		apiTenantAccount.TenantContact = NewAPIUserFromDBUser(*dbta.TenantContact)
	}

	if dbta.InfrastructureProvider != nil {
		apiTenantAccount.InfrastructureProvider = NewAPIInfrastructureProviderSummary(dbta.InfrastructureProvider)
	}

	if dbta.Tenant != nil {
		apiTenantAccount.Tenant = NewAPITenantSummary(dbta.Tenant)
	}

	apiTenantAccount.StatusHistory = []APIStatusDetail{}
	for _, dbsd := range dbsds {
		apiTenantAccount.StatusHistory = append(apiTenantAccount.StatusHistory, NewAPIStatusDetail(dbsd))
	}

	if time.Now().Before(accountNumberSubscriptionIDTierDeprecationTime) {
		apiTenantAccount.AccountNumberDeprecated = cutil.GetPtr(dbta.AccountNumber)
		apiTenantAccount.SubscriptionIDDeprecated = dbta.SubscriptionID
		apiTenantAccount.SubscriptionTierDeprecated = dbta.SubscriptionTier
	}

	for _, deprecation := range tenantAccountDeprecations {
		apiTenantAccount.Deprecations = append(apiTenantAccount.Deprecations, NewAPIDeprecation(deprecation))
	}

	global := dbta.Config.TargetedInstanceCreation
	caps := []APITenantAccountSiteCapability{
		{
			Scope:                    TenantAccountSiteCapabilityScopeGlobal,
			TargetedInstanceCreation: global,
		},
	}

	if dbta.TenantID != nil {
		enabledSiteIDs := []string{}
		disabledSiteIDs := []string{}

		for _, ts := range tenantSites {
			// Fail closed: a TenantSite with a missing Site relation cannot be
			// confirmed to belong to this account's provider, so it is excluded.
			if ts.Site == nil || ts.Site.InfrastructureProviderID != dbta.InfrastructureProviderID {
				continue
			}
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
	}

	apiTenantAccount.SiteCapabilities = caps

	return &apiTenantAccount
}
