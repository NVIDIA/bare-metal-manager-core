// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
)

const (
	// ErrTenantIDOrOrgRequired is returned when no tenant ID or tenant org is provided
	validationErrorTenantIDOrOrgRequired = "Either Tenant ID or Tenant Org must be specified"
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
			validation.Required.Error(validationErrorValueRequired),
			validationis.UUID.Error(validationErrorInvalidUUID)),
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
}

// Validate ensure the values passed in request are acceptable
func (taur APITenantAccountUpdateRequest) Validate() error {
	return validation.ValidateStruct(&taur,
		validation.Field(&taur.TenantContactID,
			validationis.UUID.Error(validationErrorInvalidUUID)),
	)
}

// APITenantAccount is the data structure to capture API representation of a TenantAccount
type APITenantAccount struct {
	// ID is the unique UUID v4 identifier for the TenantAccount
	ID string `json:"id"`
	// AccountNumber is the account number of the TenantAccount
	AccountNumber string `json:"accountNumber"`
	// InfrastructureProviderID is the ID of the InfrastructureProvider
	InfrastructureProviderID string `json:"infrastructureProviderId"`
	// InfrastructureProvider is the summary of the InfrastructureProvider
	InfrastructureProvider *APIInfrastructureProviderSummary `json:"infrastructureProvider,omitempty"`
	// InfrastructureProviderOrg is the org of the InfrastructureProvider
	InfrastructureProviderOrg string `json:"infrastructureProviderOrg"`
	// SubscriptionID is the ID of the subscription
	SubscriptionID *string `json:"subscriptionId"`
	// SubscriptionTier is the tier of the subscription
	SubscriptionTier *string `json:"subscriptionTier"`
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
func NewAPITenantAccount(dbta *cdbm.TenantAccount, dbsds []cdbm.StatusDetail, allocationCount int) *APITenantAccount {
	apiTenantAccount := APITenantAccount{
		ID:                        dbta.ID.String(),
		AccountNumber:             dbta.AccountNumber,
		InfrastructureProviderID:  dbta.InfrastructureProviderID.String(),
		InfrastructureProviderOrg: dbta.InfrastructureProviderOrg,
		SubscriptionID:            dbta.SubscriptionID,
		SubscriptionTier:          dbta.SubscriptionTier,
		TenantOrg:                 dbta.TenantOrg,
		AllocationCount:           allocationCount,
		Status:                    dbta.Status,
		Created:                   dbta.Created,
		Updated:                   dbta.Updated,
	}

	if dbta.TenantID != nil {
		apiTenantAccount.TenantID = cdb.GetStrPtr(dbta.TenantID.String())
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

	for _, dbsd := range dbsds {
		apiTenantAccount.StatusHistory = append(apiTenantAccount.StatusHistory, NewAPIStatusDetail(dbsd))
	}

	return &apiTenantAccount
}
