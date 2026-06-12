// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"

	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

var (
	// errMsgTenantCreateEndpointDeprecated is the error message to indicate that create endpoint is deprecated
	ErrMsgTenantCreateEndpointDeprecated = "POST '/org/:orgName/nico/tenant' endpoint has been deprecated"

	// errMsgTenantUpdateEndpointDeprecated is the error message to indicate that update endpoint is deprecated
	ErrMsgTenantUpdateEndpointDeprecated = "PATCH '/org/:orgName/nico/tenant/current' endpoint has been deprecated"
)

// APITenant is the data structure to capture API representation of a Tenant
type APITenant struct {
	// ID is the unique UUID v4 identifier for the Tenant
	ID string `json:"id"`
	// Org contains the name of the org the Tenant belongs to
	Org string `json:"org"`
	// OrgDisplayName contains the display name of the org the Tenant belongs to
	OrgDisplayName *string `json:"orgDisplayName"`
	// CreatedAt indicates the ISO datetime string for when the entity was created
	Created time.Time `json:"created"`
	// UpdatedAt indicates the ISO datetime string for when the entity was last updated
	Updated time.Time `json:"updated"`
	// Capabilities describes tenant-level feature flags
	Capabilities *APITenantCapabilities `json:"capabilities"`
}

// NewAPITenant accepts a DB layer Tenant object returns an API layer object
func NewAPITenant(dbtn *cdbm.Tenant) *APITenant {
	atn := APITenant{
		ID:             dbtn.ID.String(),
		Org:            dbtn.Org,
		OrgDisplayName: dbtn.OrgDisplayName,
		Capabilities:   tenantToAPITenantCapabilities(dbtn),
		Created:        dbtn.Created,
		Updated:        dbtn.Updated,
	}

	return &atn
}

// APITenantCapabilities holds the model of tenant capabilities
type APITenantCapabilities struct {
	TargetedInstanceCreation bool `json:"targetedInstanceCreation"`
}

func tenantToAPITenantCapabilities(tenant *cdbm.Tenant) *APITenantCapabilities {
	apiCaps := &APITenantCapabilities{}

	if tenant.Config != nil {
		apiCaps.TargetedInstanceCreation = tenant.Config.TargetedInstanceCreation
	}
	return apiCaps
}

// APITenantSummary is the data structure to capture API representation of a Tenant Summary
type APITenantSummary struct {
	// Org contains the name of the org this tenant belongs to
	Org string `json:"org"`
	// OrgDisplayName contains the display name of the org the Tenant belongs to
	OrgDisplayName *string `json:"orgDisplayName"`
	// Capabilities hold the capabilities, currently for use as tenant-level feature flagging
	Capabilities *APITenantCapabilities `json:"capabilities"`
}

// NewAPITenantSummary accepts a DB layer APITenantSummary object returns an API layer object
func NewAPITenantSummary(dbtn *cdbm.Tenant) *APITenantSummary {
	atn := APITenantSummary{
		Org:            dbtn.Org,
		OrgDisplayName: dbtn.OrgDisplayName,
		Capabilities:   tenantToAPITenantCapabilities(dbtn),
	}

	return &atn
}

// APIInstanceStat holds aggregated instance status counts at the API layer.
type APIInstanceStat = cdbm.InstanceStatusCounts

// APITenantStats is the data structure to capture API representation of a Tenant Stats
type APITenantStats struct {
	// Instance holds aggregated instance status counts for the tenant.
	Instance APIInstanceStat `json:"instance"`
	// Vpc is the data structure to capture API representation of a Vpc Stats associated with tenant
	Vpc APIVpcStats `json:"vpc"`
	// Subnet is the data structure to capture API representation of a Subnet Stats associated with tenant
	Subnet APISubnetStats `json:"subnet"`
	// TenantAccount is the data structure to capture API representation of a TenantAccount Stats associated with tenant
	TenantAccount APITenantAccountStats `json:"tenantAccount"`
}

// NewAPITenantStats accepts stats for each object and returns an API layer object
func NewAPITenantStats(instanceStats APIInstanceStat, vpcstatsmap map[string]int, subnetstatmap map[string]int, tastatsmap map[string]int) *APITenantStats {
	ats := APITenantStats{
		Vpc: APIVpcStats{
			Total:        vpcstatsmap["total"],
			Pending:      vpcstatsmap[cdbm.VpcStatusPending],
			Provisioning: vpcstatsmap[cdbm.VpcStatusProvisioning],
			Ready:        vpcstatsmap[cdbm.VpcStatusReady],
			Error:        vpcstatsmap[cdbm.VpcStatusError],
			Deleting:     vpcstatsmap[cdbm.VpcStatusDeleting],
		},
		Instance: instanceStats,
		Subnet: APISubnetStats{
			Total:        subnetstatmap["total"],
			Pending:      subnetstatmap[cdbm.SubnetStatusPending],
			Provisioning: subnetstatmap[cdbm.SubnetStatusProvisioning],
			Ready:        subnetstatmap[cdbm.SubnetStatusReady],
			Error:        subnetstatmap[cdbm.SubnetStatusError],
			Deleting:     subnetstatmap[cdbm.SubnetStatusDeleting],
		},
		TenantAccount: APITenantAccountStats{
			Total:   tastatsmap["total"],
			Pending: tastatsmap[cdbm.TenantAccountStatusPending],
			Invited: tastatsmap[cdbm.TenantAccountStatusInvited],
			Ready:   tastatsmap[cdbm.TenantAccountStatusReady],
			Error:   tastatsmap[cdbm.TenantAccountStatusError],
		},
	}

	return &ats
}
