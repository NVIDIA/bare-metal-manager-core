// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"time"

	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"
)

// APIVpcPeeringCreateRequest captures the request data for creating a new VPC peering
type APIVpcPeeringCreateRequest struct {
	// The order of VPCs is not important, the VPC peering is bidirectional.
	// Vpc1ID is the ID of one VPC in the peering
	Vpc1ID string `json:"vpc1Id"`
	// Vpc2ID is the ID of the other VPC in the peering
	Vpc2ID string `json:"vpc2Id"`
	// SiteID is the ID of the Site where the peering exists
	SiteID string `json:"siteId"`
}

// Validate ensures the values passed in create request are acceptable
func (vpcr APIVpcPeeringCreateRequest) Validate() error {
	err := validation.ValidateStruct(&vpcr,
		validation.Field(&vpcr.Vpc1ID,
			validation.Required.Error(validationErrorValueRequired),
			validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&vpcr.Vpc2ID,
			validation.Required.Error(validationErrorValueRequired),
			validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&vpcr.SiteID,
			validation.Required.Error(validationErrorValueRequired),
			validationis.UUID.Error(validationErrorInvalidUUID)),
	)
	if err != nil {
		return err
	}

	// Validate that the VPCs are different
	if vpcr.Vpc1ID == vpcr.Vpc2ID {
		return validation.Errors{
			"vpc2Id": errors.New("Cannot be the same value as `vpc1Id`"),
		}
	}
	return nil
}

// APIVpcPeering represents a VPC peering connection
type APIVpcPeering struct {
	// ID is the unique UUID v4 identifier of the VPC peering in NICo Cloud
	ID string `json:"id"`
	// Vpc1ID is the ID of the first VPC in the peering
	Vpc1ID string `json:"vpc1Id"`
	// Vpc1 is the summary of the first VPC in the peering
	Vpc1 *APIVpcSummary `json:"vpc1,omitempty"`
	// Vpc2ID is the ID of the second VPC in the peering
	Vpc2ID string `json:"vpc2Id"`
	// Vpc2 is the summary of the second VPC in the peering
	Vpc2 *APIVpcSummary `json:"vpc2,omitempty"`
	// SiteID is the ID of the Site where the peering exists
	SiteID string `json:"siteId"`
	// Site is the summary of the site
	Site *APISiteSummary `json:"site,omitempty"`
	// IsMultiTenant indicates if this is a multi-tenant peering
	IsMultiTenant bool `json:"isMultiTenant"`
	// Status is the status of the VPC peering
	Status string `json:"status"`
	// CreatedAt indicates the ISO datetime string for when the entity was created
	Created time.Time `json:"created"`
	// Updated indicates the ISO datetime string for when the VPC peering was last updated
	Updated time.Time `json:"updated"`
}

// NewAPIVpcPeering creates a new APIVpcPeering from a database VPC peering model
func NewAPIVpcPeering(dbVpcPeering cdbm.VpcPeering) APIVpcPeering {
	apiVpcPeering := APIVpcPeering{
		ID:            dbVpcPeering.ID.String(),
		Vpc1ID:        dbVpcPeering.Vpc1ID.String(),
		Vpc2ID:        dbVpcPeering.Vpc2ID.String(),
		SiteID:        dbVpcPeering.SiteID.String(),
		IsMultiTenant: dbVpcPeering.IsMultiTenant,
		Status:        dbVpcPeering.Status,
		Created:       dbVpcPeering.Created,
		Updated:       dbVpcPeering.Updated,
	}

	// Expand relations if available.
	if dbVpcPeering.Vpc1 != nil {
		apiVpcPeering.Vpc1 = NewAPIVpcSummary(dbVpcPeering.Vpc1)
	}
	if dbVpcPeering.Vpc2 != nil {
		apiVpcPeering.Vpc2 = NewAPIVpcSummary(dbVpcPeering.Vpc2)
	}
	if dbVpcPeering.Site != nil {
		apiVpcPeering.Site = NewAPISiteSummary(dbVpcPeering.Site)
	}

	return apiVpcPeering
}

// APIVpcPeeringSummary represents a summary of a VPC peering connection
type APIVpcPeeringSummary struct {
	// ID is the unique UUID v4 identifier of the VPC peering in NICo Cloud
	ID string `json:"id"`
	// Vpc1ID is the ID of the first VPC in the peering
	Vpc1ID string `json:"vpc1Id"`
	// Vpc2ID is the ID of the second VPC in the peering
	Vpc2ID string `json:"vpc2Id"`
	// IsMultiTenant indicates if this is a multi-tenant peering
	IsMultiTenant bool `json:"isMultiTenant"`
	// Status is the status of the VPC peering
	Status string `json:"status"`
}

// NewAPIVpcPeeringSummary creates a new APIVpcPeeringSummary from a database VPC peering model
func NewAPIVpcPeeringSummary(dbVpcPeering *cdbm.VpcPeering) *APIVpcPeeringSummary {
	if dbVpcPeering == nil {
		return nil
	}
	return &APIVpcPeeringSummary{
		ID:            dbVpcPeering.ID.String(),
		Vpc1ID:        dbVpcPeering.Vpc1ID.String(),
		Vpc2ID:        dbVpcPeering.Vpc2ID.String(),
		Status:        dbVpcPeering.Status,
		IsMultiTenant: dbVpcPeering.IsMultiTenant,
	}
}
