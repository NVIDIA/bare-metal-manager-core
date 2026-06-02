// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"

	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model/util"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	ipam "github.com/NVIDIA/infra-controller-rest/ipam"
)

const (
	// VpcPrefixBlockSizeMin is the minimum value of the VpcPrefixSize field
	VpcPrefixBlockSizeMin = 8
	// VpcPrefixBlockSizeMax is the maximum value of the VpcPrefixSize field
	VpcPrefixBlockSizeMax = 31

	validationErrorIPBlockIDRequired     = "IPBlockID is required in request"
	validationErrorVpcPrefixBlockSizeMin = "prefixLength must be at least 8"
	validationErrorVpcPrefixBlockSizeMax = "prefixLength must be at most 31"
)

// APIVpcPrefixCreateRequest is the data structure to capture user request to create a new VpcPrefix
type APIVpcPrefixCreateRequest struct {
	// Name is the name of the VpcPrefix
	Name string `json:"name"`
	// VpcID is the ID of the vpc containing the VpcPrefix
	VpcID string `json:"vpcId"`
	// IPBlockID is the derived ipBlockId for the tenant from an allocation
	IPBlockID *string `json:"ipBlockId"`
	// PrefixLength is the length of the prefix
	PrefixLength int `json:"prefixLength"`
}

// Validate ensure the values passed in request are acceptable
func (vpcr APIVpcPrefixCreateRequest) Validate() error {
	err := validation.ValidateStruct(&vpcr,
		validation.Field(&vpcr.Name,
			validation.Required.Error(validationErrorStringLength),
			validation.Length(2, 256).Error(validationErrorStringLength)),
		validation.Field(&vpcr.VpcID,
			validation.Required.Error(validationErrorValueRequired),
			validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&vpcr.IPBlockID,
			validation.Required.Error(validationErrorIPBlockIDRequired),
			validation.When(vpcr.IPBlockID != nil, validationis.UUID.Error(validationErrorInvalidUUID))),
		validation.Field(&vpcr.PrefixLength,
			validation.Required.Error(validationErrorValueRequired),
			validation.Min(VpcPrefixBlockSizeMin).Error(validationErrorVpcPrefixBlockSizeMin),
			validation.Max(VpcPrefixBlockSizeMax).Error(validationErrorVpcPrefixBlockSizeMax)),
	)

	if err != nil {
		return err
	}

	return nil
}

// APIVpcPrefixUpdateRequest is the data structure to capture user request to update a VpcPrefix
type APIVpcPrefixUpdateRequest struct {
	// Name is the name of the VpcPrefix
	Name *string `json:"name"`
	// IPBlockID is the derived ipBlockId for the tenant from an allocation
	IPBlockID *string `json:"ipBlockId"`
	// PrefixLength is the length of the prefix
	PrefixLength *int `json:"prefixLength"`
}

// Validate ensure the values passed in request are acceptable
func (vpur APIVpcPrefixUpdateRequest) Validate() error {
	err := validation.ValidateStruct(&vpur,
		validation.Field(&vpur.Name,
			// length validation rule accepts empty string as valid, hence, required is needed
			validation.When(vpur.Name != nil, validation.Required.Error(validationErrorStringLength)),
			validation.When(vpur.Name != nil, validation.Length(2, 256).Error(validationErrorStringLength))),
	)

	if vpur.IPBlockID != nil || vpur.PrefixLength != nil {
		return validation.Errors{
			"prefixLength": errors.New("prefix length modification is not supported at this time"),
		}
	}

	if err != nil {
		return err
	}

	return nil
}

// APIVpcPrefix is the data structure to capture API representation of a VpcPrefix
type APIVpcPrefix struct {
	// ID is the unique UUID v4 identifier for the VpcPrefix
	ID string `json:"id"`
	// Name is the name of the VpcPrefix
	Name string `json:"name"`
	// SiteID is the ID of the Site containing the VpcPrefix
	SiteID string `json:"siteId"`
	// Site is the summary of the Site
	Site *APISiteSummary `json:"site,omitempty"`
	// VpcID is the ID of the Vpc containing the VpcPrefix
	VpcID string `json:"vpcId"`
	// Vpc is the summary of the VPC
	Vpc *APIVpcSummary `json:"vpc,omitempty"`
	// IPBlockID is the derived IPBlockId for the tenant from an allocation
	IPBlockID *string `json:"ipBlockId"`
	// IPBlock is the summary of the IPBlock
	IPBlock *APIIPBlockSummary `json:"ipBlock,omitempty"`
	// Prefix includes both IP address and the length of the network, for example: 192.168.1.0/24
	Prefix *string `json:"prefix"`
	// PrefixLength is the length of the network prefix
	PrefixLength int `json:"prefixLength"`
	// Status is the status of the VpcPrefix
	Status string `json:"status"`
	// StatusHistory is the history of statuses for the VpcPrefix
	StatusHistory []APIStatusDetail `json:"statusHistory"`
	// UsageStats reports IPv4 usage from VpcPrefixDAO.GetPrefixUsage (in-memory IPAM over /31s from interface IPs) when requested via includeUsageStats
	UsageStats *APIIPBlockUsageStats `json:"usageStats,omitempty"`
	// CreatedAt indicates the ISO datetime string for when the entity was created
	Created time.Time `json:"created"`
	// UpdatedAt indicates the ISO datetime string for when the entity was last updated
	Updated time.Time `json:"updated"`
}

// NewAPIVpcPrefix accepts a DB layer objects and returns an API layer object
func NewAPIVpcPrefix(dbvp *cdbm.VpcPrefix, dbsds []cdbm.StatusDetail, dbpu *ipam.Usage) *APIVpcPrefix {
	apiVpcPrefix := APIVpcPrefix{
		ID:           dbvp.ID.String(),
		Name:         dbvp.Name,
		SiteID:       dbvp.SiteID.String(),
		VpcID:        dbvp.VpcID.String(),
		IPBlockID:    util.GetUUIDPtrToStrPtr(dbvp.IPBlockID),
		Prefix:       &dbvp.Prefix,
		PrefixLength: dbvp.PrefixLength,
		Status:       dbvp.Status,
		Created:      dbvp.Created,
		Updated:      dbvp.Updated,
	}

	if dbpu != nil {
		apiVpcPrefix.UsageStats = &APIIPBlockUsageStats{
			AvailableIPs:              dbpu.AvailableIPs,
			AcquiredIPs:               dbpu.AcquiredIPs,
			AvailablePrefixes:         dbpu.AvailablePrefixes,
			AcquiredPrefixes:          dbpu.AcquiredPrefixes,
			AvailableSmallestPrefixes: dbpu.AvailableSmallestPrefixes,
		}
	}

	apiVpcPrefix.StatusHistory = []APIStatusDetail{}
	for _, dbsd := range dbsds {
		apiVpcPrefix.StatusHistory = append(apiVpcPrefix.StatusHistory, NewAPIStatusDetail(dbsd))
	}

	if dbvp.Site != nil {
		apiVpcPrefix.Site = NewAPISiteSummary(dbvp.Site)
	}

	if dbvp.Vpc != nil {
		apiVpcPrefix.Vpc = NewAPIVpcSummary(dbvp.Vpc)
	}

	if dbvp.IPBlock != nil {
		apiVpcPrefix.IPBlock = NewAPIIPBlockSummary(dbvp.IPBlock)
	}

	return &apiVpcPrefix
}

// APIVpcPrefixSummary is the data structure to capture API summary of a VpcPrefix
type APIVpcPrefixSummary struct {
	// ID is the unique UUID v4 identifier for the VpcPrefix
	ID string `json:"id"`
	// Name of the VpcPrefix, only lowercase characters, digits, hyphens and cannot begin/end with hyphen
	Name string `json:"name"`
	// Prefix is the prefix of the network in CIDR notation
	Prefix *string `json:"prefix"`
	// PrefixLength is the length of the network prefix of this VpcPrefix
	PrefixLength int `json:"prefixLength"`
}

// NewAPIVpcPrefixSummary accepts a DB layer VpcPrefix object returns an API layer object
func NewAPIVpcPrefixSummary(dbvp *cdbm.VpcPrefix) *APIVpcPrefixSummary {
	apiVpcPrefixSummary := APIVpcPrefixSummary{
		ID:           dbvp.ID.String(),
		Name:         dbvp.Name,
		Prefix:       &dbvp.Prefix,
		PrefixLength: dbvp.PrefixLength,
	}
	return &apiVpcPrefixSummary
}
