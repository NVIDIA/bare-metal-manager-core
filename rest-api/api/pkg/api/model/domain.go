// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"

	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

// APIDomainCreateRequest is the request body for creating a tenant-owned DNS Domain.
type APIDomainCreateRequest struct {
	Name   string `json:"name"`
	SiteID string `json:"siteId"`
}

// Validate checks the Domain create request before it is sent to Core.
func (dcr APIDomainCreateRequest) Validate() error {
	return validation.ValidateStruct(&dcr,
		validation.Field(&dcr.Name, validation.Required.Error(validationErrorValueRequired)),
		validation.Field(&dcr.SiteID,
			validation.Required.Error(validationErrorValueRequired),
			validationis.UUID.Error(validationErrorInvalidUUID)),
	)
}

// ToProto converts a validated REST request into Core's Domain create request.
func (dcr APIDomainCreateRequest) ToProto() *corev1.CreateDomainRequest {
	return &corev1.CreateDomainRequest{Name: dcr.Name}
}

// APIDomain is the tenant-facing representation of a DNS Domain.
type APIDomain struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	SiteID  string    `json:"siteId"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// NewAPIDomain converts an owned REST DB projection to its public representation.
func NewAPIDomain(domain *cdbm.Domain) *APIDomain {
	if domain == nil {
		return nil
	}

	siteID := ""
	if domain.SiteID != nil {
		siteID = domain.SiteID.String()
	}

	return &APIDomain{
		ID:      domain.ID.String(),
		Name:    domain.Hostname,
		SiteID:  siteID,
		Created: domain.Created,
		Updated: domain.Updated,
	}
}
