// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

var (
	// Time when the Machine/InstanceType association ID attribute will be deprecated.
	machineInstanceTypeAssociationIDDeprecationTime, _ = time.Parse(time.RFC1123, "Thu, 09 Jul 2026 00:00:00 UTC")

	machineInstanceTypeDeprecations = []DeprecatedEntity{
		{
			OldValue:     "id",
			NewValue:     cdb.GetStrPtr("machineId"),
			Type:         DeprecationTypeAttribute,
			TakeActionBy: machineInstanceTypeAssociationIDDeprecationTime,
		},
	}
)

// APIMachineInstanceTypeCreateRequest is the data structure to capture user request to create a new MachineInstanceType
type APIMachineInstanceTypeCreateRequest struct {
	// MachineID is the ID of the Machine
	MachineIDs []string `json:"machineIds"`
}

// Validate ensure the values passed in request are acceptable
func (mitcr *APIMachineInstanceTypeCreateRequest) Validate() error {
	err := validation.ValidateStruct(mitcr,
		validation.Field(&mitcr.MachineIDs,
			validation.Required.Error("at least one machine ID is required"),
		),
	)
	return err
}

// ToProto builds the workflow request that asks a Site to associate the
// supplied Machines with `it`. The InstanceType ID is sourced from the
// just-fetched DB record; the request-body Machine IDs pass through.
//
// The method trusts that the request has already been Validated and
// that the handler has performed any cross-context checks Validate
// cannot see (RBAC, ownership, capability match against the
// InstanceType, etc.).
func (mitcr *APIMachineInstanceTypeCreateRequest) ToProto(it *cdbm.InstanceType) *cwssaws.AssociateMachinesWithInstanceTypeRequest {
	return &cwssaws.AssociateMachinesWithInstanceTypeRequest{
		InstanceTypeId: it.ID.String(),
		MachineIds:     mitcr.MachineIDs,
	}
}

// APIMachineInstanceType is the data structure to capture Machine Instance Type
type APIMachineInstanceType struct {
	// ID is the unique UUID v4 identifier for the Machine Instance Type
	ID string `json:"id"`
	// MachineID is the ID of the associated Machine
	MachineID string `json:"machineId"`
	// InstanceTypeID is the ID of the associated Instance Type
	InstanceTypeID string `json:"instanceTypeId"`
	// Deprecations is the list of deprecation messages denoting fields which are being deprecated
	Deprecations []APIDeprecation `json:"deprecations,omitempty"`
	// Created is the date and time the Machine Instance Type was created
	Created time.Time `json:"created"`
	// Updated is the date and time the Machine Instance Type was last updated
	Updated time.Time `json:"updated"`
}

// NewAPIMachineInstanceType creates a new APIMachineInstanceType
func NewAPIMachineInstanceType(dbmit *cdbm.MachineInstanceType) *APIMachineInstanceType {
	apiMachineInstanceType := &APIMachineInstanceType{
		ID:             dbmit.ID.String(),
		MachineID:      dbmit.MachineID,
		InstanceTypeID: dbmit.InstanceTypeID.String(),
		Created:        dbmit.Created,
		Updated:        dbmit.Updated,
	}

	// Populate deprecation metadata for deprecated response fields.
	for _, deprecation := range machineInstanceTypeDeprecations {
		apiMachineInstanceType.Deprecations = append(apiMachineInstanceType.Deprecations, NewAPIDeprecation(deprecation))
	}

	return apiMachineInstanceType
}
