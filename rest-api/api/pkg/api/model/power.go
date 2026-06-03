// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
)

const (
	PowerControlStateOn         = "on"
	PowerControlStateOff        = "off"
	PowerControlStateCycle      = "cycle"
	PowerControlStateForceOff   = "forceoff"
	PowerControlStateForceCycle = "forcecycle"
)

// ValidPowerControlStates defines the valid states for power control operations
var ValidPowerControlStates = []string{
	PowerControlStateOn,
	PowerControlStateOff,
	PowerControlStateCycle,
	PowerControlStateForceOff,
	PowerControlStateForceCycle,
}

var validPowerControlStatesAny = func() []interface{} {
	result := make([]interface{}, len(ValidPowerControlStates))
	for i, s := range ValidPowerControlStates {
		result[i] = s
	}
	return result
}()

// ========== Power Control Request ==========

// APIUpdatePowerStateRequest is the request body for power control operations
type APIUpdatePowerStateRequest struct {
	SiteID string `json:"siteId"`
	State  string `json:"state"`
}

// Validate validates the power control request
func (r *APIUpdatePowerStateRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
		validation.Field(&r.State,
			validation.Required.Error(validationErrorValueRequired),
			validation.In(validPowerControlStatesAny...).Error(
				fmt.Sprintf("must be one of %v", ValidPowerControlStates))),
	)
}

// ========== Power Control Response ==========

// APIUpdatePowerStateResponse is the API response for power control operations
type APIUpdatePowerStateResponse struct {
	TaskIDs []string `json:"taskIds"`
}

// FromProto converts an Flow SubmitTaskResponse to an APIUpdatePowerStateResponse
func (r *APIUpdatePowerStateResponse) FromProto(resp *flowv1.SubmitTaskResponse) {
	if resp == nil {
		r.TaskIDs = []string{}
		return
	}
	r.TaskIDs = make([]string, 0, len(resp.GetTaskIds()))
	for _, id := range resp.GetTaskIds() {
		r.TaskIDs = append(r.TaskIDs, id.GetId())
	}
}

// NewAPIUpdatePowerStateResponse creates an APIUpdatePowerStateResponse from an Flow SubmitTaskResponse
func NewAPIUpdatePowerStateResponse(resp *flowv1.SubmitTaskResponse) *APIUpdatePowerStateResponse {
	r := &APIUpdatePowerStateResponse{}
	r.FromProto(resp)
	return r
}

// ========== Batch Update Rack Power State Request ==========

// APIBatchUpdateRackPowerStateRequest is the JSON body for batch rack power control.
type APIBatchUpdateRackPowerStateRequest struct {
	SiteID string      `json:"siteId"`
	Filter *RackFilter `json:"filter,omitempty"`
	State  string      `json:"state"`
}

// Validate checks required fields and power state validity.
func (r *APIBatchUpdateRackPowerStateRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId is required")
	}
	return validation.ValidateStruct(r,
		validation.Field(&r.State,
			validation.Required.Error(validationErrorValueRequired),
			validation.In(validPowerControlStatesAny...).Error(
				fmt.Sprintf("must be one of %v", ValidPowerControlStates))),
	)
}

// ========== Batch Update Tray Power State Request ==========

// APIBatchUpdateTrayPowerStateRequest is the JSON body for batch tray power control.
type APIBatchUpdateTrayPowerStateRequest struct {
	SiteID string      `json:"siteId"`
	Filter *TrayFilter `json:"filter,omitempty"`
	State  string      `json:"state"`
}

// Validate checks required fields, power state validity, and filter constraints.
func (r *APIBatchUpdateTrayPowerStateRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId is required")
	}
	if err := r.Filter.Validate(); err != nil {
		return err
	}
	return validation.ValidateStruct(r,
		validation.Field(&r.State,
			validation.Required.Error(validationErrorValueRequired),
			validation.In(validPowerControlStatesAny...).Error(
				fmt.Sprintf("must be one of %v", ValidPowerControlStates))),
	)
}
