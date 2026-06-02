// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"

	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
)

// ========== Firmware Update Request ==========

// APIUpdateFirmwareRequest is the request body for firmware update operations
type APIUpdateFirmwareRequest struct {
	SiteID  string  `json:"siteId"`
	Version *string `json:"version,omitempty"`
	// Targets, when non-empty, restricts the update to a subset of
	// firmware sub-parts within the targeted tray (e.g. ["bmc", "nvos"]
	// for switch trays). Names are lowercase. The authoritative supported
	// set per tray type is derived from the Flow service's NICo proto
	// bindings (mirroring Core's per-tray-type enums in
	// carbide-core/crates/rpc/proto/forge.proto); see
	// flow/pkg/common/firmwarecomponents for the resolution logic and
	// helpers like SupportedNICoNVSwitchNames.
	// Empty/nil means "update everything in the bundle". When non-empty,
	// requires Version.
	//
	// REST surface intentionally calls these "targets" to avoid confusion
	// with carbide's tray-level "Component" vocabulary; the downstream
	// Flow proto field is named `sub_targets` and represents the same
	// enum subset.
	Targets []string `json:"targets,omitempty"`
}

// Validate validates the firmware update request
func (r *APIUpdateFirmwareRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId is required")
	}
	return validateFirmwareTargets(r.Targets, r.Version)
}

// ========== Firmware Update Response ==========

// APIUpdateFirmwareResponse is the API response for firmware update operations
type APIUpdateFirmwareResponse struct {
	TaskIDs []string `json:"taskIds"`
}

// FromProto converts an Flow SubmitTaskResponse to an APIUpdateFirmwareResponse
func (r *APIUpdateFirmwareResponse) FromProto(resp *flowv1.SubmitTaskResponse) {
	if resp == nil {
		r.TaskIDs = []string{}
		return
	}
	r.TaskIDs = make([]string, 0, len(resp.GetTaskIds()))
	for _, id := range resp.GetTaskIds() {
		r.TaskIDs = append(r.TaskIDs, id.GetId())
	}
}

// NewAPIUpdateFirmwareResponse creates an APIUpdateFirmwareResponse from an Flow SubmitTaskResponse
func NewAPIUpdateFirmwareResponse(resp *flowv1.SubmitTaskResponse) *APIUpdateFirmwareResponse {
	r := &APIUpdateFirmwareResponse{}
	r.FromProto(resp)
	return r
}

// ========== Batch Rack Firmware Update Request ==========

// APIBatchRackFirmwareUpdateRequest is the JSON body for batch rack firmware update.
type APIBatchRackFirmwareUpdateRequest struct {
	SiteID  string      `json:"siteId"`
	Filter  *RackFilter `json:"filter,omitempty"`
	Version *string     `json:"version,omitempty"`
}

// Validate checks required fields.
func (r *APIBatchRackFirmwareUpdateRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId is required")
	}
	return nil
}

// ========== Batch Tray Firmware Update Request ==========

// APIBatchTrayFirmwareUpdateRequest is the JSON body for batch tray firmware update.
type APIBatchTrayFirmwareUpdateRequest struct {
	SiteID  string      `json:"siteId"`
	Filter  *TrayFilter `json:"filter,omitempty"`
	Version *string     `json:"version,omitempty"`
	// Targets, when non-empty, restricts the update to a subset of
	// firmware sub-parts within each matched tray. Same semantics as the
	// single-tray variant. When non-empty, requires Version.
	Targets []string `json:"targets,omitempty"`
}

// Validate checks required fields and filter constraints.
func (r *APIBatchTrayFirmwareUpdateRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId is required")
	}
	if r.Filter != nil {
		if err := r.Filter.Validate(); err != nil {
			return err
		}
	}
	return validateFirmwareTargets(r.Targets, r.Version)
}

// validateFirmwareTargets enforces the cross-field constraint that a
// firmware-target subset selection is only meaningful when a target version
// is also supplied. Per-tray-type name validation is delegated to Flow,
// where the mapping from string to component-manager enum lives.
func validateFirmwareTargets(targets []string, version *string) error {
	if len(targets) == 0 {
		return nil
	}
	for _, t := range targets {
		if t == "" {
			return fmt.Errorf("targets must not contain empty strings")
		}
	}
	if version == nil || *version == "" {
		return fmt.Errorf("targets requires version to be set")
	}
	return nil
}
