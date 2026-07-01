// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// APIBmcResetRequest represents a request to reset the BMC of a machine
type APIBmcResetRequest struct {
	UseIpmiTool *bool `json:"useIpmiTool"`
}

// Validate validates the APIBmcResetRequest
func (r *APIBmcResetRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.UseIpmiTool,
			validation.Required.Error("a value must be specified for useIpmiTool"),
		),
	)
}

// ToProto converts the APIBmcResetRequest to a Core gRPC AdminBmcResetRequest
func (r *APIBmcResetRequest) ToProto(machineID string) *cwssaws.AdminBmcResetRequest {
	return &cwssaws.AdminBmcResetRequest{
		MachineId:   &machineID,
		UseIpmitool: *r.UseIpmiTool,
	}
}
