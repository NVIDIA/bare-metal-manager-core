// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"

// APIMachineValidationOnDemandRequest contains optional filters for an
// on-demand Machine validation run.
type APIMachineValidationOnDemandRequest struct {
	Tags               []string `json:"tags,omitempty"`
	AllowedTests       []string `json:"allowedTests,omitempty"`
	RunUnverifiedTests bool     `json:"runUnverifiedTests,omitempty"`
	Contexts           []string `json:"contexts,omitempty"`
}

// ToProto converts an on-demand Machine validation request to the Core API model.
func (r APIMachineValidationOnDemandRequest) ToProto(machineID string) *corev1.MachineValidationOnDemandRequest {
	return &corev1.MachineValidationOnDemandRequest{
		MachineId:         &corev1.MachineId{Id: machineID},
		Tags:              r.Tags,
		Action:            corev1.MachineValidationOnDemandRequest_Start,
		AllowedTests:      r.AllowedTests,
		RunUnverfiedTests: r.RunUnverifiedTests,
		Contexts:          r.Contexts,
	}
}

// APIMachineValidationOnDemandResponse identifies an accepted on-demand
// Machine validation run.
type APIMachineValidationOnDemandResponse struct {
	ValidationID string `json:"validationId"`
}

// NewAPIMachineValidationOnDemandResponse converts the Core response to the REST API model.
func NewAPIMachineValidationOnDemandResponse(response *corev1.MachineValidationOnDemandResponse) APIMachineValidationOnDemandResponse {
	return APIMachineValidationOnDemandResponse{
		ValidationID: response.GetValidationId().GetValue(),
	}
}
