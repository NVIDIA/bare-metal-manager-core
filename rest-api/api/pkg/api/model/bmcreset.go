// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

// APIMachineBMCResetRequest represents a request to reset the BMC of a Machine
type APIMachineBMCResetRequest struct {
	UseIpmiTool bool `json:"useIpmiTool"`
	// AcknowledgeAttachedInstance indicates the caller is aware that an Instance is currently attached to the Machine.
	AcknowledgeAttachedInstance *bool `json:"acknowledgeAttachedInstance"`
}

// ToProto converts the APIMachineBMCResetRequest to a Core gRPC AdminBmcResetRequest
func (ambrr *APIMachineBMCResetRequest) ToProto(machineID string) *cwssaws.AdminBmcResetRequest {
	return &cwssaws.AdminBmcResetRequest{
		MachineId:   &machineID,
		UseIpmitool: ambrr.UseIpmiTool,
	}
}
