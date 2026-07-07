// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"

	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// MachineDpuReprovisionMode represents the mode of a Machine DPU reprovisioning request.
type MachineDpuReprovisionMode string

const (
	MachineDpuReprovisionModeSet     MachineDpuReprovisionMode = "Set"
	MachineDpuReprovisionModeClear   MachineDpuReprovisionMode = "Clear"
	MachineDpuReprovisionModeRestart MachineDpuReprovisionMode = "Restart"
)

// ToProto converts the MachineDpuReprovisionMode to a Core gRPC DpuReprovisioningRequest_Mode
func (m MachineDpuReprovisionMode) ToProto() cwssaws.DpuReprovisioningRequest_Mode {
	switch m {
	case MachineDpuReprovisionModeSet:
		return cwssaws.DpuReprovisioningRequest_Set
	case MachineDpuReprovisionModeClear:
		return cwssaws.DpuReprovisioningRequest_Clear
	case MachineDpuReprovisionModeRestart:
		return cwssaws.DpuReprovisioningRequest_Restart
	}
	return cwssaws.DpuReprovisioningRequest_Set
}

// MachineDpuReprovisionModeValues is a list of all valid MachineDpuReprovisionMode values.
var MachineDpuReprovisionModeValues = []MachineDpuReprovisionMode{
	MachineDpuReprovisionModeSet,
	MachineDpuReprovisionModeClear,
	MachineDpuReprovisionModeRestart,
}

// APIMachineDpuReprovisionRequest represents a request to reprovision a Machine DPU.
type APIMachineDpuReprovisionRequest struct {
	Mode           MachineDpuReprovisionMode `json:"mode"`
	UpdateFirmware bool                      `json:"updateFirmware"`
	// AcknowledgeAttachedInstance indicates the caller is aware that an Instance is currently attached to the Machine.
	AcknowledgeAttachedInstance *bool `json:"acknowledgeAttachedInstance"`
}

// Validate validates the APIMachineDpuReprovisionRequest
func (amdrr *APIMachineDpuReprovisionRequest) Validate() error {
	return validation.ValidateStruct(amdrr,
		validation.Field(&amdrr.Mode,
			validation.Required.Error(validationErrorValueRequired),
			validation.In(MachineDpuReprovisionModeSet, MachineDpuReprovisionModeClear, MachineDpuReprovisionModeRestart).Error(fmt.Sprintf("must be one of %v", MachineDpuReprovisionModeValues))),
	)
}

// ToProto converts the APIMachineDpuReprovisionRequest to a Core gRPC DpuReprovisioningRequest
func (amdrr *APIMachineDpuReprovisionRequest) ToProto(machineID string) *cwssaws.DpuReprovisioningRequest {
	return &cwssaws.DpuReprovisioningRequest{
		MachineId: &cwssaws.MachineId{Id: machineID},
		Mode:      MachineDpuReprovisionMode(amdrr.Mode).ToProto(),
		// TODO: Add end user initiator in Core gRPC API
		Initiator:      cwssaws.UpdateInitiator_AdminCli,
		UpdateFirmware: amdrr.UpdateFirmware,
	}
}
