// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"

	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	DpuReprovisionModeSet     = "Set"
	DpuReprovisionModeClear   = "Clear"
	DpuReprovisionModeRestart = "Restart"
)

var validDpuReprovisionModes = []string{
	DpuReprovisionModeSet,
	DpuReprovisionModeClear,
	DpuReprovisionModeRestart,
}

var validDpuReprovisionModesAny = func() []interface{} {
	result := make([]interface{}, len(validDpuReprovisionModes))
	for i, mode := range validDpuReprovisionModes {
		result[i] = mode
	}
	return result
}()

type APIDpuReprovisionRequest struct {
	Mode           string `json:"mode"`
	UpdateFirmware bool   `json:"updateFirmware"`
}

func (r *APIDpuReprovisionRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.Mode,
			validation.Required.Error(validationErrorValueRequired),
			validation.In(validDpuReprovisionModesAny...).Error(fmt.Sprintf("must be one of %v", validDpuReprovisionModes))),
	)
}

func (r *APIDpuReprovisionRequest) ToProto(machineID string) *cwssaws.DpuReprovisioningRequest {
	return &cwssaws.DpuReprovisioningRequest{
		MachineId: &cwssaws.MachineId{Id: machineID},
		Mode:      dpuReprovisionModeToProto(r.Mode),
		// TODO: Add end user initiator
		Initiator:      cwssaws.UpdateInitiator_AdminCli,
		UpdateFirmware: r.UpdateFirmware,
	}
}

func dpuReprovisionModeToProto(mode string) cwssaws.DpuReprovisioningRequest_Mode {
	switch mode {
	case DpuReprovisionModeClear:
		return cwssaws.DpuReprovisioningRequest_Clear
	case DpuReprovisionModeRestart:
		return cwssaws.DpuReprovisioningRequest_Restart
	default:
		return cwssaws.DpuReprovisioningRequest_Set
	}
}
