// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nico

import (
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
)

// ExtractPowerState derives an operations.PowerStatus from the first
// ComputerSystem in a site exploration report.  Returns PowerStatusUnknown
// when the report is nil or contains no systems.
func ExtractPowerState(report *pb.EndpointExplorationReport) operations.PowerStatus {
	if report == nil {
		return operations.PowerStatusUnknown
	}
	systems := report.GetSystems()
	if len(systems) == 0 {
		return operations.PowerStatusUnknown
	}
	switch systems[0].GetPowerState() {
	case pb.ComputerSystemPowerState_On:
		return operations.PowerStatusOn
	case pb.ComputerSystemPowerState_Off:
		return operations.PowerStatusOff
	default:
		return operations.PowerStatusUnknown
	}
}
