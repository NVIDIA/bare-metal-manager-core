// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nico

import (
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi/gen"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
)

// MapFirmwareState converts a NICo protobuf FirmwareUpdateState into the
// corresponding operations.FirmwareUpdateState.
func MapFirmwareState(state pb.FirmwareUpdateState) operations.FirmwareUpdateState {
	switch state {
	case pb.FirmwareUpdateState_FW_STATE_QUEUED:
		return operations.FirmwareUpdateStateQueued
	case pb.FirmwareUpdateState_FW_STATE_IN_PROGRESS:
		return operations.FirmwareUpdateStateQueued // closest available state
	case pb.FirmwareUpdateState_FW_STATE_VERIFYING:
		return operations.FirmwareUpdateStateVerifying
	case pb.FirmwareUpdateState_FW_STATE_COMPLETED:
		return operations.FirmwareUpdateStateCompleted
	case pb.FirmwareUpdateState_FW_STATE_FAILED, pb.FirmwareUpdateState_FW_STATE_CANCELLED:
		return operations.FirmwareUpdateStateFailed
	default:
		return operations.FirmwareUpdateStateUnknown
	}
}
