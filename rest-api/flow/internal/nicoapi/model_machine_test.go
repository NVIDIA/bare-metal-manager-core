// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoapi

import (
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

func TestMachineDetailFromPbIncludesAssociatedDPUs(t *testing.T) {
	machine := &corev1.Machine{
		Id:          &corev1.MachineId{Id: "host-1"},
		MachineType: corev1.MachineType_HOST,
		Status: &corev1.MachineStatus{
			AssociatedDpuMachineIds: []*corev1.MachineId{
				{Id: "dpu-1"},
				{Id: ""},
				{Id: "dpu-2"},
			},
		},
	}

	detail := machineDetailFromPb(machine)

	assert.Equal(t, []string{"dpu-1", "dpu-2"}, detail.AssociatedDpuMachineIDs)
}
