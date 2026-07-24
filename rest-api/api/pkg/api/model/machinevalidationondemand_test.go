// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

func TestAPIMachineValidationOnDemandRequestToProto(t *testing.T) {
	request := APIMachineValidationOnDemandRequest{
		Tags:               []string{"history"},
		AllowedTests:       []string{"gpu_bandwidth"},
		RunUnverifiedTests: true,
		Contexts:           []string{"OnDemand"},
	}

	protoRequest := request.ToProto("machine-1")

	assert.Equal(t, "machine-1", protoRequest.GetMachineId().GetId())
	assert.Equal(t, corev1.MachineValidationOnDemandRequest_Start, protoRequest.GetAction())
	assert.Equal(t, request.Tags, protoRequest.GetTags())
	assert.Equal(t, request.AllowedTests, protoRequest.GetAllowedTests())
	assert.True(t, protoRequest.GetRunUnverfiedTests())
	assert.Equal(t, request.Contexts, protoRequest.GetContexts())
}

func TestNewAPIMachineValidationOnDemandResponse(t *testing.T) {
	response := NewAPIMachineValidationOnDemandResponse(&corev1.MachineValidationOnDemandResponse{
		ValidationId: &corev1.MachineValidationId{Value: "validation-1"},
	})

	assert.Equal(t, "validation-1", response.ValidationID)
}
