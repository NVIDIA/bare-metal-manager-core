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

func TestAPIMachineValidationOnDemandRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request APIMachineValidationOnDemandRequest
		wantErr bool
	}{
		{name: "empty options accepted"},
		{
			name: "filters accepted",
			request: APIMachineValidationOnDemandRequest{
				Tags:         []string{"history"},
				AllowedTests: []string{"gpu_bandwidth"},
				Contexts:     []string{"OnDemand"},
			},
		},
		{name: "empty tag rejected", request: APIMachineValidationOnDemandRequest{Tags: []string{""}}, wantErr: true},
		{name: "empty allowed test rejected", request: APIMachineValidationOnDemandRequest{AllowedTests: []string{""}}, wantErr: true},
		{name: "empty context rejected", request: APIMachineValidationOnDemandRequest{Contexts: []string{""}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestNewAPIMachineValidationOnDemandResponse(t *testing.T) {
	response := NewAPIMachineValidationOnDemandResponse(&corev1.MachineValidationOnDemandResponse{
		ValidationId: &corev1.MachineValidationId{Value: "validation-1"},
	})

	assert.Equal(t, "validation-1", response.ValidationID)
}
