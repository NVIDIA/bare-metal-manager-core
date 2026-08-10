// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"testing"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestVpcUpdateRequestPowerResourceGroupJSON(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		check   func(*testing.T, *corev1.VpcUpdateRequest)
	}{
		{
			name:    "legacy set",
			payload: `{"powerResourceGroup":"legacy-group"}`,
			check: func(t *testing.T, request *corev1.VpcUpdateRequest) {
				update, ok := request.PowerResourceGroupUpdate.(*corev1.VpcUpdateRequest_SetPowerResourceGroup)
				require.True(t, ok)
				require.Equal(t, "legacy-group", update.SetPowerResourceGroup)
			},
		},
		{
			name:    "new set",
			payload: `{"set_power_resource_group":"new-group"}`,
			check: func(t *testing.T, request *corev1.VpcUpdateRequest) {
				update, ok := request.PowerResourceGroupUpdate.(*corev1.VpcUpdateRequest_SetPowerResourceGroup)
				require.True(t, ok)
				require.Equal(t, "new-group", update.SetPowerResourceGroup)
			},
		},
		{
			name:    "clear",
			payload: `{"clearPowerResourceGroup":{}}`,
			check: func(t *testing.T, request *corev1.VpcUpdateRequest) {
				_, ok := request.PowerResourceGroupUpdate.(*corev1.VpcUpdateRequest_ClearPowerResourceGroup)
				require.True(t, ok)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &corev1.VpcUpdateRequest{}
			require.NoError(t, protojson.Unmarshal([]byte(test.payload), request))
			test.check(t, request)
		})
	}
}
