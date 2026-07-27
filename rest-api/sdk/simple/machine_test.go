// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package simple

import (
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/sdk/standard"
	"github.com/stretchr/testify/assert"
)

func TestMachineFromStandardIncludesLastScoutObservedVersion(t *testing.T) {
	version := "2.6.1"
	apiMachine := standard.NewMachine()
	apiMachine.SetLastScoutObservedVersion(version)

	tests := []struct {
		name       string
		apiMachine standard.Machine
		want       *string
	}{
		{
			name:       "returns reported version",
			apiMachine: *apiMachine,
			want:       &version,
		},
		{
			name:       "returns nil when version is unknown",
			apiMachine: *standard.NewMachine(),
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := machineFromStandard(tt.apiMachine)

			assert.Equal(t, tt.want, machine.LastScoutObservedVersion)
		})
	}
}
