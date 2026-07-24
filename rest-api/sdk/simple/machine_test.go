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

	machine := machineFromStandard(*apiMachine)

	assert.Equal(t, &version, machine.LastScoutObservedVersion)
}
