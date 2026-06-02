// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/stretchr/testify/assert"
)

func TestMachineCapability_NewAPIMachineCapability(t *testing.T) {
	dbmc := &cdbm.MachineCapability{
		Type:      cdbm.MachineCapabilityTypeCPU,
		Name:      "AMD Opteron Series x10",
		Frequency: cdb.GetStrPtr("3.0GHz"),
		Capacity:  cdb.GetStrPtr("3.0GHz"),
		Vendor:    cdb.GetStrPtr("AMD"),
		Count:     cdb.GetIntPtr(2),
	}

	apimc := NewAPIMachineCapability(dbmc)
	assert.Equal(t, dbmc.Type, apimc.Type)
	assert.Equal(t, dbmc.Name, apimc.Name)
	assert.Equal(t, *dbmc.Frequency, *apimc.Frequency)
	assert.Equal(t, *dbmc.Capacity, *apimc.Capacity)
	assert.Equal(t, *dbmc.Vendor, *apimc.Vendor)
	assert.Equal(t, *dbmc.Count, *apimc.Count)
}
