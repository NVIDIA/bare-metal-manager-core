// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComponentTypeValidate(t *testing.T) {
	tests := map[string]struct {
		componentType ComponentType
		wantError     bool
	}{
		"compute":     {componentType: ComponentTypeCompute},
		"nvswitch":    {componentType: ComponentTypeNVSwitch},
		"power shelf": {componentType: ComponentTypePowerShelf},
		"tor switch":  {componentType: ComponentTypeTORSwitch},
		"ums":         {componentType: ComponentTypeUMS},
		"cdu":         {componentType: ComponentTypeCDU},
		"unknown":     {componentType: ComponentTypeUnknown, wantError: true},
		"empty":       {wantError: true},
		"invalid":     {componentType: ComponentType("INVALID"), wantError: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.componentType.Validate()
			if test.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
