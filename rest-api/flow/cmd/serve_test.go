// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"

	cmconfig "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/config"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

// TestApplyComputeImplementationOverride covers the env-var fallback
// path that exists for migrating compute between nicolegacy and the new
// Component Manager-based nico implementation. Subsequent catalog
// validation rejects unknown names, so the override here is intentionally
// minimal: it only adjusts the config map.
func TestApplyComputeImplementationOverride(t *testing.T) {
	t.Run("env unset is a no-op", func(t *testing.T) {
		t.Setenv(computeImplEnvVar, "")

		cfg := cmconfig.Config{
			ComponentManagers: map[devicetypes.ComponentType]string{
				devicetypes.ComponentTypeCompute: "nicolegacy",
			},
		}

		applyComputeImplementationOverride(&cfg)

		assert.Equal(t, "nicolegacy", cfg.ComponentManagers[devicetypes.ComponentTypeCompute])
	})

	t.Run("whitespace value is treated as unset", func(t *testing.T) {
		t.Setenv(computeImplEnvVar, "   ")

		cfg := cmconfig.Config{
			ComponentManagers: map[devicetypes.ComponentType]string{
				devicetypes.ComponentTypeCompute: "nicolegacy",
			},
		}

		applyComputeImplementationOverride(&cfg)

		assert.Equal(t, "nicolegacy", cfg.ComponentManagers[devicetypes.ComponentTypeCompute])
	})

	t.Run("override replaces existing compute selection", func(t *testing.T) {
		t.Setenv(computeImplEnvVar, "nico")

		cfg := cmconfig.Config{
			ComponentManagers: map[devicetypes.ComponentType]string{
				devicetypes.ComponentTypeCompute:    "nicolegacy",
				devicetypes.ComponentTypeNVSwitch:   "nico",
				devicetypes.ComponentTypePowerShelf: "nico",
			},
		}

		applyComputeImplementationOverride(&cfg)

		assert.Equal(t, "nico", cfg.ComponentManagers[devicetypes.ComponentTypeCompute])
		// Other component types must be untouched.
		assert.Equal(t, "nico", cfg.ComponentManagers[devicetypes.ComponentTypeNVSwitch])
		assert.Equal(t, "nico", cfg.ComponentManagers[devicetypes.ComponentTypePowerShelf])
	})

	t.Run("override surrounding whitespace is trimmed", func(t *testing.T) {
		t.Setenv(computeImplEnvVar, "  nico  ")

		cfg := cmconfig.Config{
			ComponentManagers: map[devicetypes.ComponentType]string{
				devicetypes.ComponentTypeCompute: "nicolegacy",
			},
		}

		applyComputeImplementationOverride(&cfg)

		assert.Equal(t, "nico", cfg.ComponentManagers[devicetypes.ComponentTypeCompute])
	})

	t.Run("override initialises map when nil", func(t *testing.T) {
		t.Setenv(computeImplEnvVar, "nico")

		cfg := cmconfig.Config{}

		applyComputeImplementationOverride(&cfg)

		assert.Equal(t, "nico", cfg.ComponentManagers[devicetypes.ComponentTypeCompute])
	})
}
