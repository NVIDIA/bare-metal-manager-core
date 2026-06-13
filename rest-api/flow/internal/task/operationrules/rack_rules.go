// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operationrules

import (
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

// Rack-scoped operations run as a single step against the rack component
// manager. The staged, per-component-type sequencing the default rules apply
// is Core's responsibility in RMS mode, so the rack rule deliberately carries
// one stage with one step and no reachability / power-status verification.
const (
	rackPowerStepTimeout    = 30 * time.Minute
	rackFirmwareStepTimeout = 90 * time.Minute
	rackFirmwarePollInterval = "2m"
	rackFirmwarePollTimeout  = "60m"
)

// BuildRackRule returns the rule definition used when an operation targets a
// rack as a single unit (whole-rack RMS mode). It returns nil for operation
// types that have no rack-level mapping, so callers can fall back to the
// per-component path.
func BuildRackRule(operationType common.TaskType) *RuleDefinition {
	var step SequenceStep
	switch operationType {
	case common.TaskTypePowerControl:
		step = SequenceStep{
			ComponentType: devicetypes.ComponentTypeRack,
			Stage:         1,
			Timeout:       rackPowerStepTimeout,
			MainOperation: ActionConfig{Name: ActionPowerControl},
		}
	case common.TaskTypeFirmwareControl:
		step = SequenceStep{
			ComponentType: devicetypes.ComponentTypeRack,
			Stage:         1,
			Timeout:       rackFirmwareStepTimeout,
			MainOperation: ActionConfig{
				Name: ActionFirmwareControl,
				Parameters: map[string]any{
					ParamPollInterval: rackFirmwarePollInterval,
					ParamPollTimeout:  rackFirmwarePollTimeout,
				},
			},
		}
	default:
		return nil
	}

	return &RuleDefinition{
		Version: CurrentRuleDefinitionVersion,
		Steps:   []SequenceStep{step},
	}
}
