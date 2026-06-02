// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"errors"
	"fmt"
	"strings"

	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

// Target represents a batch of components of the same type for activity execution.
// Workflow passes only component IDs to activity (not full objects).
type Target struct {
	Type         devicetypes.ComponentType
	ComponentIDs []string
}

// Validate returns an error if the Target has an unknown component type or no component IDs.
func (t *Target) Validate() error {
	if t.Type == devicetypes.ComponentTypeUnknown {
		return errors.New("component type is unknown")
	}

	if len(t.ComponentIDs) == 0 {
		return errors.New("component IDs are required")
	}

	return nil
}

// String returns a human-readable representation for logging.
func (t *Target) String() string {
	return fmt.Sprintf(
		"[type: %s, component_ids: %s]",
		devicetypes.ComponentTypeToString(t.Type),
		strings.Join(t.ComponentIDs, ","),
	)
}
