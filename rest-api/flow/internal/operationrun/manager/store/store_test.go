// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operation"
	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
)

func TestCreateTargetsValidatesComponentsByType(t *testing.T) {
	runID := uuid.New()
	componentID := uuid.New()

	tests := []struct {
		name             string
		componentsByType operation.ComponentsByType
		wantErr          string
	}{
		{
			name:             "empty map",
			componentsByType: operation.ComponentsByType{},
			wantErr:          "Non-empty ComponentsByType is required",
		},
		{
			name: "unknown component type",
			componentsByType: operation.ComponentsByType{
				devicetypes.ComponentTypeUnknown: {componentID},
			},
			wantErr: "ComponentsByType contains unknown component type",
		},
		{
			name: "empty component UUID",
			componentsByType: operation.ComponentsByType{
				devicetypes.ComponentTypeCompute: {uuid.Nil},
			},
			wantErr: "contains empty component UUID",
		},
		{
			name: "duplicate component UUID",
			componentsByType: operation.ComponentsByType{
				devicetypes.ComponentTypeCompute: {componentID, componentID},
			},
			wantErr: "duplicates component",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &PostgresStore{}

			err := store.CreateTargets(
				context.Background(),
				runID,
				[]*operationrun.OperationRunTarget{
					{
						RackID:           uuid.New(),
						ComponentsByType: tt.componentsByType,
					},
				},
			)

			require.ErrorContains(t, err, "operation run target 0 components_by_type")
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
