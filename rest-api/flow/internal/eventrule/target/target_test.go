// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package target

import (
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestTarget_Validate(t *testing.T) {
	tests := map[string]struct {
		target  Target
		wantErr string
	}{
		"component": {
			target: Target{Kind: eventrule.ResourceKindComponent, ID: uuid.New()},
		},
		"rack": {
			target: Target{Kind: eventrule.ResourceKindRack, ID: uuid.New()},
		},
		"invalid kind": {
			target:  Target{Kind: "invalid", ID: uuid.New()},
			wantErr: `unknown resource kind "invalid"`,
		},
		"missing id": {
			target:  Target{Kind: eventrule.ResourceKindComponent},
			wantErr: "target id is required",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.target.Validate()
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
