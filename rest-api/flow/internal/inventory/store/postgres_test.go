// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
)

func TestUniqueRackByName(t *testing.T) {
	tests := []struct {
		name      string
		racks     []model.Rack
		wantName  string
		wantCode  codes.Code
		wantError string
	}{
		{
			name:      "no match",
			wantCode:  codes.NotFound,
			wantError: "rack shared",
		},
		{
			name:     "one match",
			racks:    []model.Rack{{Name: "shared"}},
			wantName: "shared",
		},
		{
			name:      "ambiguous match",
			racks:     []model.Rack{{Name: "shared"}, {Name: "shared"}},
			wantCode:  codes.InvalidArgument,
			wantError: `rack name "shared" matches multiple racks; use rack id`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := uniqueRackByName(tc.racks, "shared")
			if tc.wantCode != codes.OK {
				require.Error(t, err)
				assert.Equal(t, tc.wantCode, status.Code(err))
				assert.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tc.wantName, got.Name)
		})
	}
}
