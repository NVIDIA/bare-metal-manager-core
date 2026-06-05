// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSystemAPIRoutes(t *testing.T) {
	tests := []struct {
		name string
		want []Route
	}{
		{
			name: "test initializing system API routes",
			want: []Route{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSystemAPIRoutes()

			assert.Equal(t, len(got), 2)
		})
	}
}
