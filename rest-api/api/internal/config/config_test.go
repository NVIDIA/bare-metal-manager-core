// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name string
		want *Config
	}{
		{
			name: "initialize config",
			want: &Config{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewConfig()

			defaultPath := ProjectRoot + "/config.yaml"

			assert.Equal(t, defaultPath, got.GetPathToConfig())
		})
	}
}
