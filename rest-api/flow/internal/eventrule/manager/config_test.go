// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/operation"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Config)
		wantErr string
	}{
		"valid": {},
		"missing store backend": {
			mutate: func(config *Config) {
				config.Store.Backend = ""
			},
			wantErr: "unsupported event-rule store backend",
		},
		"missing inventory reader": {
			mutate: func(config *Config) {
				config.Inventory = nil
			},
			wantErr: "inventory reader is required",
		},
		"missing task manager": {
			mutate: func(config *Config) {
				config.TaskManager = nil
			},
			wantErr: "task manager is required",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := testManagerConfig()
			if test.mutate != nil {
				test.mutate(&config)
			}

			err := config.Validate()
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

type configTaskManager struct{}

func (configTaskManager) SubmitTask(
	context.Context,
	*operation.Request,
) ([]uuid.UUID, error) {
	return nil, nil
}
