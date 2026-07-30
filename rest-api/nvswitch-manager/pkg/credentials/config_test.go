// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigValidate(t *testing.T) {
	testCases := map[string]struct {
		cfg         Config
		expectErr   bool
		errContains string
	}{
		"in-memory datastore returns nil": {
			cfg:       Config{DataStoreType: DatastoreTypeInMemory},
			expectErr: false,
		},
		"unknown/empty datastore returns nil": {
			cfg:       Config{}, // zero-value DataStoreType means no extra validation
			expectErr: false,
		},
		"core datastore with nil CoreConfig returns error": {
			cfg: Config{
				DataStoreType: DatastoreTypeCore,
				CoreConfig:    nil,
			},
			expectErr:   true,
			errContains: "core config needs to be specified",
		},
		"core datastore with empty address delegates to CoreConfig.Validate": {
			cfg: Config{
				DataStoreType: DatastoreTypeCore,
				CoreConfig:    &CoreConfig{Address: "  "},
			},
			expectErr:   true,
			errContains: "invalid core api address",
		},
		"core datastore with non-empty address validates": {
			cfg: Config{
				DataStoreType: DatastoreTypeCore,
				CoreConfig:    &CoreConfig{Address: "nico-api:50051"},
			},
			expectErr: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			err := tc.cfg.Validate()

			if tc.errContains != "" {
				assert.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.errContains))
				return
			}

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
