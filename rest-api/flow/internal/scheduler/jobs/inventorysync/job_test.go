// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadExpectedSyncEnabled(t *testing.T) {
	// The mirror writes to rack / component tables, so the default has to
	// be off — an operator should have to opt in explicitly. These cases
	// pin both the truthy / falsy ParseBool grammar and the
	// "unparseable / unset is conservatively off" guarantee.
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"", false},    // unset env var
		{"true", true}, // canonical truthy
		{"True", true}, // ParseBool accepts mixed case
		{"TRUE", true}, // and upper case
		{"1", true},    // and 1
		{"t", true},    // and t
		{"false", false},
		{"0", false},
		{"f", false},
		{"on", false}, // ParseBool rejects on/off; treated as disabled with warn
		{"yes", false},
		{"garbage", false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv(envExpectedSyncEnabled, tc.raw)
			assert.Equal(t, tc.want, readExpectedSyncEnabled())
		})
	}
}
