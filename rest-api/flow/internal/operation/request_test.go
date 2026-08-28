// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWrapper_Clone(t *testing.T) {
	tests := map[string]Wrapper{
		"empty": {},
		"serialized information": {
			Code: "power_on",
			Info: json.RawMessage(`{"operation":1}`),
		},
	}

	for name, wrapper := range tests {
		t.Run(name, func(t *testing.T) {
			cloned := wrapper.Clone()
			require.Equal(t, wrapper, cloned)

			if len(cloned.Info) == 0 {
				return
			}

			cloned.Info[0] = 'x'
			require.NotEqual(t, wrapper.Info, cloned.Info)
		})
	}
}

func TestConflictStrategy_String(t *testing.T) {
	tests := map[string]struct {
		strategy ConflictStrategy
		want     string
	}{
		"reject":  {strategy: ConflictStrategyReject, want: "reject"},
		"queue":   {strategy: ConflictStrategyQueue, want: "queue"},
		"unknown": {strategy: ConflictStrategy(42), want: "ConflictStrategy(42)"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, test.want, test.strategy.String())
		})
	}
}

func TestParseConflictStrategy(t *testing.T) {
	tests := map[string]struct {
		value   string
		want    ConflictStrategy
		wantErr string
	}{
		"reject":  {value: "reject", want: ConflictStrategyReject},
		"queue":   {value: "queue", want: ConflictStrategyQueue},
		"unknown": {value: "wait", want: ConflictStrategyReject, wantErr: `unknown conflict strategy "wait"`},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			strategy, err := ParseConflictStrategy(test.value)

			require.Equal(t, test.want, strategy)

			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, test.wantErr)
		})
	}
}
